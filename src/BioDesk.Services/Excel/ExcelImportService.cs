using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Services.Translation;
using ExcelDataReader;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Excel;

public class ExcelImportService : IExcelImportService
{
    private readonly IProtocoloRepository _protocoloRepository;
    private readonly ILogger<ExcelImportService> _logger;
    private const int COL_DISEASE = 1;
    private const int COL_FREQ_START = 2;

    public ExcelImportService(IProtocoloRepository protocoloRepository, ILogger<ExcelImportService> logger)
    {
        _protocoloRepository = protocoloRepository;
        _logger = logger;
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public async Task<(bool IsValid, string ErrorMessage)> ValidateFileAsync(string filePath)
    {
        return await Task.Run(() =>
        {
            try
            {
                if (!File.Exists(filePath)) return (false, "Não encontrado");
                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                if (ext != ".xls" && ext != ".xlsx") return (false, "Formato inválido");
                
                using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read);
                using var reader = ExcelReaderFactory.CreateReader(stream);
                var dataset = reader.AsDataSet();
                var table = dataset.Tables[0];
                
                return table.Rows.Count >= 2 ? (true, string.Empty) : (false, "Vazio");
            }
            catch (Exception ex) { return (false, ex.Message); }
        });
    }

    public async Task<ExcelImportPreview> PreviewAsync(string filePath, int maxLinhasPreview = 20)
    {
        return await Task.Run(() =>
        {
            var previews = new List<PreviewLine>();
            var erros = new List<string>();
            var warnings = new List<string>();
            
            try
            {
                var (isValid, errorMessage) = ValidateFileAsync(filePath).Result;
                if (!isValid)
                {
                    erros.Add(errorMessage);
                    return new ExcelImportPreview { TotalLinhas = 0, LinhasValidas = 0, LinhasWarnings = 0, LinhasErros = 1, Previews = previews, Erros = erros, Warnings = warnings };
                }

                using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read);
                using var reader = ExcelReaderFactory.CreateReader(stream);
                var dataset = reader.AsDataSet();
                var table = dataset.Tables[0];
                
                int totalLinhas = table.Rows.Count;
                int linhasValidas = 0, linhasWarnings = 0, linhasErros = 0;

                for (int i = 1; i < table.Rows.Count && previews.Count < maxLinhasPreview; i++)
                {
                    var row = table.Rows[i];
                    var diseaseEn = row.ItemArray[COL_DISEASE]?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(diseaseEn) || diseaseEn.StartsWith("AAA")) continue;

                    var nomePt = MedicalTermsTranslator.TranslateToPortuguese(diseaseEn);
                    var freqs = ExtractFrequenciesFromRow(row);
                    linhasValidas++;
                    
                    previews.Add(new PreviewLine
                    {
                        NumeroLinha = i + 1,
                        NomeOriginal = diseaseEn,
                        NomeTraduzido = nomePt,
                        Categoria = "Geral",
                        NumeroFrequencias = freqs.Count,
                        TemTraducao = nomePt != diseaseEn
                    });
                }

                return new ExcelImportPreview { TotalLinhas = totalLinhas, LinhasValidas = linhasValidas, LinhasWarnings = linhasWarnings, LinhasErros = linhasErros, Previews = previews, Erros = erros, Warnings = warnings };
            }
            catch (Exception ex)
            {
                erros.Add(ex.Message);
                return new ExcelImportPreview { TotalLinhas = 0, LinhasValidas = 0, LinhasWarnings = 0, LinhasErros = 1, Previews = previews, Erros = erros, Warnings = warnings };
            }
        });
    }

    public async Task<ExcelImportResult> ImportAsync(string filePath)
    {
        var stopwatch = Stopwatch.StartNew();
        var erros = new List<string>();
        var warnings = new List<string>();
        
        try
        {
            using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read);
            using var reader = ExcelReaderFactory.CreateReader(stream);
            var dataset = reader.AsDataSet();
            var table = dataset.Tables[0];
            
            int totalLinhas = table.Rows.Count - 1;
            int linhasOk = 0, linhasWarnings = 0, linhasErros = 0;

            for (int i = 1; i < table.Rows.Count; i++)
            {
                var row = table.Rows[i];
                var diseaseEn = row.ItemArray[COL_DISEASE]?.ToString()?.Trim();
                if (string.IsNullOrWhiteSpace(diseaseEn) || diseaseEn.StartsWith("AAA")) continue;

                var nomePt = MedicalTermsTranslator.TranslateToPortuguese(diseaseEn);
                var freqs = ExtractFrequenciesFromRow(row);
                if (freqs.Count == 0) continue;

                var protocolo = new ProtocoloTerapeutico
                {
                    ExternalId = Guid.NewGuid().ToString(),
                    Nome = nomePt,
                    Categoria = "Geral",
                    CriadoEm = DateTime.UtcNow,
                    AtualizadoEm = DateTime.UtcNow,
                    Ativo = true
                };
                protocolo.SetFrequencias(freqs.ToArray());
                await _protocoloRepository.UpsertAsync(protocolo);
                linhasOk++;
                
                if (linhasOk % 100 == 0) _logger.LogInformation("{Ok}/{Total}", linhasOk, totalLinhas);
            }

            stopwatch.Stop();
            return new ExcelImportResult { Sucesso = true, TotalLinhas = totalLinhas, LinhasOk = linhasOk, LinhasWarnings = linhasWarnings, LinhasErros = linhasErros, DuracaoSegundos = stopwatch.Elapsed.TotalSeconds, Erros = erros, Warnings = warnings };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            return new ExcelImportResult { Sucesso = false, MensagemErro = ex.Message, DuracaoSegundos = stopwatch.Elapsed.TotalSeconds, Erros = erros, Warnings = warnings };
        }
    }

    private List<double> ExtractFrequenciesFromRow(DataRow row)
    {
        var freqs = new List<double>();
        for (int col = COL_FREQ_START; col < row.ItemArray.Length; col++)
        {
            var cellValue = row.ItemArray[col]?.ToString()?.Trim();
            if (string.IsNullOrWhiteSpace(cellValue)) continue;
            var value = cellValue.Replace(',', '.');
            if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out double freq) && freq > 0)
                freqs.Add(freq);
        }
        return freqs;
    }
}
