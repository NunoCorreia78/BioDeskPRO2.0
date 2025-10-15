using System;
using System.Collections.Generic;
using System.Data;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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
                if (!File.Exists(filePath)) return (false, "Ficheiro não encontrado");
                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                if (ext != ".xls" && ext != ".xlsx") return (false, "Extensão inválida. Apenas .xls e .xlsx são suportados");

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

                // Gerar hash estável para ExternalId (idempotência)
                var frequenciasStr = string.Join(";", freqs.OrderBy(f => f).Select(f => f.ToString("F2", CultureInfo.InvariantCulture)));
                var externalId = GerarHashEstavel(nomePt, "Geral", frequenciasStr);

                var protocolo = new ProtocoloTerapeutico
                {
                    ExternalId = externalId,
                    Nome = nomePt,
                    Categoria = "Geral",
                    CriadoEm = DateTime.UtcNow,
                    AtualizadoEm = DateTime.UtcNow,
                    Ativo = true
                };
                protocolo.SetFrequencias(freqs.ToArray());
                await _protocoloRepository.UpsertAsync(protocolo);
                linhasOk++;
            }

            stopwatch.Stop();

            // Registar log de importação (sucesso)
            var fileName = Path.GetFileName(filePath);
            await _protocoloRepository.AddImportLogAsync(
                nomeArquivo: fileName,
                totalLinhas: totalLinhas,
                sucessos: linhasOk,
                erros: linhasErros,
                mensagemErro: null
            );

            return new ExcelImportResult { Sucesso = true, TotalLinhas = totalLinhas, LinhasOk = linhasOk, LinhasWarnings = linhasWarnings, LinhasErros = linhasErros, DuracaoSegundos = stopwatch.Elapsed.TotalSeconds, Erros = erros, Warnings = warnings };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();

            // Registar log de importação (erro)
            try
            {
                var fileName = Path.GetFileName(filePath);
                await _protocoloRepository.AddImportLogAsync(
                    nomeArquivo: fileName,
                    totalLinhas: 0,
                    sucessos: 0,
                    erros: 1,
                    mensagemErro: ex.Message
                );
            }
            catch (Exception logEx)
            {
                // Log failure silencioso - não queremos mascarar o erro original
                System.Diagnostics.Debug.WriteLine($"Erro ao registar log: {logEx.Message}");
            }

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

    /// <summary>
    /// Gera hash estável (SHA256) para ExternalId baseado em nome+categoria+frequências
    /// Garante idempotência: mesmos dados = mesmo GUID
    /// </summary>
    private string GerarHashEstavel(string nome, string categoria, string frequenciasStr)
    {
        var input = $"{nome.ToLowerInvariant()}|{categoria.ToLowerInvariant()}|{frequenciasStr}";
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));

        // Converter primeiros 16 bytes para GUID
        var guidBytes = hashBytes.Take(16).ToArray();
        var guid = new Guid(guidBytes);

        return guid.ToString();
    }
}
