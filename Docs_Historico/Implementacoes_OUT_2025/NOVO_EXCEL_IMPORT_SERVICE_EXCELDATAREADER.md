# Novo ExcelImportService com ExcelDataReader

Substituir todo o conteúdo de `src/BioDesk.Services/Excel/ExcelImportService.cs` por este código:

```csharp
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

/// <summary>
/// Implementação de IExcelImportService usando ExcelDataReader (suporta .xls e .xlsx)
/// Importa FrequencyList.xls com tradução automática PT
/// </summary>
public class ExcelImportService : IExcelImportService
{
    private readonly IProtocoloRepository _protocoloRepository;
    private readonly ILogger<ExcelImportService> _logger;

    // Índices das colunas no Excel (0-based)
    private const int COL_INDIKATIONEN = 0;  // Alemão
    private const int COL_DISEASE = 1;       // Inglês
    private const int COL_FREQ_START = 2;    // Freq 1 começa na coluna 3 (índice 2)

    public ExcelImportService(
        IProtocoloRepository protocoloRepository,
        ILogger<ExcelImportService> logger)
    {
        _protocoloRepository = protocoloRepository ?? throw new ArgumentNullException(nameof(protocoloRepository));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // ⚡ CRITICAL: Registar CodePages para ler ficheiros .xls antigos
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
    }

    public async Task<(bool IsValid, string ErrorMessage)> ValidateFileAsync(string filePath)
    {
        return await Task.Run(() =>
        {
            try
            {
                if (string.IsNullOrWhiteSpace(filePath))
                    return (false, "Caminho do ficheiro não pode ser vazio");

                if (!File.Exists(filePath))
                    return (false, $"Ficheiro não encontrado: {filePath}");

                var ext = Path.GetExtension(filePath).ToLowerInvariant();
                if (ext != ".xls" && ext != ".xlsx")
                    return (false, $"Formato inválido. Esperado .xls ou .xlsx, recebido: {ext}");

                // Tentar abrir ficheiro com ExcelDataReader
                using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read);
                using var reader = ExcelReaderFactory.CreateReader(stream);
                
                if (reader == null)
                    return (false, "Não foi possível ler o ficheiro Excel");

                var dataset = reader.AsDataSet(new ExcelDataSetConfiguration
                {
                    ConfigureDataTable = _ => new ExcelDataTableConfiguration { UseHeaderRow = false }
                });

                if (dataset.Tables.Count == 0)
                    return (false, "Ficheiro não contém folhas de cálculo");

                var table = dataset.Tables[0];
                if (table.Rows.Count < 2)
                    return (false, "Ficheiro não contém dados suficientes (mínimo 2 linhas)");

                return (true, string.Empty);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao validar ficheiro Excel: {FilePath}", filePath);
                return (false, $"Erro ao validar: {ex.Message}");
            }
        });
    }

    public async Task<ExcelImportPreview> PreviewAsync(string filePath, int maxLinhasPreview = 20)
    {
        return await Task.Run(() =>
        {
            var stopwatch = Stopwatch.StartNew();
            var result = new ExcelImportPreview
            {
                Previews = new List<PreviewLine>()
            };

            try
            {
                _logger.LogInformation("📊 Iniciando preview de {FilePath} (max {MaxLinhas} linhas)", filePath, maxLinhasPreview);

                // Validar ficheiro primeiro
                var (isValid, errorMessage) = ValidateFileAsync(filePath).GetAwaiter().GetResult();
                if (!isValid)
                {
                    _logger.LogError("Erro ao validar ficheiro Excel: {FilePath}", filePath);
                    result.Erros.Add(errorMessage);
                    return result;
                }

                using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read);
                using var reader = ExcelReaderFactory.CreateReader(stream);
                var dataset = reader.AsDataSet(new ExcelDataSetConfiguration
                {
                    ConfigureDataTable = _ => new ExcelDataTableConfiguration { UseHeaderRow = false }
                });

                var table = dataset.Tables[0];
                result.TotalLinhas = table.Rows.Count;

                _logger.LogInformation("Total de linhas no ficheiro: {TotalLinhas}", result.TotalLinhas);

                // Processar primeiras N linhas (ignorar header row 0)
                int linhasProcessadas = 0;
                for (int i = 1; i < table.Rows.Count && linhasProcessadas < maxLinhasPreview; i++)
                {
                    var row = table.Rows[i];
                    var (previewLine, warning, erro) = ProcessDataRowForPreview(row, i + 1);

                    if (previewLine != null)
                    {
                        result.Previews.Add(previewLine);
                        result.LinhasValidas++;
                        linhasProcessadas++;

                        if (!string.IsNullOrEmpty(warning))
                        {
                            result.Warnings.Add($"Linha {i + 1}: {warning}");
                            result.LinhasWarnings++;
                        }
                    }
                    else if (!string.IsNullOrEmpty(erro))
                    {
                        result.Erros.Add($"Linha {i + 1}: {erro}");
                        result.LinhasErros++;
                    }
                }

                stopwatch.Stop();
                _logger.LogInformation("✅ Preview completo em {Elapsed}ms. {LinhasValidas}/{TotalLinhas} linhas válidas",
                    stopwatch.ElapsedMilliseconds, result.LinhasValidas, result.TotalLinhas);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "💥 Erro durante preview de {FilePath}", filePath);
                result.Erros.Add($"Erro durante preview: {ex.Message}");
                return result;
            }
        });
    }

    public async Task<ExcelImportResult> ImportAsync(string filePath)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = new ExcelImportResult
        {
            Erros = new List<string>(),
            Warnings = new List<string>()
        };

        try
        {
            _logger.LogInformation("🚀 Iniciando importação COMPLETA de {FilePath}", filePath);

            // Validar ficheiro primeiro
            var (isValid, errorMessage) = await ValidateFileAsync(filePath);
            if (!isValid)
            {
                _logger.LogError("Erro ao validar ficheiro: {ErrorMessage}", errorMessage);
                return result with
                {
                    Sucesso = false,
                    MensagemErro = errorMessage,
                    DuracaoSegundos = stopwatch.Elapsed.TotalSeconds
                };
            }

            using var stream = File.Open(filePath, FileMode.Open, FileAccess.Read);
            using var reader = ExcelReaderFactory.CreateReader(stream);
            var dataset = reader.AsDataSet(new ExcelDataSetConfiguration
            {
                ConfigureDataTable = _ => new ExcelDataTableConfiguration { UseHeaderRow = false }
            });

            var table = dataset.Tables[0];
            result = result with { TotalLinhas = table.Rows.Count - 1 }; // -1 para excluir header

            _logger.LogInformation("Total de linhas a processar: {TotalLinhas}", result.TotalLinhas);

            // Processar todas as linhas (ignorar header row 0)
            int linhasOk = 0, linhasWarnings = 0, linhasErros = 0;
            for (int i = 1; i < table.Rows.Count; i++)
            {
                var row = table.Rows[i];
                var (protocolo, warning, erro) = ProcessDataRow(row, i + 1);

                if (protocolo != null)
                {
                    // Upsert no repositório
                    await _protocoloRepository.UpsertAsync(protocolo);
                    linhasOk++;

                    if (!string.IsNullOrEmpty(warning))
                    {
                        result.Warnings.Add($"Linha {i + 1}: {warning}");
                        linhasWarnings++;
                    }

                    // Log de progresso a cada 100 linhas
                    if (linhasOk % 100 == 0)
                    {
                        _logger.LogInformation("📊 Progresso: {LinhasOk}/{TotalLinhas} linhas importadas ({Percentagem:F1}%)",
                            linhasOk, result.TotalLinhas, (linhasOk * 100.0 / result.TotalLinhas));
                    }
                }
                else
                {
                    result.Erros.Add($"Linha {i + 1}: {erro ?? "Erro desconhecido"}");
                    linhasErros++;
                }
            }

            stopwatch.Stop();

            // Criar log de importação na BD
            var importLog = new ImportacaoExcelLog
            {
                NomeFicheiro = Path.GetFileName(filePath),
                CaminhoCompleto = filePath,
                TotalLinhas = result.TotalLinhas,
                LinhasOk = linhasOk,
                LinhasWarnings = linhasWarnings,
                LinhasErros = linhasErros,
                DuracaoSegundos = (int)stopwatch.Elapsed.TotalSeconds,
                DataImportacao = DateTime.UtcNow,
                Sucesso = linhasErros == 0,
                DetalhesJson = System.Text.Json.JsonSerializer.Serialize(new
                {
                    Warnings = result.Warnings.Take(50).ToList(),
                    Erros = result.Erros.Take(50).ToList()
                })
            };

            // Gravar log (não bloquear em caso de erro)
            try
            {
                await _protocoloRepository.AddImportLogAsync(importLog);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Não foi possível gravar log de importação");
            }

            _logger.LogInformation("✅ Importação completa em {Elapsed}s. {LinhasOk}/{TotalLinhas} OK, {LinhasWarnings} warnings, {LinhasErros} erros",
                stopwatch.Elapsed.TotalSeconds, linhasOk, result.TotalLinhas, linhasWarnings, linhasErros);

            return result with
            {
                Sucesso = linhasErros == 0,
                LinhasOk = linhasOk,
                LinhasWarnings = linhasWarnings,
                LinhasErros = linhasErros,
                DuracaoSegundos = stopwatch.Elapsed.TotalSeconds
            };
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            _logger.LogError(ex, "💥 Erro CRÍTICO durante importação de {FilePath}", filePath);

            return result with
            {
                Sucesso = false,
                MensagemErro = $"Erro crítico: {ex.Message}",
                DuracaoSegundos = stopwatch.Elapsed.TotalSeconds
            };
        }
    }

    #region Helper Methods

    private (PreviewLine?, string?, string?) ProcessDataRowForPreview(DataRow row, int numeroLinha)
    {
        try
        {
            // Ler colunas Disease (EN) e Indikationen (DE)
            var diseaseEn = row.ItemArray.Length > COL_DISEASE ? row.ItemArray[COL_DISEASE]?.ToString()?.Trim() : null;
            var indikationenDe = row.ItemArray.Length > COL_INDIKATIONEN ? row.ItemArray[COL_INDIKATIONEN]?.ToString()?.Trim() : null;

            // Ignorar linhas vazias ou placeholders
            if (string.IsNullOrWhiteSpace(diseaseEn) ||
                diseaseEn.StartsWith("AAA", StringComparison.OrdinalIgnoreCase) ||
                diseaseEn.Contains("verfügbar", StringComparison.OrdinalIgnoreCase))
            {
                return (null, null, "Linha vazia ou placeholder");
            }

            // Traduzir para português
            var nomePt = MedicalTermsTranslator.TranslateToPortuguese(diseaseEn);
            var temTraducao = !string.Equals(diseaseEn, nomePt, StringComparison.OrdinalIgnoreCase);

            // Extrair frequências
            var frequencias = ExtractFrequenciesFromRow(row);
            var categoria = InferirCategoria(nomePt);

            var previewLine = new PreviewLine
            {
                NumeroLinha = numeroLinha,
                NomeOriginal = diseaseEn,
                NomeTraduzido = nomePt,
                Categoria = categoria,
                NumeroFrequencias = frequencias.Count,
                TemTraducao = temTraducao,
                Aviso = temTraducao ? null : "⚠️  Tradução heurística (não encontrada no dicionário)"
            };

            string? warning = frequencias.Count == 0 ? "Sem frequências" : null;
            return (previewLine, warning, null);
        }
        catch (Exception ex)
        {
            return (null, null, $"Erro ao processar linha: {ex.Message}");
        }
    }

    private (ProtocoloTerapeutico?, string?, string?) ProcessDataRow(DataRow row, int numeroLinha)
    {
        try
        {
            // Ler colunas Disease (EN) e Indikationen (DE)
            var diseaseEn = row.ItemArray.Length > COL_DISEASE ? row.ItemArray[COL_DISEASE]?.ToString()?.Trim() : null;
            var indikationenDe = row.ItemArray.Length > COL_INDIKATIONEN ? row.ItemArray[COL_INDIKATIONEN]?.ToString()?.Trim() : null;

            // Ignorar linhas vazias ou placeholders
            if (string.IsNullOrWhiteSpace(diseaseEn) ||
                diseaseEn.StartsWith("AAA", StringComparison.OrdinalIgnoreCase) ||
                diseaseEn.Contains("verfügbar", StringComparison.OrdinalIgnoreCase))
            {
                return (null, null, "Linha vazia ou placeholder");
            }

            // Traduzir para português
            var nomePt = MedicalTermsTranslator.TranslateToPortuguese(diseaseEn);

            // Extrair frequências
            var frequencias = ExtractFrequenciesFromRow(row);
            if (frequencias.Count == 0)
            {
                return (null, "Sem frequências válidas", null);
            }

            var categoria = InferirCategoria(nomePt);

            // Criar protocolo
            var protocolo = new ProtocoloTerapeutico
            {
                ExternalId = Guid.NewGuid().ToString(), // Novo GUID para cada import (upsert faz merge por Nome)
                Nome = nomePt,
                Categoria = categoria,
                CriadoEm = DateTime.UtcNow,
                AtualizadoEm = DateTime.UtcNow,
                Ativo = true
            };
            protocolo.SetFrequencias(frequencias.ToArray());

            // Warning se tradução não foi encontrada (heurística)
            bool temTraducao = !string.Equals(diseaseEn, nomePt, StringComparison.OrdinalIgnoreCase);
            string? warning = temTraducao ? null : $"Tradução heurística: '{diseaseEn}' → '{nomePt}'";

            return (protocolo, warning, null);
        }
        catch (Exception ex)
        {
            return (null, null, $"Erro ao processar linha: {ex.Message}");
        }
    }

    private List<double> ExtractFrequenciesFromRow(DataRow row)
    {
        var frequencias = new List<double>();

        // Iterar pelas colunas de frequências (COL_FREQ_START até final)
        for (int col = COL_FREQ_START; col < row.ItemArray.Length; col++)
        {
            var cellValue = row.ItemArray[col]?.ToString()?.Trim();
            if (string.IsNullOrWhiteSpace(cellValue))
                continue;

            if (TryParseFrequency(cellValue, out double freq))
            {
                frequencias.Add(freq);
            }
        }

        return frequencias;
    }

    private bool TryParseFrequency(string value, out double frequency)
    {
        frequency = 0;

        if (string.IsNullOrWhiteSpace(value))
            return false;

        // Substituir vírgula por ponto (formato europeu)
        value = value.Replace(',', '.');

        // Tentar parse
        if (double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out frequency))
        {
            return frequency > 0; // Só aceitar frequências positivas
        }

        return false;
    }

    private string? InferirCategoria(string nome)
    {
        var nomeLower = nome.ToLowerInvariant();

        // Digestivo
        if (nomeLower.Contains("abdominal") || nomeLower.Contains("estômago") || nomeLower.Contains("intestin") ||
            nomeLower.Contains("digestão") || nomeLower.Contains("náusea") || nomeLower.Contains("vômito") ||
            nomeLower.Contains("fígado") || nomeLower.Contains("vesícula") || nomeLower.Contains("cólon"))
            return "Digestivo";

        // Neurológico
        if (nomeLower.Contains("cereb") || nomeLower.Contains("nervo") || nomeLower.Contains("neuro") ||
            nomeLower.Contains("dor de cabeça") || nomeLower.Contains("enxaqueca") || nomeLower.Contains("epilepsia") ||
            nomeLower.Contains("parkinson") || nomeLower.Contains("alzheimer") || nomeLower.Contains("esclerose"))
            return "Neurológico";

        // Cardiovascular
        if (nomeLower.Contains("coração") || nomeLower.Contains("cardíaco") || nomeLower.Contains("pressão") ||
            nomeLower.Contains("circulação") || nomeLower.Contains("artéria") || nomeLower.Contains("veia"))
            return "Cardiovascular";

        // Musculoesquelético
        if (nomeLower.Contains("músculo") || nomeLower.Contains("osso") || nomeLower.Contains("articulação") ||
            nomeLower.Contains("artrite") || nomeLower.Contains("artrose") || nomeLower.Contains("tendinite") ||
            nomeLower.Contains("bursite") || nomeLower.Contains("lombar") || nomeLower.Contains("cervical"))
            return "Musculoesquelético";

        // Emocional
        if (nomeLower.Contains("ansiedade") || nomeLower.Contains("depressão") || nomeLower.Contains("stress") ||
            nomeLower.Contains("insónia") || nomeLower.Contains("fadiga") || nomeLower.Contains("emocional"))
            return "Emocional";

        // Respiratório
        if (nomeLower.Contains("pulmão") || nomeLower.Contains("respirat") || nomeLower.Contains("asma") ||
            nomeLower.Contains("bronquite") || nomeLower.Contains("tosse") || nomeLower.Contains("sinusite"))
            return "Respiratório";

        // Urinário
        if (nomeLower.Contains("rim") || nomeLower.Contains("renal") || nomeLower.Contains("urinári") ||
            nomeLower.Contains("bexiga") || nomeLower.Contains("próstata") || nomeLower.Contains("cistite"))
            return "Urinário";

        // Dermatológico
        if (nomeLower.Contains("pele") || nomeLower.Contains("dermat") || nomeLower.Contains("eczema") ||
            nomeLower.Contains("psoríase") || nomeLower.Contains("acne") || nomeLower.Contains("herpes"))
            return "Dermatológico";

        // Default
        return "Geral";
    }

    #endregion
}
```

**IMPORTANTE**: Este código substitui TODO o ficheiro `ExcelImportService.cs`. 
Principais mudanças:
1. Usa `ExcelDataReader` em vez de `EPPlus`
2. Regista `CodePagesEncodingProvider` para ler `.xls` antigos
3. Usa `DataRow` em vez de `ExcelWorksheet.Cells`
4. Mantém toda lógica de tradução, parsing, categorização
