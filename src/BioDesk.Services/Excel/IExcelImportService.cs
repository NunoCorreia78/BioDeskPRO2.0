using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Excel;

/// <summary>
/// Resultado de preview de importação Excel
/// </summary>
public record ExcelImportPreview
{
    public int TotalLinhas { get; init; }
    public int LinhasValidas { get; init; }
    public int LinhasWarnings { get; init; }
    public int LinhasErros { get; init; }
    public List<PreviewLine> Previews { get; init; } = new();
    public List<string> Erros { get; init; } = new();
    public List<string> Warnings { get; init; } = new();
}

public record PreviewLine
{
    public int NumeroLinha { get; init; }
    public string NomeOriginal { get; init; } = string.Empty;
    public string NomeTraduzido { get; init; } = string.Empty;
    public string? Categoria { get; init; }
    public int NumeroFrequencias { get; init; }
    public bool TemTraducao { get; init; }
    public string? Aviso { get; init; }
}

/// <summary>
/// Resultado de importação Excel
/// </summary>
public record ExcelImportResult
{
    public bool Sucesso { get; init; }
    public int TotalLinhas { get; init; }
    public int LinhasOk { get; init; }
    public int LinhasWarnings { get; init; }
    public int LinhasErros { get; init; }
    public double DuracaoSegundos { get; init; }
    public List<string> Erros { get; init; } = new();
    public List<string> Warnings { get; init; } = new();
    public string? MensagemErro { get; init; }
}

/// <summary>
/// Serviço de importação de ficheiros Excel (FrequencyList.xls)
/// </summary>
public interface IExcelImportService
{
    /// <summary>
    /// Preview de importação (sem gravar na BD)
    /// </summary>
    Task<ExcelImportPreview> PreviewAsync(string filePath, int maxLinhasPreview = 20);

    /// <summary>
    /// Importação completa com gravação na BD
    /// </summary>
    Task<ExcelImportResult> ImportAsync(string filePath);

    /// <summary>
    /// Validação básica do ficheiro Excel
    /// </summary>
    Task<(bool IsValid, string ErrorMessage)> ValidateFileAsync(string filePath);
}
