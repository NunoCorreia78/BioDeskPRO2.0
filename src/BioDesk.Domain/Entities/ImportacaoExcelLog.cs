using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Log de importação de Excel (FrequencyList.xls)
/// Rastreabilidade de importações e erros
/// </summary>
public class ImportacaoExcelLog
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Nome do ficheiro importado
    /// </summary>
    [Required]
    [StringLength(500)]
    public string NomeFicheiro { get; set; } = string.Empty;

    /// <summary>
    /// Caminho completo do ficheiro
    /// </summary>
    [Required]
    [StringLength(1000)]
    public string CaminhoCompleto { get; set; } = string.Empty;

    /// <summary>
    /// Data/hora da importação
    /// </summary>
    public DateTime ImportadoEm { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Total de linhas processadas
    /// </summary>
    public int TotalLinhas { get; set; }

    /// <summary>
    /// Linhas importadas com sucesso
    /// </summary>
    public int LinhasOk { get; set; }

    /// <summary>
    /// Linhas com warnings (tradução não encontrada, etc.)
    /// </summary>
    public int LinhasWarnings { get; set; }

    /// <summary>
    /// Linhas com erros (validação falhou)
    /// </summary>
    public int LinhasErros { get; set; }

    /// <summary>
    /// Duração da importação em segundos
    /// </summary>
    public double DuracaoSegundos { get; set; }

    /// <summary>
    /// Sucesso geral
    /// </summary>
    public bool Sucesso { get; set; }

    /// <summary>
    /// Mensagem de erro (se falhou)
    /// </summary>
    [StringLength(2000)]
    public string? MensagemErro { get; set; }

    /// <summary>
    /// Detalhes de warnings/erros em JSON
    /// </summary>
    public string? DetalhesJson { get; set; }

    /// <summary>
    /// Utilizador que importou (futuro)
    /// </summary>
    [StringLength(100)]
    public string? UtilizadorId { get; set; }
}
