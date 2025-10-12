using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Templates e documentos globais disponíveis para toda a clínica
/// Inclui templates da app (Consentimentos, Declarações) e documentos externos (Regulamentos, PDFs)
/// </summary>
public class TemplateGlobal
{
    public int Id { get; set; }

    /// <summary>
    /// Nome do template/documento (ex: "Regulamento Interno", "Consentimento Naturopatia")
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Tipo: "TemplateApp" (gerado pela app) | "DocumentoExterno" (PDF/Word upload)
    /// </summary>
    [Required]
    [StringLength(50)]
    public string Tipo { get; set; } = "DocumentoExterno";

    /// <summary>
    /// Caminho relativo do arquivo (ex: "Templates_Globais/Regulamento.pdf")
    /// </summary>
    [Required]
    [StringLength(500)]
    public string CaminhoArquivo { get; set; } = string.Empty;

    /// <summary>
    /// Descrição opcional do documento
    /// </summary>
    [StringLength(500)]
    public string? Descricao { get; set; }

    /// <summary>
    /// Se verdadeiro, aparece como opção de anexo nos emails
    /// </summary>
    public bool DisponivelEmail { get; set; } = true;

    /// <summary>
    /// Categoria: "Consentimento" | "Declaracao" | "Prescricao" | "Geral"
    /// </summary>
    [StringLength(50)]
    public string Categoria { get; set; } = "Geral";

    /// <summary>
    /// Data em que foi adicionado à biblioteca
    /// </summary>
    public DateTime DataAdicao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Última atualização do documento
    /// </summary>
    public DateTime? DataAtualizacao { get; set; }

    /// <summary>
    /// Soft delete
    /// </summary>
    public bool IsDeleted { get; set; } = false;
}
