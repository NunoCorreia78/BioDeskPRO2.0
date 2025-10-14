using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um item do Banco de Dados Core Informacional
/// Usado para análise de ressonância e terapias bioenergéticas
/// Inspirado no sistema Inergetix CoRe 5.0
/// </summary>
public class ItemBancoCore
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// ID externo (GUID) para garantir unicidade absoluta
    /// </summary>
    [Required]
    public Guid ExternalId { get; set; }

    /// <summary>
    /// Nome legível do item (ex: "Arnica Montana 30CH")
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Categoria principal do item
    /// </summary>
    [Required]
    public CategoriaCore Categoria { get; set; }

    /// <summary>
    /// Subcategoria específica (ex: "Trauma Físico", "Sistema Reprodutor Feminino")
    /// </summary>
    [StringLength(100)]
    public string? Subcategoria { get; set; }

    /// <summary>
    /// Descrição breve de 50-200 caracteres
    /// </summary>
    [StringLength(500)]
    public string? DescricaoBreve { get; set; }

    /// <summary>
    /// Metadata em formato JSON com informações detalhadas
    /// Exemplo: indicações, contraindicações, propriedades terapêuticas, etc.
    /// </summary>
    public string? JsonMetadata { get; set; }

    /// <summary>
    /// Fonte ou referência bibliográfica
    /// Exemplo: "Boericke Materia Medica (2000)", "Dr. Edward Bach - 38 Remedies"
    /// </summary>
    [StringLength(200)]
    public string? FonteOrigem { get; set; }

    /// <summary>
    /// Género ao qual o item é aplicável
    /// Valores: "Masculino", "Feminino", "Ambos"
    /// Crítico para órgãos reprodutores
    /// </summary>
    [StringLength(20)]
    public string? GeneroAplicavel { get; set; }

    /// <summary>
    /// Indica se o item está ativo no catálogo
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Data de criação do registo
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Data de última atualização (opcional)
    /// </summary>
    public DateTime? UpdatedAt { get; set; }
}
