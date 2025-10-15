using System;
using System.ComponentModel.DataAnnotations;
using BioDesk.Domain.Enums;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Item do Banco de Dados Core Informacional
/// Sistema inspirado no Inergetix CoRe 5.0 para análise de ressonância
/// Cada item representa um elemento terapêutico que pode ser testado via RNG
/// </summary>
public class ItemBancoCore
{
    /// <summary>
    /// ID interno da base de dados (auto-increment)
    /// </summary>
    public int Id { get; set; }

    /// <summary>
    /// Identificador único global (GUID) gerado deterministicamente via SHA256
    /// Garante reprodutibilidade e zero duplicados entre sistemas
    /// </summary>
    [Required]
    public Guid ExternalId { get; set; }

    /// <summary>
    /// Nome legível do item (ex: "Arnica Montana 30CH", "Chakra Raiz", "Rock Rose")
    /// </summary>
    [Required]
    [StringLength(300)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Categoria principal do item (Homeopatia, FloraisBach, Orgao, etc.)
    /// </summary>
    [Required]
    public CategoriaCore Categoria { get; set; }

    /// <summary>
    /// Subcategoria específica (ex: "Trauma Físico", "Medo", "Sistema Cardiovascular")
    /// Permite filtros refinados dentro de cada categoria
    /// </summary>
    [StringLength(200)]
    public string? Subcategoria { get; set; }

    /// <summary>
    /// Descrição breve do item (50-200 caracteres)
    /// Resumo das indicações principais e características
    /// </summary>
    [StringLength(500)]
    public string? DescricaoBreve { get; set; }

    /// <summary>
    /// Metadados ricos em formato JSON (mínimo 3 propriedades)
    /// Exemplos: indicações, sintomas-chave, complementares, frequências, etc.
    /// </summary>
    public string? JsonMetadata { get; set; }

    /// <summary>
    /// Fonte bibliográfica de origem (ex: "Boericke Materia Medica (2000)")
    /// Garante rastreabilidade e credibilidade clínica
    /// </summary>
    [StringLength(300)]
    public string? FonteOrigem { get; set; }

    /// <summary>
    /// Género aplicável: "Masculino", "Feminino", "Ambos"
    /// CRÍTICO para órgãos reprodutores (Próstata=Masculino, Ovários=Feminino)
    /// SEMPRE "Ambos" para emoções, florais, chakras, meridianos
    /// </summary>
    [StringLength(20)]
    public string? GeneroAplicavel { get; set; }

    /// <summary>
    /// Indica se o item está ativo e disponível para análise
    /// </summary>
    public bool IsActive { get; set; } = true;

    /// <summary>
    /// Data de criação do registo (UTC)
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
