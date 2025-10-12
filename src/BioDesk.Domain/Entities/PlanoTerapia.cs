using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um plano terapêutico para sessão bioenergética
/// Contém fila de protocolos a aplicar com Value % inicial
/// </summary>
public class PlanoTerapia
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Sessão associada
    /// </summary>
    [Required]
    public int SessaoId { get; set; }
    public Sessao Sessao { get; set; } = null!;

    /// <summary>
    /// Nome do plano (ex: "Plano Digestivo - 12/10/2025")
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Descrição do plano
    /// </summary>
    [StringLength(1000)]
    public string? Descricao { get; set; }

    /// <summary>
    /// Data de criação
    /// </summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Estado do plano (Rascunho, Ativo, Concluído, Cancelado)
    /// </summary>
    [StringLength(20)]
    public string Estado { get; set; } = "Rascunho";

    // Navigation properties
    public ICollection<Terapia> Terapias { get; set; } = new List<Terapia>();
    public ICollection<SessaoTerapia> SessoesTerapia { get; set; } = new List<SessaoTerapia>();
}
