using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma sessão de terapia bioenergética executada
/// Contém parâmetros de RNG, hardware e resultados finais
/// </summary>
public class SessaoTerapia
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Plano de terapia associado
    /// </summary>
    [Required]
    public int PlanoTerapiaId { get; set; }
    public PlanoTerapia PlanoTerapia { get; set; } = null!;

    /// <summary>
    /// Data/hora de início
    /// </summary>
    public DateTime InicioEm { get; set; }

    /// <summary>
    /// Data/hora de fim
    /// </summary>
    public DateTime? FimEm { get; set; }

    /// <summary>
    /// Duração total em minutos
    /// </summary>
    public int? DuracaoTotalMinutos { get; set; }

    /// <summary>
    /// Tipo de RNG usado (Deterministic, Alea, System)
    /// </summary>
    [StringLength(20)]
    public string TipoRng { get; set; } = "Deterministic";

    /// <summary>
    /// Seed do RNG (para reprodutibilidade)
    /// </summary>
    [StringLength(100)]
    public string? RngSeed { get; set; }

    /// <summary>
    /// Hardware usado (TiePie HS3, Mock, etc.)
    /// </summary>
    [StringLength(50)]
    public string? HardwareUsado { get; set; }

    /// <summary>
    /// Número total de itens aplicados
    /// </summary>
    public int TotalItensAplicados { get; set; }

    /// <summary>
    /// Improvement % médio alcançado
    /// </summary>
    public double ImprovementMedio { get; set; }

    /// <summary>
    /// Estado da sessão (Iniciada, EmProgresso, Concluída, Cancelada)
    /// </summary>
    [StringLength(20)]
    public string Estado { get; set; } = "Iniciada";

    /// <summary>
    /// Observações finais
    /// </summary>
    [StringLength(2000)]
    public string? Observacoes { get; set; }

    /// <summary>
    /// Data de criação
    /// </summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;

    // Navigation properties
    public ICollection<LeituraBioenergetica> Leituras { get; set; } = new List<LeituraBioenergetica>();
    public ICollection<EventoHardware> EventosHardware { get; set; } = new List<EventoHardware>();
}
