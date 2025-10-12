using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um item na fila de terapia (protocolo + Value % + Improvement %)
/// Ligação entre PlanoTerapia e ProtocoloTerapeutico
/// </summary>
public class Terapia
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Plano associado
    /// </summary>
    [Required]
    public int PlanoTerapiaId { get; set; }
    public PlanoTerapia PlanoTerapia { get; set; } = null!;

    /// <summary>
    /// Protocolo terapêutico a aplicar
    /// </summary>
    [Required]
    public int ProtocoloTerapeuticoId { get; set; }
    public ProtocoloTerapeutico ProtocoloTerapeutico { get; set; } = null!;

    /// <summary>
    /// Ordem na fila (1, 2, 3, ...)
    /// </summary>
    public int Ordem { get; set; }

    /// <summary>
    /// Value % inicial (0-100)
    /// Calculado por RNG ou métricas bioenergéticas
    /// </summary>
    public double ValuePercent { get; set; }

    /// <summary>
    /// Improvement % atual (0-100)
    /// Atualizado durante sessão
    /// </summary>
    public double ImprovementPercent { get; set; }

    /// <summary>
    /// Alvo de melhoria (%) para auto-desmarcar
    /// </summary>
    public double AlvoMelhoria { get; set; } = 95.0;

    /// <summary>
    /// Item aplicado durante sessão
    /// </summary>
    public bool Aplicado { get; set; }

    /// <summary>
    /// Data/hora de aplicação
    /// </summary>
    public DateTime? AplicadoEm { get; set; }

    /// <summary>
    /// Duração real de aplicação em minutos
    /// </summary>
    public int? DuracaoMinutos { get; set; }

    /// <summary>
    /// Notas sobre aplicação
    /// </summary>
    [StringLength(500)]
    public string? NotasAplicacao { get; set; }

    /// <summary>
    /// Data de criação
    /// </summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;
}
