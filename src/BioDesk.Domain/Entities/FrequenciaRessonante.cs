using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Frequência ressonante detectada durante scan (CoRe-like)
/// Ordenada por Value % (100% = maior ressonância)
/// </summary>
public class FrequenciaRessonante
{
    public int Id { get; set; }

    /// <summary>
    /// Sessão de terapia à qual pertence
    /// </summary>
    public int SessaoTerapiaId { get; set; }
    public SessaoTerapia SessaoTerapia { get; set; } = null!;

    /// <summary>
    /// Frequência em Hz
    /// </summary>
    [Range(0.01, 2000000)]
    public decimal FrequenciaHz { get; set; }

    /// <summary>
    /// Value % (0-100) - Ressonância inicial detectada no scan
    /// 100% = maior ressonância, 0% = sem ressonância
    /// </summary>
    [Range(0, 100)]
    public decimal ValuePct { get; set; }

    /// <summary>
    /// Improvement % (0-100) - Evolução durante a emissão
    /// Objetivo: aproximar de 100%
    /// </summary>
    [Range(0, 100)]
    public decimal ImprovementPct { get; set; } = 0;

    /// <summary>
    /// Se true, item foi selecionado para emissão
    /// </summary>
    public bool Selecionado { get; set; } = false;

    /// <summary>
    /// Status da emissão (Pendente, Emitindo, Concluído)
    /// </summary>
    [StringLength(20)]
    public string Status { get; set; } = "Pendente";

    /// <summary>
    /// Timestamp do scan
    /// </summary>
    public DateTime DetectadoEm { get; set; } = DateTime.Now;
}
