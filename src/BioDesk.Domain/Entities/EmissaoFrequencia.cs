using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Registo de uma emissão individual de frequência (sequencial)
/// Parte da sessão de terapia, com parâmetros e métricas
/// </summary>
public class EmissaoFrequencia
{
    public int Id { get; set; }

    /// <summary>
    /// Sessão de terapia à qual pertence
    /// </summary>
    public int SessaoTerapiaId { get; set; }
    public SessaoTerapia SessaoTerapia { get; set; } = null!;

    /// <summary>
    /// Protocolo usado (se aplicável)
    /// </summary>
    public int? ProtocoloTerapiaId { get; set; }
    public ProtocoloTerapia? ProtocoloTerapia { get; set; }

    /// <summary>
    /// Ordem de execução na sequência
    /// </summary>
    public int OrdemSequencia { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // PARÂMETROS DE EMISSÃO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [Range(0.01, 2000000)]
    public decimal FrequenciaHz { get; set; }

    [Range(0, 20)]
    public decimal AmplitudeV { get; set; }

    [Range(0, 50)]
    public decimal LimiteCorrenteMa { get; set; }

    [StringLength(20)]
    public string FormaOnda { get; set; } = "Sine";

    [StringLength(20)]
    public string Modulacao { get; set; } = "None";

    [Range(1, 2)]
    public int Canal { get; set; } = 1;

    /// <summary>
    /// Duração planejada em segundos
    /// </summary>
    public int DuracaoPlaneadaSeg { get; set; }

    /// <summary>
    /// Duração real em segundos
    /// </summary>
    public int DuracaoRealSeg { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // MÉTRICAS DE BIOFEEDBACK
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Value % inicial (antes da emissão)
    /// </summary>
    [Range(0, 100)]
    public decimal? ValuePctInicial { get; set; }

    /// <summary>
    /// Improvement % final (após emissão)
    /// </summary>
    [Range(0, 100)]
    public decimal? ImprovementPctFinal { get; set; }

    /// <summary>
    /// RMS médio durante emissão (mV)
    /// </summary>
    public decimal? RmsMedio { get; set; }

    /// <summary>
    /// Pico máximo detectado (mV)
    /// </summary>
    public decimal? PicoMaximo { get; set; }

    /// <summary>
    /// Impedância média (Ω)
    /// </summary>
    public decimal? ImpedanciaMedia { get; set; }

    /// <summary>
    /// Frequência dominante no FFT (Hz)
    /// </summary>
    public decimal? FrequenciaDominanteHz { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // TIMESTAMPS E STATUS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    public DateTime InicioEm { get; set; }
    public DateTime? FimEm { get; set; }

    [StringLength(20)]
    public string Status { get; set; } = "Pendente"; // Pendente, Emitindo, Concluído, Pausado, Cancelado

    [StringLength(500)]
    public string? MotivoParada { get; set; } // Se pausa automática (impedância fora de gama, etc.)
}
