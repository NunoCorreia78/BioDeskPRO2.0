using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma sessão completa de terapia bioenergética
/// Vinculada ao paciente e contém histórico de emissões
/// </summary>
public class SessaoTerapia
{
    public int Id { get; set; }

    /// <summary>
    /// Paciente que recebeu a terapia
    /// </summary>
    public int PacienteId { get; set; }
    public Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Data e hora da sessão
    /// </summary>
    public DateTime DataHora { get; set; } = DateTime.Now;

    /// <summary>
    /// Duração total da sessão em minutos
    /// </summary>
    public int DuracaoTotalMin { get; set; }

    /// <summary>
    /// Tipo de sessão (Scan, Biofeedback, Protocolo)
    /// </summary>
    [Required]
    [StringLength(50)]
    public string TipoSessao { get; set; } = string.Empty;

    /// <summary>
    /// Hash do PDF de consentimento assinado
    /// </summary>
    [StringLength(64)]
    public string? ConsentimentoHash { get; set; }

    /// <summary>
    /// Observações clínicas da sessão
    /// </summary>
    [StringLength(2000)]
    public string? Observacoes { get; set; }

    /// <summary>
    /// Emissões de frequência realizadas nesta sessão
    /// </summary>
    public List<EmissaoFrequencia> Emissoes { get; set; } = new();

    /// <summary>
    /// Métricas de biofeedback registadas durante a sessão
    /// JSON: {"rms": [...], "peak": [...], "impedance": [...]}
    /// </summary>
    public string? MetricasBiofeedbackJSON { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // METADATA
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    public DateTime CriadoEm { get; set; } = DateTime.Now;
    public DateTime? ModificadoEm { get; set; }
    public bool IsDeleted { get; set; } = false;
}
