using System;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Tipo de terapia executada.
/// </summary>
public enum TipoTerapia
{
    /// <summary>Terapia remota/informacional (seeds, RNG, 14 dias).</summary>
    Remota = 0,
    
    /// <summary>Terapia local com emissão direta de Hz + voltagem controlada.</summary>
    Local = 1,
    
    /// <summary>Sessão biofeedback autónoma (loop scan→emit).</summary>
    Biofeedback = 2
}

/// <summary>
/// Histórico de sessões de terapia executadas.
/// </summary>
public class SessionHistorico
{
    /// <summary>ID único da sessão.</summary>
    public int Id { get; set; }

    /// <summary>ID do paciente (FK opcional - pode ser sessão sem paciente específico).</summary>
    public int? PacienteId { get; set; }

    /// <summary>Data/hora de início da sessão.</summary>
    public DateTime DataHoraInicio { get; set; }

    /// <summary>Tipo de terapia executada.</summary>
    public TipoTerapia TipoTerapia { get; set; }

    /// <summary>
    /// Protocolos usados (JSON array de strings).
    /// Exemplo Remota: ["Vírus Herpes", "Detox Fígado"]
    /// Exemplo Local/Biofeedback: [] (vazio se não aplicável)
    /// </summary>
    public string ProtocolosJson { get; set; } = "[]";

    /// <summary>
    /// Frequências Hz usadas (JSON array de objetos {Hz, DutyPercent, DuracaoSegundos}).
    /// Exemplo Local: [{"Hz":432.5,"DutyPercent":50,"DuracaoSegundos":180}]
    /// Exemplo Remota: [] (não aplicável)
    /// </summary>
    public string FrequenciasHzJson { get; set; } = "[]";

    /// <summary>Duração total da sessão em minutos (calculado ou estimado).</summary>
    public int? DuracaoMinutos { get; set; }

    /// <summary>Voltagem usada (V) - apenas Local/Biofeedback.</summary>
    public double? VoltagemV { get; set; }

    /// <summary>Corrente máxima usada (mA) - apenas Local/Biofeedback.</summary>
    public double? CorrenteMa { get; set; }

    /// <summary>Notas livres sobre a sessão (opcional).</summary>
    public string? Notas { get; set; }

    /// <summary>Timestamp de criação do registo.</summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;

    // Navigation property (EF Core)
    public Paciente? Paciente { get; set; }
}
