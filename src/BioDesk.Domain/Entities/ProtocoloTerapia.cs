using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Protocolo de terapia bioenergética (importado de Excel v1)
/// Representa uma sequência pré-programada de frequências para condições específicas
/// </summary>
public class ProtocoloTerapia
{
    public int Id { get; set; }

    /// <summary>
    /// GUID externo para importação idempotente (Upsert baseado neste campo)
    /// </summary>
    [Required]
    [StringLength(36)]
    public string ExternalId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Nome do protocolo (ex: "Dor Lombar Aguda", "Stress Crónico")
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Categoria opcional (ex: "Dor", "Digestivo", "Emocional")
    /// </summary>
    [StringLength(100)]
    public string? Categoria { get; set; }

    /// <summary>
    /// Frequência em Hz (decimal positivo)
    /// </summary>
    [Range(0.01, 2000000)]
    public decimal FrequenciaHz { get; set; }

    /// <summary>
    /// Amplitude em volts (0-20V para segurança clínica)
    /// </summary>
    [Range(0, 20)]
    public decimal AmplitudeV { get; set; } = 5.0m;

    /// <summary>
    /// Limite de corrente em miliamperes (0-50mA para segurança)
    /// </summary>
    [Range(0, 50)]
    public decimal LimiteCorrenteMa { get; set; } = 10.0m;

    /// <summary>
    /// Forma de onda (Sine, Square, Triangle, Saw)
    /// </summary>
    [Required]
    [StringLength(20)]
    public string FormaOnda { get; set; } = "Sine";

    /// <summary>
    /// Modulação (AM, FM, Burst, None)
    /// </summary>
    [StringLength(20)]
    public string Modulacao { get; set; } = "None";

    /// <summary>
    /// Duração em minutos (1-180 min)
    /// </summary>
    [Range(1, 180)]
    public int DuracaoMin { get; set; } = 5;

    /// <summary>
    /// Canal de saída (1 ou 2 para TiePie HS3)
    /// </summary>
    [Range(1, 2)]
    public int Canal { get; set; } = 1;

    /// <summary>
    /// Sequência JSON com overrides passo-a-passo (opcional)
    /// Formato: [{"step":1, "freqHz":100, "durationSec":30}, ...]
    /// </summary>
    public string? SequenciaJSON { get; set; }

    /// <summary>
    /// Contraindicações clínicas
    /// </summary>
    [StringLength(1000)]
    public string? Contraindicacoes { get; set; }

    /// <summary>
    /// Notas adicionais do protocolo
    /// </summary>
    [StringLength(2000)]
    public string? Notas { get; set; }

    /// <summary>
    /// Versão do schema Excel (para compatibilidade futura)
    /// </summary>
    [StringLength(10)]
    public string Versao { get; set; } = "1.0";

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // METADATA
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    public DateTime CriadoEm { get; set; } = DateTime.Now;
    public DateTime? ModificadoEm { get; set; }
    public bool IsDeleted { get; set; } = false;
}
