using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma leitura bioenergética durante sessão
/// Contém métricas capturadas (RMS, Pico, FFT, GSR, etc.)
/// </summary>
public class LeituraBioenergetica
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Sessão associada
    /// </summary>
    [Required]
    public int SessaoTerapiaId { get; set; }
    public SessaoTerapia SessaoTerapia { get; set; } = null!;

    /// <summary>
    /// Timestamp da leitura
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// RMS (Root Mean Square) da amostra
    /// </summary>
    public double Rms { get; set; }

    /// <summary>
    /// Valor de pico (máximo absoluto)
    /// </summary>
    public double Pico { get; set; }

    /// <summary>
    /// Componente de frequência dominante (Hz)
    /// </summary>
    public double FrequenciaDominante { get; set; }

    /// <summary>
    /// Potência espectral no domínio de frequência
    /// </summary>
    public double PotenciaEspectral { get; set; }

    /// <summary>
    /// GSR (Galvanic Skin Response) - opcional
    /// </summary>
    public double? Gsr { get; set; }

    /// <summary>
    /// Métricas adicionais em JSON
    /// </summary>
    [StringLength(2000)]
    public string? MetricasAdicionaisJson { get; set; }

    /// <summary>
    /// Canal de origem (1, 2)
    /// </summary>
    public int Canal { get; set; } = 1;
}
