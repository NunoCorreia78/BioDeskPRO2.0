using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um evento de hardware durante sessão
/// Log de conexão, desconexão, erros, overlimits, etc.
/// </summary>
public class EventoHardware
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
    /// Timestamp do evento
    /// </summary>
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Tipo de evento (Connected, Disconnected, Error, Overlimit, ConfigChanged)
    /// </summary>
    [Required]
    [StringLength(50)]
    public string TipoEvento { get; set; } = string.Empty;

    /// <summary>
    /// Severidade (Info, Warning, Error, Critical)
    /// </summary>
    [StringLength(20)]
    public string Severidade { get; set; } = "Info";

    /// <summary>
    /// Mensagem descritiva
    /// </summary>
    [Required]
    [StringLength(500)]
    public string Mensagem { get; set; } = string.Empty;

    /// <summary>
    /// Detalhes adicionais em JSON
    /// </summary>
    [StringLength(2000)]
    public string? DetalhesJson { get; set; }

    /// <summary>
    /// Código de erro (se aplicável)
    /// </summary>
    [StringLength(50)]
    public string? CodigoErro { get; set; }
}
