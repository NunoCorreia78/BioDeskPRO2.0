using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um protocolo terapêutico com frequências e parâmetros de emissão
/// Importado de FrequencyList.xls e usado em terapias bioenergéticas
/// </summary>
public class ProtocoloTerapeutico
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// ID externo (GUID) para idempotência em importações
    /// </summary>
    [Required]
    [StringLength(50)]
    public string ExternalId { get; set; } = string.Empty;

    /// <summary>
    /// Nome do protocolo em Português (traduzido de FrequencyList.xls)
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Categoria (ex: "Digestivo", "Emocional", "Circulatório")
    /// </summary>
    [StringLength(100)]
    public string? Categoria { get; set; }

    /// <summary>
    /// Array de frequências em Hz (JSON serializado)
    /// Exemplo: [528, 396, 285, 174, ...]
    /// </summary>
    [Required]
    public string FrequenciasJson { get; set; } = "[]";

    /// <summary>
    /// Amplitude padrão em Volts (0-20V)
    /// </summary>
    public double AmplitudeV { get; set; } = 5.0;

    /// <summary>
    /// Limite de corrente em mA (0-50mA)
    /// </summary>
    public double LimiteCorrenteMa { get; set; } = 10.0;

    /// <summary>
    /// Forma de onda (Sine, Square, Triangle, Saw)
    /// </summary>
    [StringLength(20)]
    public string FormaOnda { get; set; } = "Sine";

    /// <summary>
    /// Tipo de modulação (None, AM, FM, Burst)
    /// </summary>
    [StringLength(20)]
    public string Modulacao { get; set; } = "None";

    /// <summary>
    /// Duração padrão por frequência em minutos
    /// </summary>
    public int DuracaoMinPorFrequencia { get; set; } = 5;

    /// <summary>
    /// Canal de saída (1, 2, Both)
    /// </summary>
    [StringLength(10)]
    public string Canal { get; set; } = "1";

    /// <summary>
    /// Contraindicações clínicas
    /// </summary>
    [StringLength(500)]
    public string? Contraindicacoes { get; set; }

    /// <summary>
    /// Notas adicionais (inclui termo original Alemão/Inglês)
    /// </summary>
    [StringLength(1000)]
    public string? Notas { get; set; }

    /// <summary>
    /// Data de criação/importação
    /// </summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Data de última atualização
    /// </summary>
    public DateTime AtualizadoEm { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Ativo no catálogo
    /// </summary>
    public bool Ativo { get; set; } = true;

    // Navigation properties
    public ICollection<Terapia> Terapias { get; set; } = new List<Terapia>();

    /// <summary>
    /// Desserializa frequências de JSON para array
    /// </summary>
    public double[] GetFrequencias()
    {
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<double[]>(FrequenciasJson) ?? Array.Empty<double>();
        }
        catch
        {
            return Array.Empty<double>();
        }
    }

    /// <summary>
    /// Serializa array de frequências para JSON
    /// </summary>
    public void SetFrequencias(double[] frequencias)
    {
        FrequenciasJson = System.Text.Json.JsonSerializer.Serialize(frequencias);
    }
}
