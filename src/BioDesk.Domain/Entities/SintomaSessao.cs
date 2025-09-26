using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa um sintoma trabalhado numa sessão específica
/// Usado para a timeline e para marcar [Trabalhar hoje]
/// </summary>
public class SintomaSessao
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Referência à sessão clínica
    /// </summary>
    [Required]
    public int SessaoClinicaId { get; set; }
    
    [ForeignKey(nameof(SessaoClinicaId))]
    public virtual SessaoClinica SessaoClinica { get; set; } = null!;

    /// <summary>
    /// Nome/descrição do sintoma
    /// </summary>
    [Required]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Sistema corporal afetado (para organização)
    /// </summary>
    [MaxLength(100)]
    public string Sistema { get; set; } = string.Empty;

    /// <summary>
    /// Intensidade do sintoma (0-10)
    /// </summary>
    [Range(0, 10)]
    public int Intensidade { get; set; }

    /// <summary>
    /// Intensidade anterior (para calcular delta)
    /// </summary>
    [Range(0, 10)]
    public int? IntensidadeAnterior { get; set; }

    /// <summary>
    /// Localização do sintoma
    /// </summary>
    [MaxLength(200)]
    public string Localizacao { get; set; } = string.Empty;

    /// <summary>
    /// Caráter do sintoma (dor surda, pontada, etc.)
    /// </summary>
    [MaxLength(200)]
    public string Carater { get; set; } = string.Empty;

    /// <summary>
    /// Frequência do sintoma
    /// </summary>
    [MaxLength(100)]
    public string Frequencia { get; set; } = string.Empty;

    /// <summary>
    /// Fatores desencadeantes
    /// </summary>
    [MaxLength(500)]
    public string Desencadeantes { get; set; } = string.Empty;

    /// <summary>
    /// Fatores de alívio
    /// </summary>
    [MaxLength(500)]
    public string Aliviantes { get; set; } = string.Empty;

    /// <summary>
    /// Estado atual do sintoma
    /// </summary>
    public EstadoSintoma Estado { get; set; } = EstadoSintoma.Ativo;

    /// <summary>
    /// Indica se foi marcado para [Trabalhar hoje]
    /// </summary>
    public bool TrabalharHoje { get; set; } = false;

    /// <summary>
    /// Indica se deve [Atualizar permanente] (ir para painel)
    /// </summary>
    public bool AtualizarPermanente { get; set; } = false;

    /// <summary>
    /// Marcado como [Relevante] para destaque
    /// </summary>
    public bool Relevante { get; set; } = false;

    /// <summary>
    /// Sintoma é [Persistente]
    /// </summary>
    public bool Persistente { get; set; } = false;

    /// <summary>
    /// Nível de risco/prioridade (0-10)
    /// </summary>
    [Range(0, 10)]
    public int NivelRisco { get; set; } = 0;

    /// <summary>
    /// Observações adicionais sobre o sintoma
    /// </summary>
    [MaxLength(1000)]
    public string Observacoes { get; set; } = string.Empty;

    /// <summary>
    /// Data em que o sintoma foi registrado pela primeira vez
    /// </summary>
    public DateTime PrimeiroRegisto { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Última atualização
    /// </summary>
    public DateTime UltimaAtualizacao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Calcula o delta de intensidade em relação à sessão anterior
    /// </summary>
    public int CalcularDelta() => IntensidadeAnterior.HasValue ? 
        Intensidade - IntensidadeAnterior.Value : 0;

    /// <summary>
    /// Verifica se o sintoma deve aparecer na timeline
    /// (TrabalharHoje OU delta ≥ 2 OU mudança de estado)
    /// </summary>
    public bool DeveAparecerNaTimeline() => 
        TrabalharHoje || Math.Abs(CalcularDelta()) >= 2 || Estado == EstadoSintoma.Resolvido;
}

public enum EstadoSintoma
{
    Ativo = 0,
    Melhorando = 1,
    Estavel = 2,
    Piorando = 3,
    Resolvido = 4,
    Arquivado = 5
}