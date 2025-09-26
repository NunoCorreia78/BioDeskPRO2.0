using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa medicação ativa permanente do paciente
/// Aparece no Painel Permanente (Tab 3)
/// </summary>
public class MedicacaoAtual
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Referência ao paciente
    /// </summary>
    [Required]
    public int PacienteId { get; set; }
    
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Nome da medicação (normalizado se possível)
    /// </summary>
    [Required]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;

    /// <summary>
    /// Código da medicação (se disponível)
    /// </summary>
    [MaxLength(50)]
    public string Codigo { get; set; } = string.Empty;

    /// <summary>
    /// Dose
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string Dose { get; set; } = string.Empty;

    /// <summary>
    /// Via de administração
    /// </summary>
    [MaxLength(50)]
    public string Via { get; set; } = string.Empty;

    /// <summary>
    /// Frequência de administração
    /// </summary>
    [Required]
    [MaxLength(100)]
    public string Frequencia { get; set; } = string.Empty;

    /// <summary>
    /// Indicação/motivo
    /// </summary>
    [MaxLength(300)]
    public string Indicacao { get; set; } = string.Empty;

    /// <summary>
    /// Data de início
    /// </summary>
    public DateTime DataInicio { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Data de suspensão (se aplicável)
    /// </summary>
    public DateTime? DataSuspensao { get; set; }

    /// <summary>
    /// Estado da medicação
    /// </summary>
    public EstadoMedicacao Estado { get; set; } = EstadoMedicacao.Ativa;

    /// <summary>
    /// Tipo de medicação
    /// </summary>
    public TipoMedicacao Tipo { get; set; } = TipoMedicacao.Base;

    /// <summary>
    /// Adesão do paciente
    /// </summary>
    public AdesaoMedicacao Adesao { get; set; } = AdesaoMedicacao.Boa;

    /// <summary>
    /// Efeitos adversos observados
    /// </summary>
    [MaxLength(500)]
    public string EfeitosAdversos { get; set; } = string.Empty;

    /// <summary>
    /// Observações adicionais
    /// </summary>
    [MaxLength(1000)]
    public string Observacoes { get; set; } = string.Empty;

    /// <summary>
    /// Data para rever esta medicação
    /// </summary>
    public DateTime? ReverEm { get; set; }

    /// <summary>
    /// Referência à sessão onde foi adicionada/alterada
    /// </summary>
    public int? SessaoOrigemId { get; set; }
    
    [ForeignKey(nameof(SessaoOrigemId))]
    public virtual SessaoClinica? SessaoOrigem { get; set; }

    /// <summary>
    /// Última atualização
    /// </summary>
    public DateTime UltimaAtualizacao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Verifica se a medicação está ativa
    /// </summary>
    public bool EstaAtiva => Estado == EstadoMedicacao.Ativa && !DataSuspensao.HasValue;

    /// <summary>
    /// Gera descrição completa da medicação
    /// </summary>
    public string DescricaoCompleta => $"{Nome} {Dose} {Via} {Frequencia}";
}

public enum EstadoMedicacao
{
    Ativa = 0,
    Suspensa = 1,
    Descontinuada = 2,
    Substituida = 3
}

public enum TipoMedicacao
{
    Base = 0,       // Medicação contínua
    Episodica = 1,  // PRN - quando necessário
    Suplementacao = 2
}

public enum AdesaoMedicacao
{
    Boa = 0,
    Irregular = 1,
    Ma = 2,
    NaoAvaliada = 3
}