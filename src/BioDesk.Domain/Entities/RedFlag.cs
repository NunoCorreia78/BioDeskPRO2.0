using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa Red Flags (alertas clínicos) identificados numa sessão
/// Sistema de alertas para situações que requerem atenção imediata
/// </summary>
public class RedFlag
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
    /// Tipo de red flag
    /// </summary>
    public TipoRedFlag Tipo { get; set; }

    /// <summary>
    /// Descrição do alerta
    /// </summary>
    [Required]
    [MaxLength(300)]
    public string Descricao { get; set; } = string.Empty;

    /// <summary>
    /// Nível de risco (0-10)
    /// </summary>
    [Range(0, 10)]
    public int NivelRisco { get; set; } = 5;

    /// <summary>
    /// Estado do alerta
    /// </summary>
    public EstadoRedFlag Estado { get; set; } = EstadoRedFlag.Ativo;

    /// <summary>
    /// Ações tomadas em resposta ao red flag
    /// </summary>
    [MaxLength(1000)]
    public string AcoesTomadas { get; set; } = string.Empty;

    /// <summary>
    /// Data de identificação
    /// </summary>
    public DateTime DataIdentificacao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Data de resolução (se aplicável)
    /// </summary>
    public DateTime? DataResolucao { get; set; }

    /// <summary>
    /// Indica se deve [Atualizar permanente] (aparecer no painel)
    /// </summary>
    public bool AtualizarPermanente { get; set; } = true; // Red flags são sempre importantes

    /// <summary>
    /// Observações adicionais
    /// </summary>
    [MaxLength(500)]
    public string Observacoes { get; set; } = string.Empty;

    /// <summary>
    /// Resolve o red flag
    /// </summary>
    public void Resolver(string acoes = "")
    {
        Estado = EstadoRedFlag.Resolvido;
        DataResolucao = DateTime.UtcNow;
        if (!string.IsNullOrWhiteSpace(acoes))
        {
            AcoesTomadas = acoes;
        }
    }
}

public enum TipoRedFlag
{
    PerdaPesoInexplicada = 0,
    FebrePersistente = 1,
    DorNoturnaProgressiva = 2,
    IncontinenciaRetencao = 3,
    DeficeNeurologico = 4,
    DorToracicaEsforco = 5,
    Hematoquezra = 6,
    Hemoptises = 7,
    Sincope = 8,
    AlteracaoMentalAguda = 9,
    DorAbdominalIntensa = 10,
    CefaleiaSubita = 11,
    Outro = 99
}

public enum EstadoRedFlag
{
    Ativo = 0,
    EmInvestigacao = 1,
    Resolvido = 2,
    FalsoPositivo = 3,
    Encaminhado = 4
}