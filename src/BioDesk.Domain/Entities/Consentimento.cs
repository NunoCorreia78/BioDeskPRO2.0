using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade para consentimentos informados
/// Aba 3: Consentimentos - Autorização para tratamentos
/// </summary>
public class Consentimento
{
    public int Id { get; set; }

    [Required]
    public int PacienteId { get; set; }

    // === TIPO DE TRATAMENTO ===
    /// <summary>
    /// Tipo: "Fitoterapia"|"Homeopatia"|"Acupunctura"|"Massagem"|"Outros"
    /// </summary>
    [Required]
    [StringLength(50)]
    public string TipoTratamento { get; set; } = string.Empty;

    /// <summary>
    /// Descrição detalhada do tratamento
    /// </summary>
    [Required]
    public string DescricaoTratamento { get; set; } = string.Empty;

    /// <summary>
    /// Personalização específica para este paciente
    /// </summary>
    public string? PersonalizacaoTratamento { get; set; }

    // === INFORMAÇÃO DETALHADA ===
    /// <summary>
    /// Natureza do procedimento
    /// </summary>
    public string? NaturezaProcedimento { get; set; }

    /// <summary>
    /// Benefícios esperados (JSON array)
    /// </summary>
    public string? BeneficiosEsperados { get; set; }

    /// <summary>
    /// Riscos e efeitos secundários (JSON array)
    /// </summary>
    public string? RiscosEfeitosSecundarios { get; set; }

    /// <summary>
    /// Alternativas disponíveis
    /// </summary>
    public string? AlternativasDisponiveis { get; set; }

    /// <summary>
    /// Contraindicações conhecidas
    /// </summary>
    public string? Contraindicacoes { get; set; }

    // === ASPETOS PRÁTICOS ===
    /// <summary>
    /// Número de sessões previstas
    /// </summary>
    public int? DuracaoEstimadaSessoes { get; set; }

    /// <summary>
    /// Frequência das sessões (ex: "Semanal", "Quinzenal")
    /// </summary>
    [StringLength(50)]
    public string? FrequenciaSessoes { get; set; }

    /// <summary>
    /// Custo por sessão individual
    /// </summary>
    [Column(TypeName = "decimal(10,2)")]
    public decimal? CustoPorSessao { get; set; }

    /// <summary>
    /// Custo total estimado do tratamento
    /// </summary>
    [Column(TypeName = "decimal(10,2)")]
    public decimal? CustoTotalEstimado { get; set; }

    /// <summary>
    /// Política de cancelamento
    /// </summary>
    public string? PoliticaCancelamento { get; set; }

    // === CONSENTIMENTO FORMAL ===
    /// <summary>
    /// Compreende a natureza do tratamento
    /// </summary>
    public bool CompreendeNatureza { get; set; }

    /// <summary>
    /// Foi informado dos riscos
    /// </summary>
    public bool InformadoRiscos { get; set; }

    /// <summary>
    /// Teve oportunidade de fazer perguntas
    /// </summary>
    public bool OportunidadePerguntas { get; set; }

    /// <summary>
    /// Consente o tratamento proposto
    /// </summary>
    public bool ConsenteTratamento { get; set; }

    /// <summary>
    /// Questões ou preocupações adicionais
    /// </summary>
    public string? QuestoesPreocupacoes { get; set; }

    // === ASSINATURA DIGITAL ===
    /// <summary>
    /// Dados da assinatura digital (base64 ou caminho do ficheiro)
    /// </summary>
    public string? AssinaturaDigital { get; set; }

    /// <summary>
    /// Data e hora da assinatura
    /// </summary>
    public DateTime? DataHoraAssinatura { get; set; }

    /// <summary>
    /// Endereço IP da assinatura (para auditoria)
    /// </summary>
    [StringLength(45)] // IPv6 máximo
    public string? EnderecoIPAssinatura { get; set; }

    // === ESTADO DO CONSENTIMENTO ===
    /// <summary>
    /// Estado: "Ativo"|"Revogado"|"Expirado"
    /// </summary>
    [Required]
    [StringLength(20)]
    public string Estado { get; set; } = "Ativo";

    /// <summary>
    /// Data de expiração do consentimento (se aplicável)
    /// </summary>
    public DateTime? DataExpiracao { get; set; }

    /// <summary>
    /// Motivo de revogação (se aplicável)
    /// </summary>
    public string? MotivoRevogacao { get; set; }

    // === METADADOS ===
    public DateTime DataCriacao { get; set; } = DateTime.UtcNow;
    public DateTime? DataAtualizacao { get; set; }

    // === NAVEGAÇÃO ===
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Verifica se o consentimento está válido (ativo e não expirado)
    /// </summary>
    public bool EstaValido =>
        Estado == "Ativo" &&
        (DataExpiracao == null || DataExpiracao > DateTime.UtcNow);
}
