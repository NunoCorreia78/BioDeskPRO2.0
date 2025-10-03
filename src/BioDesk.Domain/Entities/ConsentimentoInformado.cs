using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade principal para Consentimentos Informados - Aba 3
/// </summary>
public class ConsentimentoInformado
{
    public int Id { get; set; }
    public int PacienteId { get; set; }
    public DateTime DataCriacao { get; set; }
    public DateTime? DataUltimaAtualizacao { get; set; }

    // === IDENTIFICAÇÃO DO CONSENTIMENTO ===
    [Required]
    [MaxLength(100)]
    public string TipoTratamento { get; set; } = string.Empty;

    [Required]
    [MaxLength(500)]
    public string DescricaoTratamento { get; set; } = string.Empty;

    [MaxLength(1000)]
    public string? PersonalizacaoEspecifica { get; set; }

    // === INFORMAÇÃO DETALHADA ===
    [Required]
    public string NaturezaProcedimento { get; set; } = string.Empty;

    [Required]
    public string BeneficiosEsperados { get; set; } = string.Empty;

    [Required]
    public string RiscosEfeitosSecundarios { get; set; } = string.Empty;

    [Required]
    public string AlternativasDisponiveis { get; set; } = string.Empty;

    [Required]
    public string Contraindicacoes { get; set; } = string.Empty;

    // === ASPETOS PRÁTICOS ===
    public int NumeroSessoesPrevistas { get; set; } = 1;

    [Required]
    [MaxLength(100)]
    public string FrequenciaSessoes { get; set; } = string.Empty;

    public decimal CustoPorSessao { get; set; }

    public decimal CustoTotalEstimado { get; set; }

    [Required]
    public string PoliticaCancelamento { get; set; } = string.Empty;

    // === CONSENTIMENTO FORMAL ===
    public bool CompreendoNatureza { get; set; }
    public bool FuiInformadoRiscos { get; set; }
    public bool TiveOportunidadePerguntas { get; set; }
    public bool ConsintoTratamento { get; set; }

    [MaxLength(1000)]
    public string? QuestoesPreocupacoes { get; set; }

    // === ASSINATURA DIGITAL ===
    public string? AssinaturaDigital { get; set; } // Base64 da imagem da assinatura
    public DateTime? DataAssinatura { get; set; }
    public string? EnderecoIP { get; set; }

    // === ESTADO DO CONSENTIMENTO ===
    [Required]
    public string Estado { get; set; } = "Ativo"; // Ativo, Revogado, Expirado

    public DateTime? DataRevogacao { get; set; }
    public string? MotivoRevogacao { get; set; }

    public DateTime? DataExpiracao { get; set; }

    // Navegação
    public virtual Paciente? Paciente { get; set; }
}

/// <summary>
/// Templates pré-definidos para diferentes tipos de tratamento
/// </summary>
public static class ConsentimentoTemplates
{
    public static readonly Dictionary<string, ConsentimentoTemplate> Templates = new()
    {
        ["Fitoterapia"] = new ConsentimentoTemplate
        {
            TipoTratamento = "Fitoterapia",
            DescricaoTratamento = "Tratamento através de plantas medicinais e extratos naturais para promover o bem-estar e saúde.",
            NaturezaProcedimento = "Utilização de preparações à base de plantas medicinais, incluindo chás, tinturas, extratos e suplementos naturais.",
            BeneficiosEsperados = "• Fortalecimento do sistema imunitário\n• Melhoria do bem-estar geral\n• Redução de sintomas específicos\n• Abordagem natural e holística",
            RiscosEfeitosSecundarios = "• Possíveis reações alérgicas\n• Interações com medicamentos convencionais\n• Efeitos secundários leves (náuseas, dores de cabeça)\n• Variabilidade na resposta individual",
            AlternativasDisponiveis = "• Medicina convencional\n• Homeopatia\n• Acupunctura\n• Outras terapias complementares",
            Contraindicacoes = "• Alergias conhecidas às plantas utilizadas\n• Gravidez ou amamentação (conforme caso)\n• Interações medicamentosas graves\n• Patologias específicas contraindicadas",
            FrequenciaSessoes = "Semanal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos tardios sujeitos a taxa de 50%."
        },
        ["Homeopatia"] = new ConsentimentoTemplate
        {
            TipoTratamento = "Homeopatia",
            DescricaoTratamento = "Sistema terapêutico baseado no princípio da similitude, utilizando substâncias altamente diluídas.",
            NaturezaProcedimento = "Administração de medicamentos homeopáticos personalizados, preparados segundo os princípios da farmacopeia homeopática.",
            BeneficiosEsperados = "• Estimulação da capacidade de autorregulação\n• Tratamento individualizado\n• Abordagem holística\n• Sem efeitos secundários significativos",
            RiscosEfeitosSecundarios = "• Agravação temporária inicial (healing crisis)\n• Possível retardamento de tratamento convencional urgente\n• Resposta individual variável\n• Necessidade de acompanhamento prolongado",
            AlternativasDisponiveis = "• Medicina convencional\n• Fitoterapia\n• Acupunctura\n• Outras medicinas complementares",
            Contraindicacoes = "• Situações de urgência médica\n• Patologias que requerem tratamento convencional imediato\n• Doentes que não compreendem os princípios homeopáticos",
            FrequenciaSessoes = "Quinzenal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos tardios sujeitos a taxa de 50%."
        },
        ["Acupunctura"] = new ConsentimentoTemplate
        {
            TipoTratamento = "Acupunctura",
            DescricaoTratamento = "Técnica terapêutica que utiliza agulhas muito finas inseridas em pontos específicos do corpo.",
            NaturezaProcedimento = "Inserção de agulhas esterilizadas descartáveis em pontos de acupunctura específicos, com possível estimulação manual ou elétrica.",
            BeneficiosEsperados = "• Alívio da dor\n• Redução do stress e ansiedade\n• Melhoria do sono\n• Equilíbrio energético\n• Redução de inflamação",
            RiscosEfeitosSecundarios = "• Dor ligeira no local da inserção\n• Pequenos hematomas\n• Risco mínimo de infeção\n• Tontura ocasional\n• Fadiga pós-tratamento",
            AlternativasDisponiveis = "• Medicina convencional\n• Fisioterapia\n• Massagem terapêutica\n• Outras terapias complementares",
            Contraindicacoes = "• Distúrbios de coagulação\n• Infeções locais na pele\n• Gravidez (certos pontos)\n• Pacientes com medo extremo de agulhas",
            FrequenciaSessoes = "Semanal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos tardios sujeitos a taxa de 50%."
        },
        ["Massagem"] = new ConsentimentoTemplate
        {
            TipoTratamento = "Massagem Terapêutica",
            DescricaoTratamento = "Manipulação manual dos tecidos moles para fins terapêuticos e de bem-estar.",
            NaturezaProcedimento = "Aplicação de técnicas de massagem através de pressão, fricção e movimentos específicos nos tecidos moles.",
            BeneficiosEsperados = "• Relaxamento muscular\n• Melhoria da circulação\n• Redução do stress\n• Alívio de tensões\n• Melhoria da flexibilidade",
            RiscosEfeitosSecundarios = "• Dor muscular temporária\n• Possível agravamento de lesões existentes\n• Reações alérgicas a óleos\n• Desconforto em áreas sensíveis",
            AlternativasDisponiveis = "• Fisioterapia\n• Acupunctura\n• Exercício terapêutico\n• Outras técnicas de relaxamento",
            Contraindicacoes = "• Infeções ou feridas na pele\n• Trombose venosa profunda\n• Fraturas recentes\n• Certas condições cardíacas",
            FrequenciaSessoes = "Semanal ou quinzenal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos tardios sujeitos a taxa de 50%."
        }
    };
}

/// <summary>
/// Template para criação de consentimentos
/// </summary>
public class ConsentimentoTemplate
{
    public string TipoTratamento { get; set; } = string.Empty;
    public string DescricaoTratamento { get; set; } = string.Empty;
    public string NaturezaProcedimento { get; set; } = string.Empty;
    public string BeneficiosEsperados { get; set; } = string.Empty;
    public string RiscosEfeitosSecundarios { get; set; } = string.Empty;
    public string AlternativasDisponiveis { get; set; } = string.Empty;
    public string Contraindicacoes { get; set; } = string.Empty;
    public string FrequenciaSessoes { get; set; } = string.Empty;
    public string PoliticaCancelamento { get; set; } = string.Empty;
}
