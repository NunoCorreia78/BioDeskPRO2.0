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
            DescricaoTratamento = "Tratamento abrangente através de plantas medicinais e extratos naturais de alta qualidade para promover o bem-estar e restaurar saúde integral.",
            NaturezaProcedimento = "Utilização profissional de preparações à base de plantas medicinais de qualidade clínica, incluindo chás, tinturas concentradas, extratos padronizados e suplementos naturais específicos. Em situações de emergência médica ou patologias agudas graves, o paciente deve procurar atendimento médico convencional imediatamente.",
            BeneficiosEsperados = "• Fortalecimento eficaz do sistema imunitário\n• Melhoria significativa do bem-estar geral\n• Redução de sintomas crónicos persistentes\n• Abordagem natural e holística comprovada\n• Harmonização de funções biológicas\n• Restauração de energia e vitalidade\n• Prevenção de doenças crónicas",
            RiscosEfeitosSecundarios = "• Possíveis reações alérgicas a plantas (raras, quando há predisposição)\n• Interações com medicamentos convencionais (informar SEMPRE medicação completa)\n• Efeitos secundários leves e transientes (náuseas, dores de cabeça)\n• Variabilidade na resposta individual conforme constituição\n• Possível desintoxicação inicial (resposta terapêutica positiva)\n• Tempo de resposta gradual (3-12 semanas)",
            AlternativasDisponiveis = "• Medicina convencional farmacológica\n• Homeopatia\n• Acupunctura\n• Osteopatia e técnicas manuais\n• Outras terapias complementares integradas",
            Contraindicacoes = "• Alergias conhecidas às plantas utilizadas\n• Gravidez e amamentação (alguns produtos específicos)\n• Interações medicamentosas graves documentadas\n• Patologias graves em fase aguda (avaliar caso a caso)\n• Pacientes com dificuldade em adherência terapêutica",
            FrequenciaSessoes = "Semanal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos com menos de 24h sujeitos a taxa de 50%."
        },
        ["Homeopatia"] = new ConsentimentoTemplate
        {
            TipoTratamento = "Homeopatia",
            DescricaoTratamento = "Sistema terapêutico complementar bem estabelecido baseado no princípio da similitude, utilizando substâncias naturais altamente diluídas para estimular a capacidade inata de cura do organismo.",
            NaturezaProcedimento = "Administração profissional de medicamentos homeopáticos personalizados, preparados de acordo com os princípios rigorosos da farmacopeia homeopática, selecionados conforme as características individuais. Em situações de emergência médica, o paciente deve procurar atendimento médico convencional imediatamente.",
            BeneficiosEsperados = "• Estimulação eficaz da capacidade natural de autorregulação\n• Tratamento altamente individualizado e preciso\n• Abordagem holística profunda\n• Ausência de efeitos secundários significativos\n• Harmonização do sistema imunitário\n• Melhoria de sintomas funcionais\n• Recuperação de equilíbrio energético",
            RiscosEfeitosSecundarios = "• Possível agravação temporária inicial (healing crisis) - resposta terapêutica esperada\n• Pequeno risco de retardamento de tratamento convencional urgente (se não orientado)\n• Resposta individual altamente variável\n• Necessidade de acompanhamento prolongado e consistente\n• Possível libertação de emoções durante processo\n• Sensações transitórias de desintoxicação",
            AlternativasDisponiveis = "• Medicina convencional farmacológica\n• Fitoterapia\n• Acupunctura\n• Osteopatia e técnicas manuais\n• Outras medicinas complementares",
            Contraindicacoes = "• Situações de emergência médica aguda\n• Patologias que requerem tratamento convencional imediato (cirurgias, medicações críticas)\n• Pacientes que não conseguem compreender ou aceitar princípios homeopáticos\n• Incapacidade de manutenção de acompanhamento regular",
            FrequenciaSessoes = "Quinzenal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos com menos de 24h sujeitos a taxa de 50%."
        },
        ["Acupunctura"] = new ConsentimentoTemplate
        {
            TipoTratamento = "Acupunctura",
            DescricaoTratamento = "Técnica terapêutica milenar muitobem documentada que utiliza agulhas muito finas e estéreis inseridas em pontos específicos do corpo para equilibrar energia vital.",
            NaturezaProcedimento = "Inserção cuidadosa de agulhas esterilizadas descartáveis de calibre fino em pontos de acupunctura específicos, com possível estimulação manual ou elétrica complementar. Em situações de urgência médica, o paciente deve procurar atendimento médico imediatamente.",
            BeneficiosEsperados = "• Alívio eficaz e duradouro da dor\n• Redução significativa de stress e ansiedade\n• Melhoria substancial da qualidade do sono\n• Equilíbrio e regulação de funções orgânicas\n• Redução de inflamação e edema\n• Fortalecimento do sistema imunitário\n• Melhoria geral de energia e bem-estar",
            RiscosEfeitosSecundarios = "• Dor ligeira ou muito leve na inserção das agulhas (normal)\n• Pequenos hematomas nos pontos (raros e resolvem naturalmente)\n• Risco mínimo de infeção (agulhas são estéreis descartáveis)\n• Muito raro: pneumotórax em punção torácica (técnico experiente evita)\n• Possível sonolência pós-tratamento (sinal de resposta positiva)\n• Possível relaxamento profundo ou reações emocionais (seguro)",
            AlternativasDisponiveis = "• Medicina convencional farmacológica\n• Fisioterapia\n• Massagem terapêutica\n• Osteopatia\n• Outras terapias complementares",
            Contraindicacoes = "• Distúrbios graves de coagulação\n• Infeções locais ativas na pele\n• Gravidez (alguns pontos evitados, outros seguros)\n• Pacientes com fobia extrema de agulhas\n• Uso de anticoagulantes agressivos (consultar médico)",
            FrequenciaSessoes = "Semanal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos com menos de 24h sujeitos a taxa de 50%."
        },
        ["Massagem"] = new ConsentimentoTemplate
        {
            TipoTratamento = "Massagem Terapêutica",
            DescricaoTratamento = "Manipulação profissional e terapêutica dos tecidos moles para fins terapêuticos eficazes, bem-estar integral e recuperação funcional.",
            NaturezaProcedimento = "Aplicação profissional de técnicas de massagem através de pressão controlada, fricção específica e movimentos direcionados em tecidos moles corporais. Em caso de lesão aguda, suspeita de fratura ou emergência médica, o paciente deve procurar avaliação médica.",
            BeneficiosEsperados = "• Relaxamento muscular profundo e duradouro\n• Melhoria significativa da circulação sanguínea e linfática\n• Redução markada do stress e tensão\n• Alívio eficaz de dores musculares\n• Melhoria da flexibilidade e amplitude de movimento\n• Melhoria significativa da qualidade do sono\n• Aumento geral de bem-estar e vitalidade",
            RiscosEfeitosSecundarios = "• Dor muscular leve durante ou após a massagem (resposta terapêutica normal)\n• Possível agravamento temporário de lesões pré-existentes (raro)\n• Reações alérgicas a óleos ou cremes (raras, informar sensibilidade)\n• Desconforto em áreas muito sensíveis (comunicar ao terapeuta)\n• Possível fadiga ligeira pós-sessão (sinal de libertação de tensão)",
            AlternativasDisponiveis = "• Fisioterapia convencional\n• Acupunctura\n• Exercício terapêutico\n• Osteopatia e técnicas manuais\n• Outras técnicas de relaxamento",
            Contraindicacoes = "• Infeções ou feridas abertas na pele\n• Trombose venosa profunda diagnosticada\n• Fraturas recentes (menos de 6 semanas)\n• Certas condições cardíacas graves\n• Cirurgias recentes (menos de 4 semanas)",
            FrequenciaSessoes = "Semanal ou quinzenal",
            PoliticaCancelamento = "Cancelamento com 24h de antecedência. Cancelamentos com menos de 24h sujeitos a taxa de 50%."
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
