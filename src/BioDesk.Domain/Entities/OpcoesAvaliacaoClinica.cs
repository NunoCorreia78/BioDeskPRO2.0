using System.Collections.Generic;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Classes estáticas com as opções predefinidas para chips, dropdowns e seletores
/// Otimizado para rapidez clínica com frases rápidas
/// </summary>
public static class OpcoesMotivoConsulta
{
    public static readonly List<string> Motivos = new()
    {
        "Dor lombar",
        "Cervicalgia", 
        "Cefaleias",
        "Ansiedade",
        "Stress",
        "Fadiga",
        "Refluxo",
        "Dispepsia",
        "Obstipação",
        "Diarreia",
        "Intolerâncias",
        "Alergias",
        "Insónia",
        "Dores articulares",
        "Outro"
    };

    public static readonly List<string> Localizacoes = new()
    {
        "Cervical",
        "Dorsal",
        "Lombar",
        "Sacroilíaca",
        "Ombro",
        "Braço",
        "Antebraço",
        "Mão",
        "Quadril",
        "Coxa",
        "Joelho",
        "Perna",
        "Pé",
        "Cabeça",
        "Pescoço",
        "Tórax",
        "Abdómen",
        "Outra"
    };

    public static readonly List<string> Lados = new() { "Esquerdo", "Direito", "Bilateral" };

    public static readonly List<string> Duracoes = new()
    {
        "< 1 semana",
        "1-4 semanas", 
        "1-3 meses",
        "> 3 meses"
    };

    public static readonly List<string> Evolucoes = new() { "Melhorou", "Piorou", "Estável" };

    public static readonly List<string> Caracteres = new()
    {
        "Pontada",
        "Peso", 
        "Queimação",
        "Latejante",
        "Rigidez",
        "Cólica"
    };

    public static readonly List<string> FatoresAgravantes = new()
    {
        "Esforço",
        "Postura",
        "Alimentação",
        "Stress",
        "Frio",
        "Sono"
    };

    public static readonly List<string> FatoresAlivio = new()
    {
        "Repouso",
        "Calor",
        "Alongamentos",
        "Medicação",
        "Alimentação leve"
    };
}

public static class OpcoesHistoriaClinica
{
    public static readonly List<string> DoencasCronicas = new()
    {
        "HTA",
        "Diabetes",
        "Dislipidemia",
        "Tiroide",
        "Autoimune",
        "Asma",
        "Doença cardíaca",
        "Renal",
        "Hepática",
        "Depressão/Ansiedade",
        "Outro"
    };

    public static readonly List<string> TiposAlergias = new()
    {
        "Medicamentos",
        "Alimentares",
        "Ambientais",
        "Contacto"
    };

    public static readonly List<string> VacinacaoRelevante = new()
    {
        "COVID-19",
        "Gripe sazonal",
        "Hepatite B",
        "Tétano",
        "HPV"
    };

    public static readonly List<string> FrasesRapidas = new()
    {
        "Sem alergias",
        "Sem medicação crónica",
        "Sem suplementação",
        "Vacinação em dia",
        "Sem cirurgias"
    };
}

public static class OpcoesRevisaoSistemas
{
    public static readonly Dictionary<string, List<string>> SistemasSintomas = new()
    {
        ["Cardiovascular"] = new() { "Dor torácica", "Palpitações", "HTA", "Edemas", "Intolerância ao esforço" },
        ["Respiratório"] = new() { "Dispneia", "Tosse", "Asma", "Apneia do sono" },
        ["Digestivo"] = new() { "Refluxo", "Dispepsia", "Obstipação", "Diarreia", "Gases", "Intolerâncias" },
        ["Renal/Urinário"] = new() { "Disúria", "Poliúria", "ITU recorrente", "Litíase" },
        ["Endócrino/Metabólico"] = new() { "Ganho/perda ponderal", "Frio/Calor", "Sede excessiva" },
        ["Músculo-esquelético"] = new() { "Cervicalgia", "Lombalgia", "Artralgias", "Rigidez matinal" },
        ["Neurológico"] = new() { "Cefaleias", "Tonteiras", "Parestesias", "Insónia" },
        ["Pele"] = new() { "Eczema", "Urticária", "Acne", "Alopecia" },
        ["Humor/Sono/Energia"] = new() { "Ansiedade", "Humor deprimido", "Cansaço", "Insónia", "Sonolência" }
    };
}

public static class OpcoesEstiloVida
{
    public static readonly List<string> Alimentacao = new()
    {
        "Omnívoro",
        "Mediterrânica", 
        "Vegetariana",
        "Vegan",
        "Baixo FODMAP",
        "Sem glúten",
        "Sem lactose",
        "Outro"
    };

    public static readonly List<string> Hidratacao = new()
    {
        "< 1L",
        "1-1.5L",
        "1.5-2L", 
        "> 2L"
    };

    public static readonly List<string> Exercicio = new()
    {
        "Caminhada",
        "Força",
        "Cardio",
        "Yoga/Pilates",
        "Alongamentos"
    };

    public static readonly List<string> FrequenciaExercicio = new()
    {
        "Nunca",
        "1-2x/semana",
        "3-4x/semana",
        "5-6x/semana",
        "Diariamente"
    };

    public static readonly List<string> Tabaco = new() { "Nunca", "Ex-fumador", "Fumador" };
    public static readonly List<string> Alcool = new() { "Nunca", "Social", "Frequente" };
    public static readonly List<string> Cafeina = new() { "0", "1", "2", "3+" };

    public static readonly List<string> Sono = new()
    {
        "Latência ↑",
        "Despertares",
        "Não restaurador", 
        "Roncopatia"
    };
}

public static class OpcoesHistoriaFamiliar
{
    public static readonly List<string> Antecedentes = new()
    {
        "HTA",
        "Diabetes",
        "AVC",
        "IAM",
        "Cancro",
        "Autoimune",
        "Tiroide",
        "Depressão/Ansiedade",
        "Demência",
        "Outro"
    };

    public static readonly List<string> Parentesco = new()
    {
        "Pai",
        "Mãe",
        "Avós",
        "Irmãos"
    };
}

/// <summary>
/// Frases rápidas globais para otimizar o preenchimento clínico
/// </summary>
public static class FrasesRapidasGlobais
{
    public static readonly Dictionary<string, Dictionary<string, object>> FrasesRapidas = new()
    {
        ["Sem alergias"] = new()
        {
            ["HistoriaClinica.SemAlergias"] = true,
            ["HistoriaClinica.TiposAlergiasJson"] = "",
            ["HistoriaClinica.EspecificarAlergias"] = ""
        },
        ["Sem medicação crónica"] = new()
        {
            ["HistoriaClinica.SemMedicacao"] = true,
            ["HistoriaClinica.MedicacaoAtualJson"] = ""
        },
        ["Queixa principal controlada"] = new()
        {
            ["MotivoConsulta.Evolucao"] = "Melhorou",
            ["MotivoConsulta.Intensidade"] = 2
        },
        ["Recomenda-se aumentar hidratação"] = new()
        {
            ["EstiloVida.Hidratacao"] = "> 2L"
        },
        ["Sono reparador"] = new()
        {
            ["EstiloVida.SonoJson"] = "[]",
            ["EstiloVida.Stress"] = 3
        }
    };
}