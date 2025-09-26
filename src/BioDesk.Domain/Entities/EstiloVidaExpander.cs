using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 9) ESTILO DE VIDA 🟡 IMPORTANTE
/// Hábitos de vida: exercício, alimentação, sono, stress, vícios
/// SL (stress 0-10) · CHIP (exercícios) · DD (frequência) · NUM (horas sono) · CHK (vícios)
/// </summary>
public class EstiloVidaExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Importante;
    public override string NomeExpander => "9) Estilo de Vida";

    // EXERCÍCIO FÍSICO
    private List<string> _tiposExercicio = new();
    private string _frequenciaExercicio = "Nunca";
    private int _duracaoExercicio = 0; // minutos
    private string _intensidadeExercicio = "Ligeira";

    // ALIMENTAÇÃO
    private string _padraoAlimentar = "Omnívoro";
    private List<string> _restricoesAlimentares = new();
    private int _refeicoesDay = 3;
    private string _hidratacao = "1-2 litros";
    private string _suplementacao = string.Empty;

    // SONO
    private int _horasSono = 7;
    private string _qualidadeSono = "Boa";
    private List<string> _problemasSono = new();
    private string _horarioSono = "22:00-07:00";

    // STRESS
    private int _nivelStress = 5; // 0-10
    private List<string> _fontesStress = new();
    private List<string> _gestaoStress = new();

    // VÍCIOS E HÁBITOS
    private string _tabaco = "Nunca fumei";
    private string _alcool = "Nunca bebo";
    private string _cafeina = "1-2 cafés/dia";
    private List<string> _outrasSubstancias = new();

    // TRABALHO E AMBIENTE
    private string _tipoTrabalho = "Escritório";
    private int _horasTrabalho = 8;
    private string _exposicaoRiscos = string.Empty;

    // VIDA SOCIAL
    private string _relacionamentos = "Bom";
    private string _apoioSocial = "Adequado";
    private List<string> _hobbies = new();

    // PROPRIEDADES - EXERCÍCIO
    public List<string> TiposExercicio
    {
        get => _tiposExercicio;
        set { _tiposExercicio = value; OnPropertyChanged(); }
    }

    public string FrequenciaExercicio
    {
        get => _frequenciaExercicio;
        set { _frequenciaExercicio = value; OnPropertyChanged(); }
    }

    public int DuracaoExercicio
    {
        get => _duracaoExercicio;
        set { _duracaoExercicio = Math.Max(0, value); OnPropertyChanged(); }
    }

    public string IntensidadeExercicio
    {
        get => _intensidadeExercicio;
        set { _intensidadeExercicio = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - ALIMENTAÇÃO
    public string PadraoAlimentar
    {
        get => _padraoAlimentar;
        set { _padraoAlimentar = value; OnPropertyChanged(); }
    }

    public List<string> RestricoesAlimentares
    {
        get => _restricoesAlimentares;
        set { _restricoesAlimentares = value; OnPropertyChanged(); }
    }

    public int RefeicoesDay
    {
        get => _refeicoesDay;
        set { _refeicoesDay = Math.Max(1, Math.Min(8, value)); OnPropertyChanged(); }
    }

    public string Hidratacao
    {
        get => _hidratacao;
        set { _hidratacao = value; OnPropertyChanged(); }
    }

    public string Suplementacao
    {
        get => _suplementacao;
        set { _suplementacao = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - SONO
    public int HorasSono
    {
        get => _horasSono;
        set { _horasSono = Math.Max(1, Math.Min(24, value)); OnPropertyChanged(); }
    }

    public string QualidadeSono
    {
        get => _qualidadeSono;
        set { _qualidadeSono = value; OnPropertyChanged(); }
    }

    public List<string> ProblemasSono
    {
        get => _problemasSono;
        set { _problemasSono = value; OnPropertyChanged(); }
    }

    public string HorarioSono
    {
        get => _horarioSono;
        set { _horarioSono = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - STRESS
    public int NivelStress
    {
        get => _nivelStress;
        set { _nivelStress = Math.Max(0, Math.Min(10, value)); OnPropertyChanged(); }
    }

    public List<string> FontesStress
    {
        get => _fontesStress;
        set { _fontesStress = value; OnPropertyChanged(); }
    }

    public List<string> GestaoStress
    {
        get => _gestaoStress;
        set { _gestaoStress = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - VÍCIOS
    public string Tabaco
    {
        get => _tabaco;
        set { _tabaco = value; OnPropertyChanged(); }
    }

    public string Alcool
    {
        get => _alcool;
        set { _alcool = value; OnPropertyChanged(); }
    }

    public string Cafeina
    {
        get => _cafeina;
        set { _cafeina = value; OnPropertyChanged(); }
    }

    public List<string> OutrasSubstancias
    {
        get => _outrasSubstancias;
        set { _outrasSubstancias = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - TRABALHO
    public string TipoTrabalho
    {
        get => _tipoTrabalho;
        set { _tipoTrabalho = value; OnPropertyChanged(); }
    }

    public int HorasTrabalho
    {
        get => _horasTrabalho;
        set { _horasTrabalho = Math.Max(0, Math.Min(24, value)); OnPropertyChanged(); }
    }

    public string ExposicaoRiscos
    {
        get => _exposicaoRiscos;
        set { _exposicaoRiscos = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - VIDA SOCIAL
    public string Relacionamentos
    {
        get => _relacionamentos;
        set { _relacionamentos = value; OnPropertyChanged(); }
    }

    public string ApoioSocial
    {
        get => _apoioSocial;
        set { _apoioSocial = value; OnPropertyChanged(); }
    }

    public List<string> Hobbies
    {
        get => _hobbies;
        set { _hobbies = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public string ResumoExercicio => FrequenciaExercicio == "Nunca" 
        ? "Sedentário" 
        : $"{FrequenciaExercicio} | {DuracaoExercicio}min | {IntensidadeExercicio}";

    public string ResumoSono => $"{HorasSono}h | {QualidadeSono}";

    public string ResumoStress => $"Nível {NivelStress}/10";

    public bool TemFactoresRisco => 
        Tabaco.Contains("Fumador") || 
        Alcool.Contains("Diário") || 
        NivelStress >= 8 || 
        HorasSono < 6;

    public string ResumoEstiloVida
    {
        get
        {
            var componentes = new List<string>();
            
            // Exercício
            if (FrequenciaExercicio != "Nunca")
                componentes.Add($"Exercício: {FrequenciaExercicio}");
            
            // Sono
            componentes.Add($"Sono: {HorasSono}h");
            
            // Stress
            if (NivelStress >= 7)
                componentes.Add($"Stress: {NivelStress}/10");
            
            // Vícios
            if (Tabaco.Contains("Fumador"))
                componentes.Add("Tabaco");
            if (Alcool.Contains("Diário") || Alcool.Contains("Excessivo"))
                componentes.Add("Álcool");
                
            return componentes.Count > 0 ? string.Join(" | ", componentes) : "Não avaliado";
        }
    }

    // OPÇÕES PRÉ-DEFINIDAS
    public static List<string> OpcoesTiposExercicio => new()
    {
        // CARDIO
        "Caminhada",
        "Corrida/Jogging",
        "Ciclismo",
        "Natação",
        "Dança",
        "Aeróbica",
        "Spinning",

        // FORÇA
        "Musculação",
        "Pilates",
        "Yoga",
        "Crossfit",
        "Calistenia",

        // DESPORTOS
        "Futebol",
        "Ténis",
        "Padel",
        "Basquetebol",
        "Volleyball",
        "Artes marciais",

        // OUTROS
        "Jardinagem",
        "Tarefas domésticas",
        "Subir escadas",
        "Outro"
    };

    public static List<string> OpcoesFrequenciaExercicio => new()
    {
        "Nunca",
        "Raramente",
        "1-2 vezes/semana",
        "3-4 vezes/semana",
        "5-6 vezes/semana",
        "Diariamente"
    };

    public static List<string> OpcoesIntensidadeExercicio => new()
    {
        "Ligeira",
        "Moderada", 
        "Intensa",
        "Muito intensa"
    };

    public static List<string> OpcoesPadraoAlimentar => new()
    {
        "Omnívoro",
        "Vegetariano",
        "Vegano",
        "Pescetariano",
        "Mediterrânico",
        "Low-carb",
        "Keto",
        "Paleo",
        "Outro"
    };

    public static List<string> OpcoesRestricoes => new()
    {
        "Sem restrições",
        "Glúten",
        "Lactose",
        "Açúcar",
        "Sal",
        "Fritos",
        "Processados",
        "Carne vermelha",
        "Álcool",
        "Cafeína",
        "Outra restrição"
    };

    public static List<string> OpcoesHidratacao => new()
    {
        "Menos de 1 litro",
        "1-2 litros",
        "2-3 litros",
        "Mais de 3 litros"
    };

    public static List<string> OpcoesQualidadeSono => new()
    {
        "Excelente",
        "Boa",
        "Razoável",
        "Má",
        "Muito má"
    };

    public static List<string> OpcoesProblemasSono => new()
    {
        "Nenhum",
        "Dificuldade adormecer",
        "Acordar durante a noite",
        "Acordar muito cedo",
        "Pesadelos",
        "Ressonar",
        "Apneia do sono",
        "Pernas inquietas",
        "Insónia"
    };

    public static List<string> OpcoesFontesStress => new()
    {
        "Trabalho",
        "Família",
        "Finanças",
        "Saúde",
        "Relacionamentos",
        "Estudos",
        "Trânsito",
        "Habitação",
        "Futuro",
        "Solidão",
        "Tecnologia",
        "Notícias",
        "Outro"
    };

    public static List<string> OpcoesGestaoStress => new()
    {
        "Exercício físico",
        "Meditação",
        "Respiração profunda",
        "Yoga",
        "Música",
        "Leitura",
        "Passear",
        "Conversar com amigos",
        "Hobbies",
        "Terapia",
        "Não faço nada",
        "Outro método"
    };

    public static List<string> OpcoesTabaco => new()
    {
        "Nunca fumei",
        "Ex-fumador",
        "Fumador ocasional",
        "Fumador moderado (1-10 cigarros/dia)",
        "Fumador pesado (>10 cigarros/dia)",
        "Cachimbo/charuto",
        "Cigarros eletrônicos"
    };

    public static List<string> OpcoesAlcool => new()
    {
        "Nunca bebo",
        "Ocasionalmente",
        "Fins de semana",
        "2-3 vezes/semana",
        "Diário moderado",
        "Diário excessivo"
    };

    public static List<string> OpcoesCafeina => new()
    {
        "Não bebo cafeína",
        "1 café/dia",
        "2-3 cafés/dia",
        "4-5 cafés/dia",
        ">5 cafés/dia",
        "Chá principalmente",
        "Bebidas energéticas"
    };

    public static List<string> OpcoesTipoTrabalho => new()
    {
        "Escritório",
        "Manual",
        "Misto",
        "Doméstico",
        "Estudante",
        "Reformado",
        "Desempregado",
        "Outro"
    };

    public static List<string> OpcoesRelacionamentos => new()
    {
        "Excelente",
        "Bom",
        "Razoável",
        "Difícil",
        "Isolado"
    };

    public static List<string> OpcoesApoioSocial => new()
    {
        "Muito bom",
        "Adequado",
        "Limitado",
        "Inexistente"
    };

    // VALIDAÇÃO
    public bool IsValid => true; // Sempre válido

    public List<string> GetValidationErrors()
    {
        return new List<string>(); // Sem validações obrigatórias
    }

    // ANÁLISE DE RISCO (simplificada)
    public string AvaliacaoRisco
    {
        get
        {
            var riscos = new List<string>();
            
            if (Tabaco.Contains("Fumador"))
                riscos.Add("🚬 Tabaco");
            
            if (Alcool.Contains("Diário") || Alcool.Contains("excessivo"))
                riscos.Add("🍷 Álcool");
            
            if (FrequenciaExercicio == "Nunca")
                riscos.Add("🏃 Sedentarismo");
            
            if (NivelStress >= 8)
                riscos.Add("😰 Stress elevado");
            
            if (HorasSono < 6)
                riscos.Add("😴 Sono insuficiente");
            
            return riscos.Count > 0 
                ? $"⚠️ Fatores de risco: {string.Join(", ", riscos)}"
                : "✅ Estilo de vida saudável";
        }
    }
}