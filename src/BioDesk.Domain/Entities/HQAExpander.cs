using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 2) HISTÓRIA DA QUEIXA ATUAL (HQA) 🔴 CRÍTICO
/// Detalhes completos da queixa principal: localização, intensidade, características
/// SL (intensidade 0-10) · CHIP (características) · DD (localização, fatores) · TXTL (evolução)
/// </summary>
public class HQAExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Critico;
    public override string NomeExpander => "2) História da Queixa Atual (HQA)";

    // LOCALIZAÇÃO
    private List<string> _localizacoes = new();
    private string _ladoAfetado = "Bilateral";
    private string _irradiacao = string.Empty;

    // CARACTERÍSTICAS DA DOR
    private int _intensidade = 0;
    private List<string> _caracteristicasDor = new();
    private string _horarioPior = string.Empty;
    private string _horarioMelhor = string.Empty;

    // FATORES MODIFICADORES
    private List<string> _fatoresAgravantes = new();
    private List<string> _fatoresAlivio = new();

    // EVOLUÇÃO
    private string _evolucao = string.Empty;
    private string _impactoVidaDiaria = string.Empty;
    private string _limitacoesFuncionais = string.Empty;

    // TRATAMENTOS ANTERIORES
    private string _tratamentosRealizados = string.Empty;
    private string _medicamentosUsados = string.Empty;
    private string _resultadosTratamentos = string.Empty;

    // PROPRIEDADES
    public List<string> Localizacoes
    {
        get => _localizacoes;
        set { _localizacoes = value; OnPropertyChanged(); }
    }

    public string LadoAfetado
    {
        get => _ladoAfetado;
        set { _ladoAfetado = value; OnPropertyChanged(); }
    }

    public string Irradiacao
    {
        get => _irradiacao;
        set { _irradiacao = value; OnPropertyChanged(); }
    }

    public int Intensidade
    {
        get => _intensidade;
        set { _intensidade = Math.Max(0, Math.Min(10, value)); OnPropertyChanged(); }
    }

    public List<string> CaracteristicasDor
    {
        get => _caracteristicasDor;
        set { _caracteristicasDor = value; OnPropertyChanged(); }
    }

    public string HorarioPior
    {
        get => _horarioPior;
        set { _horarioPior = value; OnPropertyChanged(); }
    }

    public string HorarioMelhor
    {
        get => _horarioMelhor;
        set { _horarioMelhor = value; OnPropertyChanged(); }
    }

    public List<string> FatoresAgravantes
    {
        get => _fatoresAgravantes;
        set { _fatoresAgravantes = value; OnPropertyChanged(); }
    }

    public List<string> FatoresAlivio
    {
        get => _fatoresAlivio;
        set { _fatoresAlivio = value; OnPropertyChanged(); }
    }

    public string Evolucao
    {
        get => _evolucao;
        set { _evolucao = value; OnPropertyChanged(); }
    }

    public string ImpactoVidaDiaria
    {
        get => _impactoVidaDiaria;
        set { _impactoVidaDiaria = value; OnPropertyChanged(); }
    }

    public string LimitacoesFuncionais
    {
        get => _limitacoesFuncionais;
        set { _limitacoesFuncionais = value; OnPropertyChanged(); }
    }

    public string TratamentosRealizados
    {
        get => _tratamentosRealizados;
        set { _tratamentosRealizados = value; OnPropertyChanged(); }
    }

    public string MedicamentosUsados
    {
        get => _medicamentosUsados;
        set { _medicamentosUsados = value; OnPropertyChanged(); }
    }

    public string ResultadosTratamentos
    {
        get => _resultadosTratamentos;
        set { _resultadosTratamentos = value; OnPropertyChanged(); }
    }

    // OPÇÕES PRÉ-DEFINIDAS
    public static List<string> OpcoesLocalizacao => new()
    {
        // CABEÇA E PESCOÇO
        "Cabeça (frontal)",
        "Cabeça (temporal)",
        "Cabeça (occipital)",
        "Pescoço",
        "Cervical alta",
        "Cervical baixa",
        "Trapézio",

        // TRONCO
        "Lombar",
        "Dorsal alta",
        "Dorsal baixa",
        "Sacro",
        "Cóccix",
        "Costelas",

        // MEMBROS SUPERIORES
        "Ombro",
        "Braço",
        "Cotovelo",
        "Antebraço",
        "Punho",
        "Mão",
        "Dedos",

        // MEMBROS INFERIORES
        "Anca",
        "Coxa",
        "Joelho",
        "Perna",
        "Tornozelo",
        "Pé",
        "Dedos do pé",

        // OUTRAS
        "Peito",
        "Abdómen",
        "Região pélvica",
        "Generalizada"
    };

    public static List<string> OpcoesLado => new()
    {
        "Esquerdo",
        "Direito",
        "Bilateral"
    };

    public static List<string> OpcoesCaracteristicasDor => new()
    {
        // QUALIDADE
        "Dor surda",
        "Dor aguda/penetrante",
        "Dor latejante/pulsátil",
        "Dor tipo queimadura",
        "Dor tipo choque elétrico",
        "Dor tipo facada",
        "Dor tipo aperto/pressão",
        "Dor tipo cãibra",

        // PADRÃO
        "Constante",
        "Intermitente",
        "Episódica",
        "Cíclica",

        // OUTROS SINTOMAS
        "Rigidez",
        "Formigueiro",
        "Dormência",
        "Fraqueza",
        "Inchaço",
        "Calor local",
        "Vermelhidão"
    };

    public static List<string> OpcoesHorario => new()
    {
        "Manhã",
        "Meio da manhã",
        "Almoço",
        "Tarde",
        "Final do dia",
        "Noite",
        "Madrugada",
        "Variável",
        "Sem padrão específico"
    };

    public static List<string> OpcoesFatoresAgravantes => new()
    {
        // ATIVIDADE
        "Movimento",
        "Esforço físico",
        "Exercício",
        "Levantar peso",
        "Caminhar",
        "Estar de pé",
        "Estar sentado",
        "Deitar",
        "Dobrar",
        "Torcer",
        "Tossir/espirrar",

        // AMBIENTAIS
        "Frio",
        "Calor",
        "Humidade",
        "Mudanças climáticas",
        "Stress",
        "Falta de sono",
        "Cansaço",

        // ALIMENTARES
        "Certos alimentos",
        "Álcool",
        "Cafeína",
        "Jejum",

        // OUTROS
        "Menstruação",
        "Posição específica",
        "Barulho",
        "Luz intensa"
    };

    public static List<string> OpcoesFatoresAlivio => new()
    {
        "Repouso",
        "Movimento suave",
        "Calor local",
        "Frio local",
        "Massagem",
        "Alongamentos",
        "Medicação",
        "Posição específica",
        "Dormir",
        "Relaxamento",
        "Exercício leve",
        "Banho quente",
        "Distração",
        "Nada melhora"
    };

    // PROPRIEDADES CALCULADAS
    public string IntensidadeTexto => $"{Intensidade}/10";
    
    public string LocalizacaoResumida => Localizacoes.Count > 0 
        ? string.Join(", ", Localizacoes) + (LadoAfetado != "Bilateral" ? $" ({LadoAfetado})" : "")
        : "Não especificada";

    public bool TemInformacaoBasica => Localizacoes.Count > 0 || Intensidade > 0;

    // VALIDAÇÃO
    public bool IsValid => TemInformacaoBasica;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!TemInformacaoBasica)
            errors.Add("É necessário especificar pelo menos a localização ou intensidade da queixa");
        
        return errors;
    }

    // MÉTODOS HELPER
    public void AdicionarLocalizacao(string localizacao)
    {
        if (!string.IsNullOrWhiteSpace(localizacao) && !Localizacoes.Contains(localizacao))
        {
            Localizacoes.Add(localizacao);
            OnPropertyChanged(nameof(Localizacoes));
            OnPropertyChanged(nameof(LocalizacaoResumida));
        }
    }

    public void AdicionarCaracteristica(string caracteristica)
    {
        if (!string.IsNullOrWhiteSpace(caracteristica) && !CaracteristicasDor.Contains(caracteristica))
        {
            CaracteristicasDor.Add(caracteristica);
            OnPropertyChanged(nameof(CaracteristicasDor));
        }
    }

    public void AdicionarFatorAgravante(string fator)
    {
        if (!string.IsNullOrWhiteSpace(fator) && !FatoresAgravantes.Contains(fator))
        {
            FatoresAgravantes.Add(fator);
            OnPropertyChanged(nameof(FatoresAgravantes));
        }
    }

    public void AdicionarFatorAlivio(string fator)
    {
        if (!string.IsNullOrWhiteSpace(fator) && !FatoresAlivio.Contains(fator))
        {
            FatoresAlivio.Add(fator);
            OnPropertyChanged(nameof(FatoresAlivio));
        }
    }
}