using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Linq;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 7) CIRURGIAS 🟡 IMPORTANTE
/// Histórico cirúrgico completo - operações, datas, complicações
/// TXT (cirurgia) · DAT (data) · DD (resultado) · CHK (complicações) · TXTL (observações)
/// </summary>
public class CirurgiasExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Importante;
    public override string NomeExpander => "7) Cirurgias";

    // ESTADO GLOBAL
    private bool _semCirurgias = false;

    // CIRURGIAS
    private List<Cirurgia> _cirurgias = new();

    // OBSERVAÇÕES
    private string _observacoes = string.Empty;

    // PROPRIEDADES
    public bool SemCirurgias
    {
        get => _semCirurgias;
        set
        {
            _semCirurgias = value;
            if (value)
            {
                Cirurgias.Clear();
                OnPropertyChanged(nameof(Cirurgias));
            }
            OnPropertyChanged();
        }
    }

    public List<Cirurgia> Cirurgias
    {
        get => _cirurgias;
        set { _cirurgias = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public bool TemCirurgias => Cirurgias.Count > 0;
    
    public int TotalCirurgias => Cirurgias.Count;

    public List<Cirurgia> CirurgiasRecentes => Cirurgias
        .Where(c => c.Data.HasValue && c.Data.Value >= DateTime.Today.AddYears(-2))
        .OrderByDescending(c => c.Data)
        .ToList();

    public bool TemComplicacoes => Cirurgias.Any(c => c.TemComplicacoes);

    public string ResumoCirurgias
    {
        get
        {
            if (SemCirurgias) return "Sem cirurgias";
            if (!TemCirurgias) return "Não avaliado";
            
            var recentes = CirurgiasRecentes.Count;
            var complicacoes = TemComplicacoes ? " | Complicações" : "";
            return $"{TotalCirurgias} cirurgia(s){(recentes > 0 ? $" | {recentes} recente(s)" : "")}{complicacoes}";
        }
    }

    // VALIDAÇÃO
    public bool IsValid => SemCirurgias || TemCirurgias;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!SemCirurgias && !TemCirurgias)
            errors.Add("É necessário especificar se teve cirurgias ou marcar 'Sem cirurgias'");
        
        foreach (var cirurgia in Cirurgias)
        {
            if (string.IsNullOrWhiteSpace(cirurgia.Nome))
                errors.Add("Nome da cirurgia não pode estar vazio");
        }
        
        return errors;
    }

    // MÉTODOS HELPER
    public void AdicionarCirurgia(string nome)
    {
        if (!string.IsNullOrWhiteSpace(nome))
        {
            var novaCirurgia = new Cirurgia { Nome = nome };
            Cirurgias.Add(novaCirurgia);
            OnPropertyChanged(nameof(Cirurgias));
            OnPropertyChanged(nameof(TemCirurgias));
            OnPropertyChanged(nameof(TotalCirurgias));
            OnPropertyChanged(nameof(ResumoCirurgias));
        }
    }
}

/// <summary>
/// Cirurgia individual
/// </summary>
public class Cirurgia : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _nome = string.Empty;
    private string _tipo = "Eletiva";
    private DateTime? _data;
    private string _hospital = string.Empty;
    private string _cirurgiao = string.Empty;
    private string _anestesia = string.Empty;
    private string _resultado = "Sucesso";
    private bool _temComplicacoes = false;
    private string _complicacoes = string.Empty;
    private string _tempoRecuperacao = string.Empty;
    private string _observacoes = string.Empty;

    public string Nome
    {
        get => _nome;
        set { _nome = value; OnPropertyChanged(); }
    }

    public string Tipo
    {
        get => _tipo;
        set { _tipo = value; OnPropertyChanged(); }
    }

    public DateTime? Data
    {
        get => _data;
        set { _data = value; OnPropertyChanged(); CalcularTempoDecorrido(); }
    }

    public string Hospital
    {
        get => _hospital;
        set { _hospital = value; OnPropertyChanged(); }
    }

    public string Cirurgiao
    {
        get => _cirurgiao;
        set { _cirurgiao = value; OnPropertyChanged(); }
    }

    public string Anestesia
    {
        get => _anestesia;
        set { _anestesia = value; OnPropertyChanged(); }
    }

    public string Resultado
    {
        get => _resultado;
        set { _resultado = value; OnPropertyChanged(); }
    }

    public bool TemComplicacoes
    {
        get => _temComplicacoes;
        set { _temComplicacoes = value; OnPropertyChanged(); }
    }

    public string Complicacoes
    {
        get => _complicacoes;
        set { _complicacoes = value; OnPropertyChanged(); }
    }

    public string TempoRecuperacao
    {
        get => _tempoRecuperacao;
        set { _tempoRecuperacao = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public string TempoDecorrido { get; private set; } = string.Empty;

    private void CalcularTempoDecorrido()
    {
        if (Data.HasValue)
        {
            var tempo = DateTime.Today - Data.Value;
            var anos = tempo.Days / 365;
            var meses = (tempo.Days % 365) / 30;
            
            if (anos > 0)
                TempoDecorrido = $"{anos} ano(s) atrás";
            else if (meses > 0)
                TempoDecorrido = $"{meses} mês(es) atrás";
            else if (tempo.Days > 0)
                TempoDecorrido = $"{tempo.Days} dia(s) atrás";
            else
                TempoDecorrido = "Hoje";
        }
        else
        {
            TempoDecorrido = "Data não especificada";
        }
        OnPropertyChanged(nameof(TempoDecorrido));
    }

    public string CirurgiaCompleta => 
        !string.IsNullOrWhiteSpace(Hospital) ? $"{Nome} ({Hospital})" : Nome;

    // OPÇÕES PRÉ-DEFINIDAS
    public static List<string> CirurgiasComuns => new()
    {
        // ABDOMINAIS
        "Apendicectomia",
        "Colecistectomia (vesícula biliar)",
        "Hérnia inguinal",
        "Hérnia umbilical",
        "Hérnia incisional",
        "Gastrectomia",
        "Colectomia",
        "Cesariana",

        // ORTOPÉDICAS
        "Artroscopia joelho",
        "Prótese anca",
        "Prótese joelho",
        "Meniscectomia",
        "Ligamento cruzado",
        "Síndrome túnel cárpico",
        "Fratura (especificar)",
        
        // CARDIOVASCULARES
        "Bypass coronário",
        "Angioplastia",
        "Válvula cardíaca",
        "Pacemaker",
        "Varizes",

        // GINECOLÓGICAS
        "Histerectomia",
        "Ooforectomia",
        "Cesariana",
        "Curetagem",
        "Laparoscopia ginecológica",

        // UROLÓGICAS
        "Prostatectomia",
        "Nefrectomia",
        "Cistoscopia",
        "Litotrícia",

        // OFTALMOLÓGICAS
        "Catarata",
        "Retina",
        "Glaucoma",
        "LASIK",

        // ORL
        "Amígdalas",
        "Adenoides",
        "Septo nasal",
        "Pólipos nasais",

        // DERMATOLÓGICAS
        "Remoção lesão cutânea",
        "Biópsia cutânea",

        // OUTRAS
        "Tiroidectomia",
        "Mastectomia",
        "Endoscopia",
        "Colonoscopia",
        "Outra (especificar)"
    };

    public static List<string> OpcoesTipo => new()
    {
        "Eletiva",
        "Urgência",
        "Emergência",
        "Ambulatória",
        "Diagnóstica",
        "Terapêutica"
    };

    public static List<string> OpcoesAnestesia => new()
    {
        "Geral",
        "Regional (epidural/raquidiana)",
        "Local",
        "Sedação",
        "Não especificada"
    };

    public static List<string> OpcoesResultado => new()
    {
        "Sucesso",
        "Sucesso parcial",
        "Complicações menores",
        "Complicações maiores",
        "Insucesso",
        "A avaliar"
    };

    public static List<string> ComplicacoesComuns => new()
    {
        "Infeção",
        "Hemorragia",
        "Dor persistente",
        "Cicatrização deficiente",
        "Aderências",
        "Rejeição material",
        "Lesão nervosa",
        "Trombose",
        "Embolia",
        "Reação anestésica",
        "Deiscência sutura",
        "Outra"
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}