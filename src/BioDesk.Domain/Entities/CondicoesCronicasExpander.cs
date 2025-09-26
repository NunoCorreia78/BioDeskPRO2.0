using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Linq;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 5) CONDIÇÕES CRÓNICAS 🔴 CRÍTICO
/// Doenças crónicas, diagnósticos médicos, condições de longo prazo
/// CHIP (condições pré-definidas) · TXT (outras condições) · DD (estado) · DAT (diagnóstico)
/// </summary>
public class CondicoesCronicasExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Critico;
    public override string NomeExpander => "5) Condições Crónicas";

    // ESTADO GLOBAL
    private bool _semCondicoesCronicas = false;

    // CONDIÇÕES PRINCIPAIS
    private List<CondicaoCronica> _condicoes = new();

    // OBSERVAÇÕES
    private string _observacoes = string.Empty;

    // PROPRIEDADES
    public bool SemCondicoesCronicas
    {
        get => _semCondicoesCronicas;
        set
        {
            _semCondicoesCronicas = value;
            if (value)
            {
                Condicoes.Clear();
                OnPropertyChanged(nameof(Condicoes));
            }
            OnPropertyChanged();
        }
    }

    public List<CondicaoCronica> Condicoes
    {
        get => _condicoes;
        set { _condicoes = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public bool TemCondicoes => Condicoes.Count > 0;
    
    public int TotalCondicoes => Condicoes.Count;

    public List<CondicaoCronica> CondicoesAtivas => Condicoes
        .Where(c => c.Estado == "Ativa" || c.Estado == "Controlada")
        .ToList();

    public bool TemCondicoesGraves => Condicoes.Any(c => c.Gravidade == "Grave");

    public string ResumoCondicoes
    {
        get
        {
            if (SemCondicoesCronicas) return "Sem condições crónicas";
            if (!TemCondicoes) return "Não avaliado";
            
            return $"{TotalCondicoes} condição(ões) | {CondicoesAtivas.Count} ativa(s)";
        }
    }

    // CONDIÇÕES PRÉ-DEFINIDAS
    public static List<string> CondicoesDisponiveis => new()
    {
        // CARDIOVASCULARES
        "Hipertensão arterial",
        "Doença cardíaca coronária",
        "Insuficiência cardíaca",
        "Arritmias",
        "Colesterol alto",
        "Triglicéridos altos",

        // METABÓLICAS/ENDÓCRINAS
        "Diabetes tipo 1",
        "Diabetes tipo 2",
        "Pré-diabetes",
        "Resistência à insulina",
        "Síndrome metabólica",
        "Doenças da tiroide",
        "Hipotireoidismo",
        "Hipertireoidismo",
        "Obesidade",

        // RESPIRATÓRIAS
        "Asma",
        "DPOC (Doença Pulmonar Obstrutiva Crónica)",
        "Apneia do sono",
        "Rinite alérgica",
        "Sinusite crónica",

        // DIGESTIVAS
        "Refluxo gastroesofágico",
        "Síndrome do intestino irritável",
        "Doença inflamatória intestinal",
        "Doença celíaca",
        "Úlcera péptica",
        "Doença hepática",

        // NEUROLÓGICAS
        "Enxaquecas",
        "Epilepsia",
        "Esclerose múltipla",
        "Doença de Parkinson",
        "Alzheimer/Demência",
        "Neuropatia",

        // PSIQUIÁTRICAS
        "Depressão",
        "Ansiedade",
        "Distúrbio bipolar",
        "Insónia crónica",
        "Síndrome de pânico",

        // MÚSCULO-ESQUELÉTICAS
        "Artrite reumatoide",
        "Osteoartrose",
        "Fibromialgia",
        "Osteoporose",
        "Lúpus",
        "Artrite psoriática",

        // DERMATOLÓGICAS
        "Psoríase",
        "Eczema/Dermatite atópica",
        "Rosácea",

        // UROLÓGICAS/GINECOLÓGICAS
        "Hiperplasia prostática benigna",
        "Endometriose",
        "Síndrome do ovário poliquístico",
        "Incontinência urinária",

        // OUTRAS
        "Insuficiência renal crónica",
        "Anemia",
        "Osteoporose",
        "Doença autoimune",
        "Cancro (especificar)",
        "Outra condição"
    };

    // VALIDAÇÃO
    public bool IsValid => SemCondicoesCronicas || TemCondicoes;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!SemCondicoesCronicas && !TemCondicoes)
            errors.Add("É necessário especificar se tem condições crónicas ou marcar 'Sem condições crónicas'");
        
        foreach (var condicao in Condicoes)
        {
            if (string.IsNullOrWhiteSpace(condicao.Nome))
                errors.Add("Nome da condição não pode estar vazio");
        }
        
        return errors;
    }

    // MÉTODOS HELPER
    public void AdicionarCondicao(string nome)
    {
        if (!string.IsNullOrWhiteSpace(nome))
        {
            var novaCondicao = new CondicaoCronica { Nome = nome };
            Condicoes.Add(novaCondicao);
            OnPropertyChanged(nameof(Condicoes));
            OnPropertyChanged(nameof(TemCondicoes));
            OnPropertyChanged(nameof(TotalCondicoes));
            OnPropertyChanged(nameof(ResumoCondicoes));
        }
    }
}

/// <summary>
/// Condição crónica individual
/// </summary>
public class CondicaoCronica : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _nome = string.Empty;
    private string _estado = "Ativa";
    private string _gravidade = "Ligeira";
    private DateTime? _dataDignostico;
    private string _medicoResponsavel = string.Empty;
    private string _tratamentoAtual = string.Empty;
    private string _observacoes = string.Empty;
    private bool _requerSeguimento = true;

    public string Nome
    {
        get => _nome;
        set { _nome = value; OnPropertyChanged(); }
    }

    public string Estado
    {
        get => _estado;
        set { _estado = value; OnPropertyChanged(); }
    }

    public string Gravidade
    {
        get => _gravidade;
        set { _gravidade = value; OnPropertyChanged(); }
    }

    public DateTime? DataDiagnostico
    {
        get => _dataDignostico;
        set { _dataDignostico = value; OnPropertyChanged(); CalcularTempoDesdeDignostico(); }
    }

    public string MedicoResponsavel
    {
        get => _medicoResponsavel;
        set { _medicoResponsavel = value; OnPropertyChanged(); }
    }

    public string TratamentoAtual
    {
        get => _tratamentoAtual;
        set { _tratamentoAtual = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    public bool RequerSeguimento
    {
        get => _requerSeguimento;
        set { _requerSeguimento = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public string TempoDesdeDignostico { get; private set; } = string.Empty;

    private void CalcularTempoDesdeDignostico()
    {
        if (DataDiagnostico.HasValue)
        {
            var tempo = DateTime.Today - DataDiagnostico.Value;
            var anos = tempo.Days / 365;
            var meses = (tempo.Days % 365) / 30;
            
            if (anos > 0)
                TempoDesdeDignostico = $"{anos} ano(s)";
            else if (meses > 0)
                TempoDesdeDignostico = $"{meses} mês(es)";
            else
                TempoDesdeDignostico = "Recente";
        }
        else
        {
            TempoDesdeDignostico = "Data não especificada";
        }
        OnPropertyChanged(nameof(TempoDesdeDignostico));
    }

    // OPÇÕES
    public static List<string> OpcoesEstado => new()
    {
        "Ativa",
        "Controlada", 
        "Em remissão",
        "Inativa",
        "Resolvida"
    };

    public static List<string> OpcoesGravidade => new()
    {
        "Ligeira",
        "Moderada",
        "Grave"
    };

    // DEPENDÊNCIAS AUTOMÁTICAS (para exames complementares)
    public List<string> ExamesSugeridos
    {
        get
        {
            var exames = new List<string>();
            
            switch (Nome.ToLower())
            {
                case var n when n.Contains("diabetes"):
                    exames.AddRange(new[] { "HbA1c", "Glicemia em jejum", "Perfil lipídico" });
                    break;
                case var n when n.Contains("hipertensão"):
                    exames.AddRange(new[] { "Tensão arterial", "ECG", "Perfil lipídico" });
                    break;
                case var n when n.Contains("colesterol"):
                    exames.AddRange(new[] { "Perfil lipídico completo" });
                    break;
                case var n when n.Contains("tiroide"):
                    exames.AddRange(new[] { "TSH", "T3", "T4" });
                    break;
                case var n when n.Contains("anemia"):
                    exames.AddRange(new[] { "Hemograma", "Ferritina", "B12", "Ácido fólico" });
                    break;
                case var n when n.Contains("renal"):
                    exames.AddRange(new[] { "Creatinina", "Ureia", "Análise urina" });
                    break;
            }
            
            return exames;
        }
    }

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}