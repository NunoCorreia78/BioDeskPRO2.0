using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Linq;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 8) HISTÓRIA FAMILIAR 🟡 IMPORTANTE
/// Antecedentes familiares relevantes - doenças hereditárias, factores de risco
/// CHIP (doenças) · DD (parentesco) · CHK (vivo/falecido) · NUM (idade) · TXTL (observações)
/// </summary>
public class HistoriaFamiliarExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Importante;
    public override string NomeExpander => "8) História Familiar";

    // ESTADO GLOBAL
    private bool _semHistoriaRelevante = false;

    // ANTECEDENTES FAMILIARES
    private List<AntecedenteFamiliar> _antecedentes = new();

    // OBSERVAÇÕES
    private string _observacoes = string.Empty;

    // PROPRIEDADES
    public bool SemHistoriaRelevante
    {
        get => _semHistoriaRelevante;
        set
        {
            _semHistoriaRelevante = value;
            if (value)
            {
                Antecedentes.Clear();
                OnPropertyChanged(nameof(Antecedentes));
            }
            OnPropertyChanged();
        }
    }

    public List<AntecedenteFamiliar> Antecedentes
    {
        get => _antecedentes;
        set { _antecedentes = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public bool TemAntecedentes => Antecedentes.Count > 0;
    
    public int TotalAntecedentes => Antecedentes.Count;

    public List<AntecedenteFamiliar> AntecedentesCriticos => Antecedentes
        .Where(a => DoencasCriticas.Contains(a.Doenca))
        .ToList();

    public bool TemRiscoGenetico => AntecedentesCriticos.Count > 0;

    public Dictionary<string, int> AntecedentesPorParentesco
    {
        get
        {
            return Antecedentes
                .GroupBy(a => a.Parentesco)
                .ToDictionary(g => g.Key, g => g.Count());
        }
    }

    public string ResumoHistoriaFamiliar
    {
        get
        {
            if (SemHistoriaRelevante) return "Sem história familiar relevante";
            if (!TemAntecedentes) return "Não avaliado";
            
            var risco = TemRiscoGenetico ? " | Risco genético" : "";
            return $"{TotalAntecedentes} antecedente(s){risco}";
        }
    }

    // DOENÇAS COM COMPONENTE GENÉTICO SIGNIFICATIVO
    private static readonly List<string> DoencasCriticas = new()
    {
        "Cancro da mama",
        "Cancro do cólon",
        "Cancro do ovário",
        "Cancro da próstata",
        "Doença cardíaca coronária",
        "Enfarte do miocárdio",
        "Diabetes tipo 1",
        "Diabetes tipo 2",
        "Hipertensão arterial",
        "AVC",
        "Doença de Alzheimer",
        "Doença de Parkinson",
        "Huntington",
        "Esclerose múltipla",
        "Fibrose quística",
        "Hemofilia",
        "Anemia falciforme",
        "Talassemia"
    };

    // VALIDAÇÃO
    public bool IsValid => SemHistoriaRelevante || TemAntecedentes;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!SemHistoriaRelevante && !TemAntecedentes)
            errors.Add("É necessário especificar antecedentes familiares ou marcar 'Sem história relevante'");
        
        foreach (var antecedente in Antecedentes)
        {
            if (string.IsNullOrWhiteSpace(antecedente.Doenca))
                errors.Add("Doença do antecedente não pode estar vazia");
            if (string.IsNullOrWhiteSpace(antecedente.Parentesco))
                errors.Add("Parentesco do antecedente não pode estar vazio");
        }
        
        return errors;
    }

    // MÉTODOS HELPER
    public void AdicionarAntecedente(string doenca, string parentesco)
    {
        if (!string.IsNullOrWhiteSpace(doenca) && !string.IsNullOrWhiteSpace(parentesco))
        {
            var novoAntecedente = new AntecedenteFamiliar 
            { 
                Doenca = doenca, 
                Parentesco = parentesco 
            };
            Antecedentes.Add(novoAntecedente);
            OnPropertyChanged(nameof(Antecedentes));
            OnPropertyChanged(nameof(TemAntecedentes));
            OnPropertyChanged(nameof(ResumoHistoriaFamiliar));
        }
    }

    // ANÁLISE DE RISCO GENÉTICO (simplificada)
    public string AvaliacaoRiscoGenetico
    {
        get
        {
            if (!TemRiscoGenetico) return "Risco genético baixo";
            
            var riscoAlto = AntecedentesCriticos.Count(a => 
                (a.Parentesco == "Pai" || a.Parentesco == "Mãe") ||
                (a.IdadeObito.HasValue && a.IdadeObito < 60));
                
            if (riscoAlto > 0)
                return "⚠️ Risco genético elevado - Considerar rastreio";
            else
                return "⚡ Risco genético moderado";
        }
    }
}

/// <summary>
/// Antecedente familiar individual
/// </summary>
public class AntecedenteFamiliar : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _doenca = string.Empty;
    private string _parentesco = string.Empty;
    private bool _vivo = true;
    private int? _idadeAtual;
    private int? _idadeObito;
    private int? _idadeDiagnostico;
    private string _observacoes = string.Empty;

    public string Doenca
    {
        get => _doenca;
        set { _doenca = value; OnPropertyChanged(); }
    }

    public string Parentesco
    {
        get => _parentesco;
        set { _parentesco = value; OnPropertyChanged(); }
    }

    public bool Vivo
    {
        get => _vivo;
        set { _vivo = value; OnPropertyChanged(); }
    }

    public int? IdadeAtual
    {
        get => _idadeAtual;
        set { _idadeAtual = value; OnPropertyChanged(); }
    }

    public int? IdadeObito
    {
        get => _idadeObito;
        set { _idadeObito = value; OnPropertyChanged(); }
    }

    public int? IdadeDiagnostico
    {
        get => _idadeDiagnostico;
        set { _idadeDiagnostico = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public string StatusVital => Vivo ? "Vivo" : "Falecido";
    
    public string IdadeInfo
    {
        get
        {
            if (Vivo && IdadeAtual.HasValue)
                return $"{IdadeAtual} anos";
            else if (!Vivo && IdadeObito.HasValue)
                return $"✝ {IdadeObito} anos";
            else
                return "Idade não especificada";
        }
    }

    public string DiagnosticoInfo
    {
        get
        {
            if (IdadeDiagnostico.HasValue)
                return $"Diagnóstico aos {IdadeDiagnostico} anos";
            else
                return "Idade do diagnóstico não especificada";
        }
    }

    public string AntecedenteCompleto => 
        $"{Parentesco}: {Doenca} ({StatusVital})";

    // OPÇÕES PRÉ-DEFINIDAS
    public static List<string> OpcoesParentesco => new()
    {
        // PARENTESCO DIRETO (1º grau)
        "Pai",
        "Mãe",
        "Filho",
        "Filha",
        "Irmão",
        "Irmã",

        // PARENTESCO 2º GRAU
        "Avô paterno",
        "Avó paterna",
        "Avô materno",
        "Avó materna",
        "Tio paterno",
        "Tia paterna",
        "Tio materno",
        "Tia materna",
        "Meio-irmão",
        "Meia-irmã",

        // PARENTESCO 3º GRAU
        "Primo",
        "Prima",
        "Bisavô",
        "Bisavó",

        // OUTROS
        "Padrasto",
        "Madrasta",
        "Outro familiar"
    };

    public static List<string> DoencasComuns => new()
    {
        // CARDIOVASCULARES
        "Doença cardíaca coronária",
        "Enfarte do miocárdio",
        "AVC",
        "Hipertensão arterial",
        "Colesterol alto",
        "Morte súbita cardíaca",

        // CANCROS
        "Cancro da mama",
        "Cancro do pulmão",
        "Cancro do cólon",
        "Cancro da próstata",
        "Cancro do ovário",
        "Cancro do estômago",
        "Cancro do fígado",
        "Leucemia",
        "Linfoma",

        // METABÓLICAS
        "Diabetes tipo 1",
        "Diabetes tipo 2",
        "Obesidade",
        "Doenças da tiroide",

        // NEUROLÓGICAS
        "Doença de Alzheimer",
        "Demência",
        "Doença de Parkinson",
        "Epilepsia",
        "Esclerose múltipla",
        "Huntington",

        // PSIQUIÁTRICAS
        "Depressão",
        "Distúrbio bipolar",
        "Esquizofrenia",
        "Suicídio",

        // GENÉTICAS
        "Fibrose quística",
        "Hemofilia",
        "Anemia falciforme",
        "Talassemia",
        "Síndrome de Down",

        // OUTRAS
        "Asma",
        "Artrite reumatoide",
        "Doença inflamatória intestinal",
        "Doença renal crónica",
        "Glaucoma",
        "Osteoporose",
        "Alcoolismo",
        "Dependência de drogas",
        "Outra doença"
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}