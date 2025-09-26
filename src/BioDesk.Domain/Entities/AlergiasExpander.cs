using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Linq;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 4) ALERGIAS 🔴 CRÍTICO
/// Alergias medicamentosas, alimentares, ambientais - INFORMAÇÃO CRÍTICA PARA PRESCRIÇÃO
/// CHIP (tipos alergias) · TXT (especificar) · DD (gravidade) · TXTL (reações)
/// </summary>
public class AlergiasExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Critico;
    public override string NomeExpander => "4) Alergias";

    // ESTADO GLOBAL
    private bool _semAlergias = false;
    
    // ALERGIAS MEDICAMENTOSAS (CRÍTICO!)
    private List<AlergiaMedicamentosa> _alergiasMedicamentosas = new();
    
    // ALERGIAS ALIMENTARES
    private List<AlergiaAlimentar> _alergiasAlimentares = new();
    
    // ALERGIAS AMBIENTAIS
    private List<AlergiaAmbiental> _alergiasAmbientais = new();
    
    // OUTRAS ALERGIAS
    private List<OutraAlergia> _outrasAlergias = new();

    // OBSERVAÇÕES GERAIS
    private string _observacoes = string.Empty;

    // PROPRIEDADES
    public bool SemAlergias
    {
        get => _semAlergias;
        set
        {
            _semAlergias = value;
            if (value)
            {
                LimparTodasAlergias();
            }
            OnPropertyChanged();
        }
    }

    public List<AlergiaMedicamentosa> AlergiasMedicamentosas
    {
        get => _alergiasMedicamentosas;
        set { _alergiasMedicamentosas = value; OnPropertyChanged(); }
    }

    public List<AlergiaAlimentar> AlergiasAlimentares
    {
        get => _alergiasAlimentares;
        set { _alergiasAlimentares = value; OnPropertyChanged(); }
    }

    public List<AlergiaAmbiental> AlergiasAmbientais
    {
        get => _alergiasAmbientais;
        set { _alergiasAmbientais = value; OnPropertyChanged(); }
    }

    public List<OutraAlergia> OutrasAlergias
    {
        get => _outrasAlergias;
        set { _outrasAlergias = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public bool TemAlergias => AlergiasMedicamentosas.Count > 0 || 
                              AlergiasAlimentares.Count > 0 || 
                              AlergiasAmbientais.Count > 0 || 
                              OutrasAlergias.Count > 0;

    public int TotalAlergias => AlergiasMedicamentosas.Count + 
                               AlergiasAlimentares.Count + 
                               AlergiasAmbientais.Count + 
                               OutrasAlergias.Count;

    public bool TemAlergiasGraves => AlergiasMedicamentosas.Any(a => a.Gravidade == "Grave") ||
                                    AlergiasAlimentares.Any(a => a.Gravidade == "Grave") ||
                                    AlergiasAmbientais.Any(a => a.Gravidade == "Grave") ||
                                    OutrasAlergias.Any(a => a.Gravidade == "Grave");

    public string ResumoAlergias
    {
        get
        {
            if (SemAlergias) return "Sem alergias conhecidas";
            if (!TemAlergias) return "Não avaliado";

            var resumos = new List<string>();
            
            if (AlergiasMedicamentosas.Count > 0)
                resumos.Add($"Medicamentos ({AlergiasMedicamentosas.Count})");
            
            if (AlergiasAlimentares.Count > 0)
                resumos.Add($"Alimentares ({AlergiasAlimentares.Count})");
            
            if (AlergiasAmbientais.Count > 0)
                resumos.Add($"Ambientais ({AlergiasAmbientais.Count})");
            
            if (OutrasAlergias.Count > 0)
                resumos.Add($"Outras ({OutrasAlergias.Count})");
            
            return string.Join(" | ", resumos);
        }
    }

    // VALIDAÇÃO
    public bool IsValid => SemAlergias || TemAlergias;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!SemAlergias && !TemAlergias)
            errors.Add("É necessário especificar se tem alergias ou marcar 'Sem alergias'");
        
        // Validar alergias medicamentosas (crítico!)
        foreach (var alergia in AlergiasMedicamentosas)
        {
            if (string.IsNullOrWhiteSpace(alergia.Medicamento))
                errors.Add("Medicamento da alergia não pode estar vazio");
        }
        
        return errors;
    }

    // MÉTODOS HELPER
    private void LimparTodasAlergias()
    {
        AlergiasMedicamentosas.Clear();
        AlergiasAlimentares.Clear();
        AlergiasAmbientais.Clear();
        OutrasAlergias.Clear();
        OnPropertyChanged(nameof(AlergiasMedicamentosas));
        OnPropertyChanged(nameof(AlergiasAlimentares));
        OnPropertyChanged(nameof(AlergiasAmbientais));
        OnPropertyChanged(nameof(OutrasAlergias));
        OnPropertyChanged(nameof(TemAlergias));
        OnPropertyChanged(nameof(TotalAlergias));
        OnPropertyChanged(nameof(ResumoAlergias));
    }
}

/// <summary>
/// Alergia medicamentosa - INFORMAÇÃO CRÍTICA
/// </summary>
public class AlergiaMedicamentosa : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _medicamento = string.Empty;
    private string _principioAtivo = string.Empty;
    private string _reacao = string.Empty;
    private string _gravidade = "Ligeira";
    private DateTime? _dataReacao;
    private string _contexto = string.Empty;

    public string Medicamento
    {
        get => _medicamento;
        set { _medicamento = value; OnPropertyChanged(); }
    }

    public string PrincipioAtivo
    {
        get => _principioAtivo;
        set { _principioAtivo = value; OnPropertyChanged(); }
    }

    public string Reacao
    {
        get => _reacao;
        set { _reacao = value; OnPropertyChanged(); }
    }

    public string Gravidade
    {
        get => _gravidade;
        set { _gravidade = value; OnPropertyChanged(); }
    }

    public DateTime? DataReacao
    {
        get => _dataReacao;
        set { _dataReacao = value; OnPropertyChanged(); }
    }

    public string Contexto
    {
        get => _contexto;
        set { _contexto = value; OnPropertyChanged(); }
    }

    public static List<string> OpcoesGravidade => new()
    {
        "Ligeira",
        "Moderada",
        "Grave",
        "Muito grave (anafilaxia)"
    };

    public static List<string> OpcoesReacao => new()
    {
        "Erupção cutânea",
        "Urticária",
        "Prurido",
        "Inchaço",
        "Dificuldade respiratória",
        "Náuseas/vómitos",
        "Diarreia",
        "Tonturas",
        "Anafilaxia",
        "Outra"
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Alergia alimentar
/// </summary>
public class AlergiaAlimentar : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _alimento = string.Empty;
    private string _reacao = string.Empty;
    private string _gravidade = "Ligeira";

    public string Alimento
    {
        get => _alimento;
        set { _alimento = value; OnPropertyChanged(); }
    }

    public string Reacao
    {
        get => _reacao;
        set { _reacao = value; OnPropertyChanged(); }
    }

    public string Gravidade
    {
        get => _gravidade;
        set { _gravidade = value; OnPropertyChanged(); }
    }

    public static List<string> AlimentosComuns => new()
    {
        "Leite/lacticínios",
        "Ovos",
        "Glúten/trigo",
        "Frutos secos",
        "Amendoim",
        "Peixe",
        "Marisco",
        "Soja",
        "Tomate",
        "Morango",
        "Chocolate",
        "Outro"
    };

    public static List<string> OpcoesGravidade => new()
    {
        "Ligeira",
        "Moderada", 
        "Grave"
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Alergia ambiental
/// </summary>
public class AlergiaAmbiental : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _alergeno = string.Empty;
    private string _reacao = string.Empty;
    private string _gravidade = "Ligeira";
    private string _sazonalidade = string.Empty;

    public string Alergeno
    {
        get => _alergeno;
        set { _alergeno = value; OnPropertyChanged(); }
    }

    public string Reacao
    {
        get => _reacao;
        set { _reacao = value; OnPropertyChanged(); }
    }

    public string Gravidade
    {
        get => _gravidade;
        set { _gravidade = value; OnPropertyChanged(); }
    }

    public string Sazonalidade
    {
        get => _sazonalidade;
        set { _sazonalidade = value; OnPropertyChanged(); }
    }

    public static List<string> AlergenosComuns => new()
    {
        "Pólen (geral)",
        "Pólen de gramíneas",
        "Pólen de árvores",
        "Ácaros",
        "Pelo de animais",
        "Fungos/bolores",
        "Poeira doméstica",
        "Produtos químicos",
        "Perfumes",
        "Látex",
        "Outro"
    };

    public static List<string> OpcoesSazonalidade => new()
    {
        "Todo o ano",
        "Primavera",
        "Verão", 
        "Outono",
        "Inverno",
        "Variável"
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Outras alergias
/// </summary>
public class OutraAlergia : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _tipo = string.Empty;
    private string _descricao = string.Empty;
    private string _reacao = string.Empty;
    private string _gravidade = "Ligeira";

    public string Tipo
    {
        get => _tipo;
        set { _tipo = value; OnPropertyChanged(); }
    }

    public string Descricao
    {
        get => _descricao;
        set { _descricao = value; OnPropertyChanged(); }
    }

    public string Reacao
    {
        get => _reacao;
        set { _reacao = value; OnPropertyChanged(); }
    }

    public string Gravidade
    {
        get => _gravidade;
        set { _gravidade = value; OnPropertyChanged(); }
    }

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}