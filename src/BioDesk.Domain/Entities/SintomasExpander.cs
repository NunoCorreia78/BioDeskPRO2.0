using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Linq;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 3) SINTOMAS 🟡 IMPORTANTE
/// Revisão de sistemas por aparelhos - sintomas atuais e recentes
/// CHK (presença/ausência) · CHIP (sintomas específicos) · SL (intensidade) · TXTL (observações)
/// </summary>
public class SintomasExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Importante;
    public override string NomeExpander => "3) Sintomas";

    // SISTEMAS DE ÓRGÃOS
    public SistemaCardiovascular Cardiovascular { get; set; } = new();
    public SistemaRespiratorio Respiratorio { get; set; } = new();
    public SistemaDigestivo Digestivo { get; set; } = new();
    public SistemaNeurologico Neurologico { get; set; } = new();
    public SistemaMusculoEsqueletico MusculoEsqueletico { get; set; } = new();
    public SistemaGeniturinario Geniturinario { get; set; } = new();
    public SistemaDermatologico Dermatologico { get; set; } = new();
    public SistemaEndocrino Endocrino { get; set; } = new();
    public SistemaHematologico Hematologico { get; set; } = new();

    // OBSERVAÇÕES GERAIS
    private string _observacoesGerais = string.Empty;
    
    public string ObservacoesGerais
    {
        get => _observacoesGerais;
        set { _observacoesGerais = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public int TotalSintomasPositivos
    {
        get
        {
            return Cardiovascular.SintomasPositivos.Count +
                   Respiratorio.SintomasPositivos.Count +
                   Digestivo.SintomasPositivos.Count +
                   Neurologico.SintomasPositivos.Count +
                   MusculoEsqueletico.SintomasPositivos.Count +
                   Geniturinario.SintomasPositivos.Count +
                   Dermatologico.SintomasPositivos.Count +
                   Endocrino.SintomasPositivos.Count +
                   Hematologico.SintomasPositivos.Count;
        }
    }

    public bool TemSintomas => TotalSintomasPositivos > 0;

    public string ResumoSintomas
    {
        get
        {
            if (!TemSintomas) return "Sem sintomas reportados";
            return $"{TotalSintomasPositivos} sintoma(s) em {QuantidadeSistemasAfetados} sistema(s)";
        }
    }

    private int QuantidadeSistemasAfetados
    {
        get
        {
            int count = 0;
            if (Cardiovascular.SintomasPositivos.Count > 0) count++;
            if (Respiratorio.SintomasPositivos.Count > 0) count++;
            if (Digestivo.SintomasPositivos.Count > 0) count++;
            if (Neurologico.SintomasPositivos.Count > 0) count++;
            if (MusculoEsqueletico.SintomasPositivos.Count > 0) count++;
            if (Geniturinario.SintomasPositivos.Count > 0) count++;
            if (Dermatologico.SintomasPositivos.Count > 0) count++;
            if (Endocrino.SintomasPositivos.Count > 0) count++;
            if (Hematologico.SintomasPositivos.Count > 0) count++;
            return count;
        }
    }

    // VALIDAÇÃO
    public bool IsValid => true; // Sempre válido, pode estar vazio

    public List<string> GetValidationErrors()
    {
        return new List<string>(); // Sem validações obrigatórias para sintomas
    }
}

/// <summary>
/// Base para sistemas de sintomas
/// </summary>
public abstract class SistemaBase : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private List<string> _sintomasPositivos = new();
    private List<string> _sintomasNegativos = new();
    private string _observacoes = string.Empty;

    public List<string> SintomasPositivos
    {
        get => _sintomasPositivos;
        set { _sintomasPositivos = value; OnPropertyChanged(); }
    }

    public List<string> SintomasNegativos
    {
        get => _sintomasNegativos;
        set { _sintomasNegativos = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    public abstract string NomeSistema { get; }
    public abstract List<string> SintomasDisponiveis { get; }

    public bool TemSintomas => SintomasPositivos.Count > 0;
    public int TotalSintomas => SintomasPositivos.Count;

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }

    public void AdicionarSintomaPositivo(string sintoma)
    {
        if (!string.IsNullOrWhiteSpace(sintoma) && !SintomasPositivos.Contains(sintoma))
        {
            SintomasPositivos.Add(sintoma);
            SintomasNegativos.Remove(sintoma); // Remove dos negativos se existir
            OnPropertyChanged(nameof(SintomasPositivos));
            OnPropertyChanged(nameof(SintomasNegativos));
        }
    }

    public void AdicionarSintomaNegativo(string sintoma)
    {
        if (!string.IsNullOrWhiteSpace(sintoma) && !SintomasNegativos.Contains(sintoma))
        {
            SintomasNegativos.Add(sintoma);
            SintomasPositivos.Remove(sintoma); // Remove dos positivos se existir
            OnPropertyChanged(nameof(SintomasPositivos));
            OnPropertyChanged(nameof(SintomasNegativos));
        }
    }
}

public class SistemaCardiovascular : SistemaBase
{
    public override string NomeSistema => "Cardiovascular";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Dor no peito",
        "Palpitações",
        "Falta de ar",
        "Fadiga aos esforços",
        "Tonturas",
        "Síncope (desmaio)",
        "Edema (inchaço)",
        "Claudicação intermitente",
        "Dor nas pernas ao caminhar",
        "Cianose (cor azulada)",
        "Sudorese excessiva",
        "Ortopneia (falta de ar deitado)"
    };
}

public class SistemaRespiratorio : SistemaBase
{
    public override string NomeSistema => "Respiratório";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Tosse seca",
        "Tosse com expetoração",
        "Falta de ar",
        "Pieira/sibilo",
        "Dor torácica",
        "Hemoptises (sangue na tosse)",
        "Rouquidão",
        "Dor de garganta",
        "Congestão nasal",
        "Espirros",
        "Apneia do sono",
        "Respiração ruidosa"
    };
}

public class SistemaDigestivo : SistemaBase
{
    public override string NomeSistema => "Digestivo";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Náuseas",
        "Vómitos",
        "Dor abdominal",
        "Azia/queimadura",
        "Distensão abdominal",
        "Flatulência",
        "Obstipação",
        "Diarreia",
        "Sangue nas fezes",
        "Fezes escuras (melenas)",
        "Perda de apetite",
        "Perda de peso",
        "Dificuldade em engolir",
        "Regurgitação",
        "Icterícia (cor amarela)"
    };
}

public class SistemaNeurologico : SistemaBase
{
    public override string NomeSistema => "Neurológico";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Cefaleias/dores de cabeça",
        "Tonturas",
        "Vertigens",
        "Alterações da visão",
        "Perda de memória",
        "Confusão mental",
        "Alterações do sono",
        "Tremores",
        "Formigueiro",
        "Dormência",
        "Fraqueza muscular",
        "Perda de equilíbrio",
        "Alterações da fala",
        "Convulsões",
        "Perda de consciência"
    };
}

public class SistemaMusculoEsqueletico : SistemaBase
{
    public override string NomeSistema => "Músculo-Esquelético";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Dores articulares",
        "Rigidez matinal",
        "Inchaço articular",
        "Limitação de movimentos",
        "Dores musculares",
        "Cãibras",
        "Fraqueza muscular",
        "Dor nas costas",
        "Dor cervical",
        "Fraturas recorrentes",
        "Deformidades articulares"
    };
}

public class SistemaGeniturinario : SistemaBase
{
    public override string NomeSistema => "Génito-Urinário";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Alterações urinárias",
        "Dor ao urinar",
        "Urgência urinária",
        "Frequência urinária aumentada",
        "Incontinência urinária",
        "Sangue na urina",
        "Urina escura/turva",
        "Dor no flanco",
        "Disfunção eréctil",
        "Diminuição da libido",
        "Alterações menstruais",
        "Corrimento vaginal",
        "Dor pélvica"
    };
}

public class SistemaDermatologico : SistemaBase
{
    public override string NomeSistema => "Dermatológico";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Erupção cutânea",
        "Prurido (comichão)",
        "Secura da pele",
        "Alterações de cor",
        "Lesões cutâneas",
        "Úlceras",
        "Descamação",
        "Alterações nas unhas",
        "Queda de cabelo",
        "Sudorese excessiva",
        "Odor corporal"
    };
}

public class SistemaEndocrino : SistemaBase
{
    public override string NomeSistema => "Endócrino";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Alterações de peso",
        "Intolerância ao frio",
        "Intolerância ao calor",
        "Sudorese excessiva",
        "Fadiga",
        "Alterações do humor",
        "Sede excessiva",
        "Fome excessiva",
        "Micção frequente",
        "Alterações do crescimento",
        "Alterações da pele/cabelo"
    };
}

public class SistemaHematologico : SistemaBase
{
    public override string NomeSistema => "Hematológico";
    
    public override List<string> SintomasDisponiveis => new()
    {
        "Fadiga persistente",
        "Palidez",
        "Hematomas fáceis",
        "Sangramento excessivo",
        "Gânglios aumentados",
        "Infeções frequentes",
        "Febre recorrente",
        "Perda de peso inexplicada",
        "Sudores noturnos"
    };
}