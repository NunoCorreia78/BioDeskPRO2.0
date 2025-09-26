using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 10) FUNÇÕES BIOLÓGICAS 🟡 IMPORTANTE
/// Funções vitais: apetite, peso, sede, micção, defecação, menstruação
/// NUM (peso, altura) · DD (frequência) · CHK (alterações) · TXTL (observações específicas)
/// </summary>
public class FuncoesBiologicasExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Importante;
    public override string NomeExpander => "10) Funções Biológicas";

    // PESO E MEDIDAS
    private double _pesoAtual = 0;
    private double _altura = 0;
    private bool _alteracoesPeso = false;
    private string _tipoAlteracaoPeso = string.Empty;
    private double _pesoAnterior = 0;
    private DateTime? _dataAlteracaoPeso;

    // APETITE E SEDE
    private string _apetite = "Normal";
    private bool _alteracoesApetite = false;
    private string _tipoAlteracaoApetite = string.Empty;
    private string _sede = "Normal";
    private bool _alteracoesSede = false;

    // ELIMINAÇÃO URINÁRIA
    private string _frequenciaUrinaria = "Normal (4-6x/dia)";
    private string _caracteristicasUrina = "Normal";
    private bool _problemasUrinarios = false;
    private List<string> _sintomasUrinarios = new();

    // ELIMINAÇÃO INTESTINAL
    private string _frequenciaIntestinal = "Diária";
    private string _caracteristicasFezes = "Normal";
    private bool _problemasIntestinais = false;
    private List<string> _sintomasIntestinais = new();

    // FUNÇÃO SEXUAL (se aplicável)
    private string _funcaoSexual = "Não avaliada";
    private bool _problemasSetuais = false;
    private List<string> _sintomasSetuais = new();

    // MENSTRUAÇÃO (para mulheres)
    private bool _aplicavelMenstruacao = false;
    private string _statusMenstrual = "Regular";
    private int _cicloDias = 28;
    private int _duracaoMenstruacao = 5;
    private DateTime? _ultimaMenstruacao;
    private bool _problemasMenstruais = false;
    private List<string> _sintomasMenstruais = new();

    // PROPRIEDADES - PESO E MEDIDAS
    public double PesoAtual
    {
        get => _pesoAtual;
        set { _pesoAtual = Math.Max(0, value); OnPropertyChanged(); CalcularIMC(); }
    }

    public double Altura
    {
        get => _altura;
        set { _altura = Math.Max(0, value); OnPropertyChanged(); CalcularIMC(); }
    }

    public bool AlteracoesPeso
    {
        get => _alteracoesPeso;
        set { _alteracoesPeso = value; OnPropertyChanged(); }
    }

    public string TipoAlteracaoPeso
    {
        get => _tipoAlteracaoPeso;
        set { _tipoAlteracaoPeso = value; OnPropertyChanged(); }
    }

    public double PesoAnterior
    {
        get => _pesoAnterior;
        set { _pesoAnterior = Math.Max(0, value); OnPropertyChanged(); }
    }

    public DateTime? DataAlteracaoPeso
    {
        get => _dataAlteracaoPeso;
        set { _dataAlteracaoPeso = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - APETITE
    public string Apetite
    {
        get => _apetite;
        set { _apetite = value; OnPropertyChanged(); }
    }

    public bool AlteracoesApetite
    {
        get => _alteracoesApetite;
        set { _alteracoesApetite = value; OnPropertyChanged(); }
    }

    public string TipoAlteracaoApetite
    {
        get => _tipoAlteracaoApetite;
        set { _tipoAlteracaoApetite = value; OnPropertyChanged(); }
    }

    public string Sede
    {
        get => _sede;
        set { _sede = value; OnPropertyChanged(); }
    }

    public bool AlteracoesSede
    {
        get => _alteracoesSede;
        set { _alteracoesSede = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - URINÁRIA
    public string FrequenciaUrinaria
    {
        get => _frequenciaUrinaria;
        set { _frequenciaUrinaria = value; OnPropertyChanged(); }
    }

    public string CaracteristicasUrina
    {
        get => _caracteristicasUrina;
        set { _caracteristicasUrina = value; OnPropertyChanged(); }
    }

    public bool ProblemasUrinarios
    {
        get => _problemasUrinarios;
        set { _problemasUrinarios = value; OnPropertyChanged(); }
    }

    public List<string> SintomasUrinarios
    {
        get => _sintomasUrinarios;
        set { _sintomasUrinarios = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - INTESTINAL
    public string FrequenciaIntestinal
    {
        get => _frequenciaIntestinal;
        set { _frequenciaIntestinal = value; OnPropertyChanged(); }
    }

    public string CaracteristicasFezes
    {
        get => _caracteristicasFezes;
        set { _caracteristicasFezes = value; OnPropertyChanged(); }
    }

    public bool ProblemasIntestinais
    {
        get => _problemasIntestinais;
        set { _problemasIntestinais = value; OnPropertyChanged(); }
    }

    public List<string> SintomasIntestinais
    {
        get => _sintomasIntestinais;
        set { _sintomasIntestinais = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - FUNÇÃO SEXUAL
    public string FuncaoSexual
    {
        get => _funcaoSexual;
        set { _funcaoSexual = value; OnPropertyChanged(); }
    }

    public bool ProblemasSetuais
    {
        get => _problemasSetuais;
        set { _problemasSetuais = value; OnPropertyChanged(); }
    }

    public List<string> SintomasSetuais
    {
        get => _sintomasSetuais;
        set { _sintomasSetuais = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES - MENSTRUAÇÃO
    public bool AplicavelMenstruacao
    {
        get => _aplicavelMenstruacao;
        set { _aplicavelMenstruacao = value; OnPropertyChanged(); }
    }

    public string StatusMenstrual
    {
        get => _statusMenstrual;
        set { _statusMenstrual = value; OnPropertyChanged(); }
    }

    public int CicloDias
    {
        get => _cicloDias;
        set { _cicloDias = Math.Max(15, Math.Min(45, value)); OnPropertyChanged(); }
    }

    public int DuracaoMenstruacao
    {
        get => _duracaoMenstruacao;
        set { _duracaoMenstruacao = Math.Max(1, Math.Min(10, value)); OnPropertyChanged(); }
    }

    public DateTime? UltimaMenstruacao
    {
        get => _ultimaMenstruacao;
        set { _ultimaMenstruacao = value; OnPropertyChanged(); }
    }

    public bool ProblemasMenstruais
    {
        get => _problemasMenstruais;
        set { _problemasMenstruais = value; OnPropertyChanged(); }
    }

    public List<string> SintomasMenstruais
    {
        get => _sintomasMenstruais;
        set { _sintomasMenstruais = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public double IMC { get; private set; } = 0;
    public string ClassificacaoIMC { get; private set; } = string.Empty;

    private void CalcularIMC()
    {
        if (PesoAtual > 0 && Altura > 0)
        {
            var alturaM = Altura / 100; // converter cm para metros
            IMC = Math.Round(PesoAtual / (alturaM * alturaM), 1);
            
            ClassificacaoIMC = IMC switch
            {
                < 18.5 => "Abaixo do peso",
                >= 18.5 and < 25 => "Peso normal",
                >= 25 and < 30 => "Sobrepeso",
                >= 30 and < 35 => "Obesidade grau I",
                >= 35 and < 40 => "Obesidade grau II",
                >= 40 => "Obesidade grau III",
                _ => "Não calculável"
            };
        }
        else
        {
            IMC = 0;
            ClassificacaoIMC = "Dados insuficientes";
        }
        
        OnPropertyChanged(nameof(IMC));
        OnPropertyChanged(nameof(ClassificacaoIMC));
    }

    public string ResumoAlteracoesPeso
    {
        get
        {
            if (!AlteracoesPeso) return "Peso estável";
            
            var diferenca = PesoAnterior > 0 ? PesoAtual - PesoAnterior : 0;
            var sinal = diferenca > 0 ? "+" : "";
            return $"{TipoAlteracaoPeso} ({sinal}{diferenca:F1}kg)";
        }
    }

    public bool TemAlteracoesSignificativas => 
        AlteracoesPeso || AlteracoesApetite || AlteracoesSede || 
        ProblemasUrinarios || ProblemasIntestinais || 
        (AplicavelMenstruacao && ProblemasMenstruais);

    public string ResumoFuncoesBiologicas
    {
        get
        {
            var componentes = new List<string>();
            
            if (IMC > 0)
                componentes.Add($"IMC: {IMC} ({ClassificacaoIMC})");
            
            if (AlteracoesPeso)
                componentes.Add($"Peso: {TipoAlteracaoPeso}");
            
            if (ProblemasUrinarios)
                componentes.Add("Problemas urinários");
            
            if (ProblemasIntestinais)
                componentes.Add("Problemas intestinais");
            
            if (AplicavelMenstruacao && ProblemasMenstruais)
                componentes.Add("Problemas menstruais");
            
            return componentes.Count > 0 ? string.Join(" | ", componentes) : "Funções normais";
        }
    }

    // OPÇÕES PRÉ-DEFINIDAS
    public static List<string> OpcoesApetite => new()
    {
        "Normal",
        "Aumentado",
        "Diminuído",
        "Ausente",
        "Seletivo",
        "Variável"
    };

    public static List<string> OpcoesTipoAlteracaoApetite => new()
    {
        "Aumento recente",
        "Diminuição recente",
        "Perda total",
        "Compulsão alimentar",
        "Aversão a alimentos específicos",
        "Náuseas relacionadas"
    };

    public static List<string> OpcoesSede => new()
    {
        "Normal",
        "Aumentada",
        "Diminuída",
        "Ausente"
    };

    public static List<string> OpcoesFrequenciaUrinaria => new()
    {
        "Normal (4-6x/dia)",
        "Diminuída (<4x/dia)",
        "Aumentada (7-10x/dia)",
        "Muito aumentada (>10x/dia)",
        "Noctúria (acordar para urinar)"
    };

    public static List<string> OpcoesCaracteristicasUrina => new()
    {
        "Normal",
        "Cor alterada (escura)",
        "Cor alterada (muito clara)",
        "Turva",
        "Espumosa",
        "Sangue (hematúria)",
        "Odor forte"
    };

    public static List<string> OpcoesSintomasUrinarios => new()
    {
        "Dor/ardor ao urinar",
        "Urgência urinária",
        "Incontinência",
        "Jato fraco",
        "Gotejamento",
        "Sensação de esvaziamento incompleto",
        "Dor suprapúbica",
        "Noctúria"
    };

    public static List<string> OpcoesFrequenciaIntestinal => new()
    {
        "Várias vezes por dia",
        "Diária",
        "Dia sim, dia não",
        "2-3 vezes/semana",
        "1 vez/semana",
        "Menos de 1 vez/semana"
    };

    public static List<string> OpcoesCaracteristicasFezes => new()
    {
        "Normal",
        "Duras/secas",
        "Moles/pastosas",
        "Líquidas",
        "Com sangue",
        "Muito escuras",
        "Muito claras",
        "Oleosas",
        "Com muco"
    };

    public static List<string> OpcoesSintomasIntestinais => new()
    {
        "Obstipação",
        "Diarreia",
        "Alternância obstipação/diarreia",
        "Gases excessivos",
        "Distensão abdominal",
        "Cólicas",
        "Urgência intestinal",
        "Incontinência fecal",
        "Dor anal"
    };

    public static List<string> OpcoesFuncaoSexual => new()
    {
        "Não avaliada",
        "Normal",
        "Diminuída",
        "Ausente",
        "Dor durante ato sexual",
        "Disfunção erétil",
        "Ejaculação precoce",
        "Secura vaginal",
        "Vaginismo"
    };

    public static List<string> OpcoesStatusMenstrual => new()
    {
        "Regular",
        "Irregular",
        "Amenorreia",
        "Menorragia (fluxo excessivo)",
        "Oligomenorreia (ciclos longos)",
        "Polimenorreia (ciclos curtos)",
        "Menopausa",
        "Pré-menopausa"
    };

    public static List<string> OpcoesSintomasMenstruais => new()
    {
        "Dismenorreia (dores)",
        "SPM (síndrome pré-menstrual)",
        "Fluxo excessivo",
        "Fluxo escasso",
        "Coágulos",
        "Spotting",
        "Alterações do humor",
        "Retenção de líquidos",
        "Sensibilidade mamária"
    };

    // VALIDAÇÃO
    public bool IsValid => true; // Sempre válido

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        // Validações opcionais para alertas
        if (PesoAtual > 0 && Altura > 0 && (IMC < 16 || IMC > 45))
            errors.Add($"⚠️ IMC {IMC} pode indicar problema nutricional");
        
        return errors;
    }
}