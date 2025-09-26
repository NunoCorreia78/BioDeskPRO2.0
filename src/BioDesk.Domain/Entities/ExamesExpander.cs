using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Linq;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 11) EXAMES 🟡 IMPORTANTE
/// Exames complementares: análises, imagiologia, relatórios médicos
/// DAT (data) · TXT (exame) · DD (resultado) · ANN (anexo) · TXTL (observações)
/// </summary>
public class ExamesExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Importante;
    public override string NomeExpander => "11) Exames";

    // ESTADO GLOBAL
    private bool _semExames = false;

    // EXAMES
    private List<ExameComplementar> _exames = new();

    // OBSERVAÇÕES
    private string _observacoes = string.Empty;

    // PROPRIEDADES
    public bool SemExames
    {
        get => _semExames;
        set
        {
            _semExames = value;
            if (value)
            {
                Exames.Clear();
                OnPropertyChanged(nameof(Exames));
            }
            OnPropertyChanged();
        }
    }

    public List<ExameComplementar> Exames
    {
        get => _exames;
        set { _exames = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public bool TemExames => Exames.Count > 0;
    
    public int TotalExames => Exames.Count;

    public List<ExameComplementar> ExamesRecentes => Exames
        .Where(e => e.Data.HasValue && e.Data.Value >= DateTime.Today.AddMonths(-6))
        .OrderByDescending(e => e.Data)
        .ToList();

    public List<ExameComplementar> ExamesAlterados => Exames
        .Where(e => e.Resultado == "Alterado" || e.Resultado == "Patológico")
        .ToList();

    public bool TemExamesAlterados => ExamesAlterados.Count > 0;

    public Dictionary<string, int> ExamesPorTipo => Exames
        .GroupBy(e => e.TipoExame)
        .ToDictionary(g => g.Key, g => g.Count());

    public string ResumoExames
    {
        get
        {
            if (SemExames) return "Sem exames";
            if (!TemExames) return "Não avaliado";
            
            var recentes = ExamesRecentes.Count;
            var alterados = ExamesAlterados.Count;
            var alteradosTexto = alterados > 0 ? $" | {alterados} alterado(s)" : "";
            return $"{TotalExames} exame(s){(recentes > 0 ? $" | {recentes} recente(s)" : "")}{alteradosTexto}";
        }
    }

    // EXAMES SUGERIDOS BASEADOS EM CONDIÇÕES (integração com outros expanders)
    public List<string> ExamesSugeridosParaCondicoes(List<string> condicoes)
    {
        var sugeridos = new HashSet<string>();
        
        foreach (var condicao in condicoes.Select(c => c.ToLower()))
        {
            switch (condicao)
            {
                case var c when c.Contains("diabetes"):
                    sugeridos.UnionWith(new[] { "HbA1c", "Glicemia em jejum", "Perfil lipídico" });
                    break;
                case var c when c.Contains("hipertensão"):
                    sugeridos.UnionWith(new[] { "ECG", "Tensão arterial", "Função renal" });
                    break;
                case var c when c.Contains("colesterol"):
                    sugeridos.UnionWith(new[] { "Perfil lipídico completo" });
                    break;
                case var c when c.Contains("tiroide"):
                    sugeridos.UnionWith(new[] { "TSH", "T3 livre", "T4 livre" });
                    break;
                case var c when c.Contains("anemia"):
                    sugeridos.UnionWith(new[] { "Hemograma", "Ferritina", "B12", "Ácido fólico" });
                    break;
                case var c when c.Contains("renal"):
                    sugeridos.UnionWith(new[] { "Função renal", "Análise urina", "Ecografia renal" });
                    break;
                case var c when c.Contains("cardíac"):
                    sugeridos.UnionWith(new[] { "ECG", "Ecocardiograma", "Enzimas cardíacas" });
                    break;
            }
        }
        
        return sugeridos.ToList();
    }

    // VALIDAÇÃO
    public bool IsValid => SemExames || TemExames;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!SemExames && !TemExames)
            errors.Add("É necessário especificar se tem exames ou marcar 'Sem exames'");
        
        foreach (var exame in Exames)
        {
            if (string.IsNullOrWhiteSpace(exame.Nome))
                errors.Add("Nome do exame não pode estar vazio");
        }
        
        return errors;
    }

    // MÉTODOS HELPER
    public void AdicionarExame(string nome, string tipo = "Análise")
    {
        if (!string.IsNullOrWhiteSpace(nome))
        {
            var novoExame = new ExameComplementar 
            { 
                Nome = nome, 
                TipoExame = tipo,
                Data = DateTime.Today
            };
            Exames.Add(novoExame);
            OnPropertyChanged(nameof(Exames));
            OnPropertyChanged(nameof(TemExames));
            OnPropertyChanged(nameof(ResumoExames));
        }
    }

    // ANÁLISE DE TENDÊNCIAS (simplificada)
    public string AnaliseHbA1c
    {
        get
        {
            var hba1cs = Exames
                .Where(e => e.Nome.ToLower().Contains("hba1c") && !string.IsNullOrEmpty(e.ValorNumerico))
                .OrderBy(e => e.Data)
                .ToList();

            if (hba1cs.Count >= 2)
            {
                if (double.TryParse(hba1cs.Last().ValorNumerico, out var ultimo) &&
                    double.TryParse(hba1cs[^2].ValorNumerico, out var penultimo))
                {
                    var tendencia = ultimo > penultimo ? "↗️ A subir" : ultimo < penultimo ? "↘️ A descer" : "→ Estável";
                    return $"HbA1c: {ultimo}% {tendencia}";
                }
            }
            
            return string.Empty;
        }
    }
}

/// <summary>
/// Exame complementar individual
/// </summary>
public class ExameComplementar : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _nome = string.Empty;
    private string _tipoExame = "Análise";
    private DateTime? _data;
    private string _local = string.Empty;
    private string _medicoSolicitante = string.Empty;
    private string _resultado = "Pendente";
    private string _valorNumerico = string.Empty;
    private string _unidade = string.Empty;
    private string _valorReferencia = string.Empty;
    private string _interpretacao = string.Empty;
    private string _observacoes = string.Empty;
    private bool _temAnexo = false;
    private string _caminhoAnexo = string.Empty;

    public string Nome
    {
        get => _nome;
        set { _nome = value; OnPropertyChanged(); }
    }

    public string TipoExame
    {
        get => _tipoExame;
        set { _tipoExame = value; OnPropertyChanged(); }
    }

    public DateTime? Data
    {
        get => _data;
        set { _data = value; OnPropertyChanged(); CalcularTempoDecorrido(); }
    }

    public string Local
    {
        get => _local;
        set { _local = value; OnPropertyChanged(); }
    }

    public string MedicoSolicitante
    {
        get => _medicoSolicitante;
        set { _medicoSolicitante = value; OnPropertyChanged(); }
    }

    public string Resultado
    {
        get => _resultado;
        set { _resultado = value; OnPropertyChanged(); }
    }

    public string ValorNumerico
    {
        get => _valorNumerico;
        set { _valorNumerico = value; OnPropertyChanged(); ValidarValorNumerico(); }
    }

    public string Unidade
    {
        get => _unidade;
        set { _unidade = value; OnPropertyChanged(); }
    }

    public string ValorReferencia
    {
        get => _valorReferencia;
        set { _valorReferencia = value; OnPropertyChanged(); ValidarValorNumerico(); }
    }

    public string Interpretacao
    {
        get => _interpretacao;
        set { _interpretacao = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    public bool TemAnexo
    {
        get => _temAnexo;
        set { _temAnexo = value; OnPropertyChanged(); }
    }

    public string CaminhoAnexo
    {
        get => _caminhoAnexo;
        set { _caminhoAnexo = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public string TempoDecorrido { get; private set; } = string.Empty;
    public string StatusValor { get; private set; } = string.Empty;

    private void CalcularTempoDecorrido()
    {
        if (Data.HasValue)
        {
            var tempo = DateTime.Today - Data.Value;
            if (tempo.Days == 0)
                TempoDecorrido = "Hoje";
            else if (tempo.Days < 30)
                TempoDecorrido = $"{tempo.Days} dia(s) atrás";
            else if (tempo.Days < 365)
                TempoDecorrido = $"{tempo.Days / 30} mês(es) atrás";
            else
                TempoDecorrido = $"{tempo.Days / 365} ano(s) atrás";
        }
        else
        {
            TempoDecorrido = "Data não especificada";
        }
        OnPropertyChanged(nameof(TempoDecorrido));
    }

    private void ValidarValorNumerico()
    {
        if (string.IsNullOrWhiteSpace(ValorNumerico) || string.IsNullOrWhiteSpace(ValorReferencia))
        {
            StatusValor = string.Empty;
            return;
        }

        if (double.TryParse(ValorNumerico, out var valor))
        {
            // Parsing simples para valores de referência (ex: "4.0-6.0", "<5.7", ">100")
            if (ValorReferencia.Contains("-"))
            {
                var partes = ValorReferencia.Split('-');
                if (partes.Length == 2 && 
                    double.TryParse(partes[0].Trim(), out var min) && 
                    double.TryParse(partes[1].Trim(), out var max))
                {
                    if (valor < min)
                        StatusValor = "🔵 Baixo";
                    else if (valor > max)
                        StatusValor = "🔴 Alto";
                    else
                        StatusValor = "✅ Normal";
                }
            }
            else if (ValorReferencia.StartsWith("<") && 
                     double.TryParse(ValorReferencia.Substring(1).Trim(), out var limiteMax))
            {
                StatusValor = valor < limiteMax ? "✅ Normal" : "🔴 Alto";
            }
            else if (ValorReferencia.StartsWith(">") && 
                     double.TryParse(ValorReferencia.Substring(1).Trim(), out var limiteMin))
            {
                StatusValor = valor > limiteMin ? "✅ Normal" : "🔵 Baixo";
            }
        }
        
        OnPropertyChanged(nameof(StatusValor));
    }

    public string ExameCompleto => 
        $"{Nome}{(!string.IsNullOrEmpty(ValorNumerico) ? $": {ValorNumerico} {Unidade}" : "")}{(!string.IsNullOrEmpty(StatusValor) ? $" {StatusValor}" : "")}";

    // OPÇÕES PRÉ-DEFINIDAS
    public static List<string> OpcoesTipoExame => new()
    {
        "Análise",
        "Imagiologia",
        "Biópsia",
        "Endoscopia",
        "Cardiologia",
        "Neurologia",
        "Oftalmologia",
        "Audiometria",
        "Dermatoscopia",
        "Outro"
    };

    public static List<string> OpcoesResultado => new()
    {
        "Pendente",
        "Normal",
        "Alterado",
        "Patológico",
        "Inconclusivo",
        "A repetir"
    };

    public static Dictionary<string, List<string>> ExamesPorTipo => new()
    {
        ["Análise"] = new()
        {
            // BIOQUÍMICA
            "Glicemia",
            "HbA1c",
            "Colesterol total",
            "HDL",
            "LDL",
            "Triglicéridos",
            "Creatinina",
            "Ureia",
            "Ácido úrico",
            "Transaminases (ALT/AST)",
            "Fosfatase alcalina",
            "Bilirrubina",

            // HEMATOLOGIA
            "Hemograma",
            "Velocidade sedimentação",
            "Proteína C reativa",
            "Ferritina",
            "B12",
            "Ácido fólico",
            "D-Dímeros",

            // ENDÓCRINAS
            "TSH",
            "T3 livre",
            "T4 livre",
            "Cortisol",
            "Testosterona",
            "Estradiol",
            "PSA",

            // MARCADORES
            "Troponina",
            "BNP/NT-proBNP",
            "CEA",
            "CA 19.9",
            "CA 125",
            "AFP",

            // URINA
            "Análise urina",
            "Urocultura",
            "Microalbuminúria"
        },

        ["Imagiologia"] = new()
        {
            // RADIOLOGIA
            "Raio-X tórax",
            "Raio-X abdómen",
            "Raio-X coluna",
            "Mamografia",

            // ECOGRAFIA
            "Ecografia abdominal",
            "Ecocardiograma",
            "Ecografia pélvica",
            "Ecografia tiroideia",

            // TAC/RM
            "TAC crânio",
            "TAC tórax",
            "TAC abdómen",
            "RM coluna",
            "RM crânio",

            // OUTROS
            "Densitometria óssea",
            "Cintigrafia"
        },

        ["Cardiologia"] = new()
        {
            "ECG",
            "Ecocardiograma",
            "Holter 24h",
            "Prova de esforço",
            "Tensão arterial 24h"
        }
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}