using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Linq;

namespace BioDesk.Domain.Entities;

/// <summary>
/// EXPANDER 6) MEDICAÇÃO 🔴 CRÍTICO
/// Medicamentos atuais, suplementos, dosagens - CRÍTICO PARA INTERAÇÕES
/// TXT (medicamento) · NUM (dosagem) · DD (frequência) · DAT (início) · CHK (ativo)
/// </summary>
public class MedicacaoExpander : ExpanderBase
{
    public override PrioridadeClinica PrioridadeClinica => PrioridadeClinica.Critico;
    public override string NomeExpander => "6) Medicação";

    // ESTADO GLOBAL
    private bool _semMedicacao = false;

    // MEDICAMENTOS
    private List<Medicamento> _medicamentos = new();
    
    // SUPLEMENTOS
    private List<Suplemento> _suplementos = new();

    // OBSERVAÇÕES
    private string _observacoesMedicacao = string.Empty;
    private string _reacoesMedicamentos = string.Empty;

    // PROPRIEDADES
    public bool SemMedicacao
    {
        get => _semMedicacao;
        set
        {
            _semMedicacao = value;
            if (value)
            {
                LimparTodaMedicacao();
            }
            OnPropertyChanged();
        }
    }

    public List<Medicamento> Medicamentos
    {
        get => _medicamentos;
        set { _medicamentos = value; OnPropertyChanged(); }
    }

    public List<Suplemento> Suplementos
    {
        get => _suplementos;
        set { _suplementos = value; OnPropertyChanged(); }
    }

    public string ObservacoesMedicacao
    {
        get => _observacoesMedicacao;
        set { _observacoesMedicacao = value; OnPropertyChanged(); }
    }

    public string ReacoesMedicamentos
    {
        get => _reacoesMedicamentos;
        set { _reacoesMedicamentos = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public bool TemMedicacao => Medicamentos.Count > 0 || Suplementos.Count > 0;
    
    public int TotalItens => Medicamentos.Count + Suplementos.Count;

    public List<Medicamento> MedicamentosAtivos => Medicamentos
        .Where(m => m.Ativo)
        .ToList();

    public List<Suplemento> SuplementosAtivos => Suplementos
        .Where(s => s.Ativo)
        .ToList();

    public int TotalAtivos => MedicamentosAtivos.Count + SuplementosAtivos.Count;

    public bool TemMedicamentosControlados => Medicamentos
        .Any(m => m.TipoMedicamento.Contains("Controlado"));

    public string ResumoMedicacao
    {
        get
        {
            if (SemMedicacao) return "Sem medicação";
            if (!TemMedicacao) return "Não avaliado";
            
            return $"{Medicamentos.Count} medicamento(s) | {Suplementos.Count} suplemento(s) | {TotalAtivos} ativo(s)";
        }
    }

    // VALIDAÇÃO
    public bool IsValid => SemMedicacao || TemMedicacao;

    public List<string> GetValidationErrors()
    {
        var errors = new List<string>();
        
        if (!SemMedicacao && !TemMedicacao)
            errors.Add("É necessário especificar se toma medicação ou marcar 'Sem medicação'");
        
        foreach (var medicamento in Medicamentos)
        {
            if (string.IsNullOrWhiteSpace(medicamento.Nome))
                errors.Add("Nome do medicamento não pode estar vazio");
            if (string.IsNullOrWhiteSpace(medicamento.Dosagem))
                errors.Add($"Dosagem do medicamento '{medicamento.Nome}' é obrigatória");
        }
        
        foreach (var suplemento in Suplementos)
        {
            if (string.IsNullOrWhiteSpace(suplemento.Nome))
                errors.Add("Nome do suplemento não pode estar vazio");
        }
        
        return errors;
    }

    // MÉTODOS HELPER
    private void LimparTodaMedicacao()
    {
        Medicamentos.Clear();
        Suplementos.Clear();
        OnPropertyChanged(nameof(Medicamentos));
        OnPropertyChanged(nameof(Suplementos));
        OnPropertyChanged(nameof(TemMedicacao));
        OnPropertyChanged(nameof(TotalItens));
        OnPropertyChanged(nameof(ResumoMedicacao));
    }

    public void AdicionarMedicamento(string nome)
    {
        if (!string.IsNullOrWhiteSpace(nome))
        {
            var novoMedicamento = new Medicamento { Nome = nome };
            Medicamentos.Add(novoMedicamento);
            OnPropertyChanged(nameof(Medicamentos));
            OnPropertyChanged(nameof(TemMedicacao));
            OnPropertyChanged(nameof(ResumoMedicacao));
        }
    }

    public void AdicionarSuplemento(string nome)
    {
        if (!string.IsNullOrWhiteSpace(nome))
        {
            var novoSuplemento = new Suplemento { Nome = nome };
            Suplementos.Add(novoSuplemento);
            OnPropertyChanged(nameof(Suplementos));
            OnPropertyChanged(nameof(TemMedicacao));
            OnPropertyChanged(nameof(ResumoMedicacao));
        }
    }

    // DETECÇÃO DE INTERAÇÕES (básica)
    public List<string> PossiveisInteracoes
    {
        get
        {
            var interacoes = new List<string>();
            var medicamentosAtivos = MedicamentosAtivos.Select(m => m.Nome.ToLower()).ToList();
            
            // Exemplos de interações comuns (simplificado)
            if (medicamentosAtivos.Any(m => m.Contains("warfarina")) && 
                medicamentosAtivos.Any(m => m.Contains("aspirina")))
            {
                interacoes.Add("⚠️ Warfarina + Aspirina: Risco de hemorragia");
            }
            
            if (medicamentosAtivos.Any(m => m.Contains("digoxina")) && 
                medicamentosAtivos.Any(m => m.Contains("furosemida")))
            {
                interacoes.Add("⚠️ Digoxina + Furosemida: Monitorizar potássio");
            }
            
            return interacoes;
        }
    }
}

/// <summary>
/// Medicamento individual
/// </summary>
public class Medicamento : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _nome = string.Empty;
    private string _principioAtivo = string.Empty;
    private string _dosagem = string.Empty;
    private string _frequencia = string.Empty;
    private string _viaAdministracao = "Oral";
    private string _tipoMedicamento = "Livre";
    private DateTime? _dataInicio;
    private DateTime? _dataFim;
    private bool _ativo = true;
    private string _indicacao = string.Empty;
    private string _medicoPrescritor = string.Empty;
    private string _observacoes = string.Empty;

    public string Nome
    {
        get => _nome;
        set { _nome = value; OnPropertyChanged(); }
    }

    public string PrincipioAtivo
    {
        get => _principioAtivo;
        set { _principioAtivo = value; OnPropertyChanged(); }
    }

    public string Dosagem
    {
        get => _dosagem;
        set { _dosagem = value; OnPropertyChanged(); }
    }

    public string Frequencia
    {
        get => _frequencia;
        set { _frequencia = value; OnPropertyChanged(); }
    }

    public string ViaAdministracao
    {
        get => _viaAdministracao;
        set { _viaAdministracao = value; OnPropertyChanged(); }
    }

    public string TipoMedicamento
    {
        get => _tipoMedicamento;
        set { _tipoMedicamento = value; OnPropertyChanged(); }
    }

    public DateTime? DataInicio
    {
        get => _dataInicio;
        set { _dataInicio = value; OnPropertyChanged(); CalcularDuracao(); }
    }

    public DateTime? DataFim
    {
        get => _dataFim;
        set { _dataFim = value; OnPropertyChanged(); CalcularDuracao(); }
    }

    public bool Ativo
    {
        get => _ativo;
        set { _ativo = value; OnPropertyChanged(); }
    }

    public string Indicacao
    {
        get => _indicacao;
        set { _indicacao = value; OnPropertyChanged(); }
    }

    public string MedicoPrescritor
    {
        get => _medicoPrescritor;
        set { _medicoPrescritor = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // PROPRIEDADES CALCULADAS
    public string DuracaoTratamento { get; private set; } = string.Empty;

    private void CalcularDuracao()
    {
        if (DataInicio.HasValue)
        {
            var fim = DataFim ?? DateTime.Today;
            var duracao = fim - DataInicio.Value;
            var dias = duracao.Days;
            
            if (dias < 30)
                DuracaoTratamento = $"{dias} dia(s)";
            else if (dias < 365)
                DuracaoTratamento = $"{dias / 30} mês(es)";
            else
                DuracaoTratamento = $"{dias / 365} ano(s)";
        }
        else
        {
            DuracaoTratamento = "Duração não especificada";
        }
        OnPropertyChanged(nameof(DuracaoTratamento));
    }

    public string MedicamentoCompleto => 
        !string.IsNullOrWhiteSpace(Dosagem) ? $"{Nome} {Dosagem}" : Nome;

    // OPÇÕES
    public static List<string> OpcoesFrequencia => new()
    {
        "1 vez por dia",
        "2 vezes por dia",
        "3 vezes por dia", 
        "4 vezes por dia",
        "De 8/8 horas",
        "De 12/12 horas",
        "SOS (se necessário)",
        "Semanal",
        "Mensal",
        "Outra frequência"
    };

    public static List<string> OpcoesViaAdministracao => new()
    {
        "Oral",
        "Sublingual",
        "Injetável (IM)",
        "Injetável (IV)",
        "Injetável (SC)",
        "Tópica",
        "Inalatória",
        "Retal",
        "Transdérmica",
        "Ocular",
        "Nasal",
        "Vaginal",
        "Outra"
    };

    public static List<string> OpcoesTipo => new()
    {
        "Livre",
        "Com receita médica",
        "Controlado",
        "Genérico",
        "Biológico",
        "Manipulado"
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}

/// <summary>
/// Suplemento individual
/// </summary>
public class Suplemento : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    private string _nome = string.Empty;
    private string _tipo = "Vitamina";
    private string _dosagem = string.Empty;
    private string _frequencia = string.Empty;
    private bool _ativo = true;
    private string _marca = string.Empty;
    private string _motivo = string.Empty;
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

    public string Dosagem
    {
        get => _dosagem;
        set { _dosagem = value; OnPropertyChanged(); }
    }

    public string Frequencia
    {
        get => _frequencia;
        set { _frequencia = value; OnPropertyChanged(); }
    }

    public bool Ativo
    {
        get => _ativo;
        set { _ativo = value; OnPropertyChanged(); }
    }

    public string Marca
    {
        get => _marca;
        set { _marca = value; OnPropertyChanged(); }
    }

    public string Motivo
    {
        get => _motivo;
        set { _motivo = value; OnPropertyChanged(); }
    }

    public string Observacoes
    {
        get => _observacoes;
        set { _observacoes = value; OnPropertyChanged(); }
    }

    // OPÇÕES
    public static List<string> OpcoesTipo => new()
    {
        "Vitamina",
        "Mineral",
        "Probiótico",
        "Enzima",
        "Aminoácido",
        "Ácido gordo",
        "Antioxidante",
        "Fitoterápico",
        "Homeopático",
        "Outro"
    };

    public static List<string> SuplementosComuns => new()
    {
        // VITAMINAS
        "Vitamina D3",
        "Vitamina B12",
        "Complexo B",
        "Vitamina C",
        "Ácido Fólico",
        "Vitamina A",
        "Vitamina E",
        "Vitamina K2",

        // MINERAIS
        "Magnésio",
        "Ferro",
        "Zinco",
        "Cálcio",
        "Potássio",
        "Selénio",
        "Crómio",

        // ÁCIDOS GORDOS
        "Ómega 3",
        "Óleo de peixe",
        "DHA/EPA",

        // PROBIÓTICOS
        "Probiótico (multicepa)",
        "Lactobacillus",
        "Bifidobacterium",

        // OUTROS
        "Coenzima Q10",
        "Melatonina",
        "Colágeno",
        "Glucosamina",
        "Condroitina",
        "MSM",
        "Curcuma",
        "Spirulina",
        "Chlorella"
    };

    protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null)
    {
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
    }
}