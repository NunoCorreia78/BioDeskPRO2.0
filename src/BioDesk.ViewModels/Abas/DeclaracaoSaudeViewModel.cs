using System;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel para Aba 2: Declaração de Saúde
/// Contém todos os dados médicos e histórico do paciente
/// </summary>
public partial class DeclaracaoSaudeViewModel : ObservableValidator
{
    private readonly ILogger<DeclaracaoSaudeViewModel> _logger;

    public DeclaracaoSaudeViewModel(ILogger<DeclaracaoSaudeViewModel> logger)
    {
        _logger = logger;

        // Inicializar coleções
        Cirurgias = new ObservableCollection<Cirurgia>();
        Hospitalizacoes = new ObservableCollection<Hospitalizacao>();
        MedicamentosAtuais = new ObservableCollection<MedicamentoAtual>();
        AlergiasMedicamentosas = new ObservableCollection<AlergiaMedicamentosa>();
        AlergiasAlimentares = new ObservableCollection<AlergiaAlimentar>();
        AlergiasAmbientais = new ObservableCollection<AlergiaAmbiental>();
        IntoleranciasAlimentares = new ObservableCollection<IntoleranciaAlimentar>();
        HistoriaFamiliar = new ObservableCollection<HistoriaFamiliar>();

        // Opções para dropdowns
        OpcoesTabagismo = new[] { "Selecione...", "Nunca fumou", "Ex-fumador", "Fumador atual" };
        OpcoesAlcool = new[] { "Selecione...", "Nunca", "Ocasional", "Regular", "Excessivo" };
        OpcoesExercicio = new[] { "Selecione...", "Sedentário", "Ligeiro", "Moderado", "Intenso" };
        OpcoesDieta = new[] { "Selecione...", "Omnívora", "Vegetariana", "Vegana", "Mediterrânica", "Outras" };
        OpcoesSeveridade = new[] { "Selecione...", "Leve", "Moderada", "Grave" };
        OpcoesStatusFamiliar = new[] { "Selecione...", "Vivo", "Falecido" };

        _logger.LogInformation("DeclaracaoSaudeViewModel inicializado");
    }

    #region === ANTECEDENTES PESSOAIS ===

    // Doenças Crónicas
    [ObservableProperty]
    private bool _temDiabetes;

    [ObservableProperty]
    private bool _temHipertensao;

    [ObservableProperty]
    private bool _temCardiopatias;

    [ObservableProperty]
    private bool _temAlergias;

    [ObservableProperty]
    private bool _temOutrasDoencas;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(MostraEspecificacaoOutras))]
    private string? _especificacaoOutrasDoencas;

    public bool MostraEspecificacaoOutras => TemOutrasDoencas;

    // Suplementação
    [ObservableProperty]
    private string? _suplementosAlimentares;

    [ObservableProperty]
    private string? _medicamentosNaturais;

    // Coleções dinâmicas
    public ObservableCollection<Cirurgia> Cirurgias { get; }
    public ObservableCollection<Hospitalizacao> Hospitalizacoes { get; }
    public ObservableCollection<MedicamentoAtual> MedicamentosAtuais { get; }

    #endregion

    #region === ALERGIAS E INTOLERÂNCIAS ===

    public ObservableCollection<AlergiaMedicamentosa> AlergiasMedicamentosas { get; }
    public ObservableCollection<AlergiaAlimentar> AlergiasAlimentares { get; }
    public ObservableCollection<AlergiaAmbiental> AlergiasAmbientais { get; }
    public ObservableCollection<IntoleranciaAlimentar> IntoleranciasAlimentares { get; }

    #endregion

    #region === ANTECEDENTES FAMILIARES ===

    public ObservableCollection<HistoriaFamiliar> HistoriaFamiliar { get; }

    [ObservableProperty]
    private string? _doencasHereditarias;

    [ObservableProperty]
    private string? _observacoesFamiliares;

    #endregion

    #region === ESTILO DE VIDA ===

    // Hábitos
    [ObservableProperty]
    [Required]
    [NotifyPropertyChangedFor(nameof(MostraDetalheTabagismo))]
    private string _tabagismo = "Selecione...";

    [ObservableProperty]
    private string? _detalheTabagismo;

    public bool MostraDetalheTabagismo => Tabagismo != "Nunca fumou" && Tabagismo != "Selecione...";

    [ObservableProperty]
    [Required]
    [NotifyPropertyChangedFor(nameof(MostraDetalheAlcool))]
    private string _consumoAlcool = "Selecione...";

    [ObservableProperty]
    private string? _detalheAlcool;

    public bool MostraDetalheAlcool => ConsumoAlcool != "Nunca" && ConsumoAlcool != "Selecione...";

    [ObservableProperty]
    [Required]
    [NotifyPropertyChangedFor(nameof(MostraDetalheExercicio))]
    private string _exercicioFisico = "Selecione...";

    [ObservableProperty]
    private string? _detalheExercicio;

    public bool MostraDetalheExercicio => ExercicioFisico != "Sedentário" && ExercicioFisico != "Selecione...";

    [ObservableProperty]
    [Range(4, 12)]
    private int _horasSono = 8;

    [ObservableProperty]
    private string _qualidadeSono = "Boa";

    // Alimentação
    [ObservableProperty]
    [Required]
    private string _tipoDieta = "Selecione...";

    [ObservableProperty]
    private string? _restricaoesAlimentares;

    [ObservableProperty]
    [Range(0.5, 4.0)]
    private decimal _consumoAguaDiario = 1.5m;

    #endregion

    #region === DECLARAÇÃO LEGAL ===

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PodeAvancar))]
    private bool _confirmoVeracidade;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PodeAvancar))]
    private bool _compreendoImportancia;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PodeAvancar))]
    private bool _comprometoInformarAlteracoes;

    [ObservableProperty]
    private string? _observacoesAdicionais;

    public bool PodeAvancar => ConfirmoVeracidade && CompreendoImportancia && ComprometoInformarAlteracoes;

    #endregion

    #region === OPÇÕES PARA DROPDOWNS ===

    public string[] OpcoesTabagismo { get; }
    public string[] OpcoesAlcool { get; }
    public string[] OpcoesExercicio { get; }
    public string[] OpcoesDieta { get; }
    public string[] OpcoesSeveridade { get; }
    public string[] OpcoesStatusFamiliar { get; }

    #endregion

    #region === COMMANDS ===

    [RelayCommand]
    private void AdicionarCirurgia()
    {
        var novaCirurgia = new Cirurgia
        {
            Data = DateTime.Today,
            TipoCirurgia = "",
            Hospital = "",
            Observacoes = ""
        };
        Cirurgias.Add(novaCirurgia);
        _logger.LogInformation("Nova cirurgia adicionada");
    }

    [RelayCommand]
    private void RemoverCirurgia(Cirurgia? cirurgia)
    {
        if (cirurgia != null && Cirurgias.Contains(cirurgia))
        {
            Cirurgias.Remove(cirurgia);
            _logger.LogInformation("Cirurgia removida");
        }
    }

    [RelayCommand]
    private void AdicionarHospitalizacao()
    {
        var novaHospitalizacao = new Hospitalizacao
        {
            Data = DateTime.Today,
            Motivo = "",
            DuracaoDias = 1,
            Hospital = ""
        };
        Hospitalizacoes.Add(novaHospitalizacao);
        _logger.LogInformation("Nova hospitalização adicionada");
    }

    [RelayCommand]
    private void RemoverHospitalizacao(Hospitalizacao? hospitalizacao)
    {
        if (hospitalizacao != null && Hospitalizacoes.Contains(hospitalizacao))
        {
            Hospitalizacoes.Remove(hospitalizacao);
            _logger.LogInformation("Hospitalização removida");
        }
    }

    [RelayCommand]
    private void AdicionarMedicamento()
    {
        var novoMedicamento = new MedicamentoAtual
        {
            Nome = "",
            Dosagem = "",
            Frequencia = "",
            DesdeQuando = DateTime.Today
        };
        MedicamentosAtuais.Add(novoMedicamento);
        _logger.LogInformation("Novo medicamento adicionado");
    }

    [RelayCommand]
    private void RemoverMedicamento(MedicamentoAtual? medicamento)
    {
        if (medicamento != null && MedicamentosAtuais.Contains(medicamento))
        {
            MedicamentosAtuais.Remove(medicamento);
            _logger.LogInformation("Medicamento removido");
        }
    }

    [RelayCommand]
    private void AdicionarAlergiaMedicamentosa()
    {
        var novaAlergia = new AlergiaMedicamentosa
        {
            Medicamento = "",
            Severidade = "Leve",
            Reacao = ""
        };
        AlergiasMedicamentosas.Add(novaAlergia);
        _logger.LogInformation("Nova alergia medicamentosa adicionada");
    }

    [RelayCommand]
    private void RemoverAlergiaMedicamentosa(AlergiaMedicamentosa? alergia)
    {
        if (alergia != null && AlergiasMedicamentosas.Contains(alergia))
        {
            AlergiasMedicamentosas.Remove(alergia);
            _logger.LogInformation("Alergia medicamentosa removida");
        }
    }

    [RelayCommand]
    private void AdicionarAlergiaAlimentar()
    {
        var novaAlergia = new AlergiaAlimentar
        {
            Alimento = "",
            ReacaoConhecida = ""
        };
        AlergiasAlimentares.Add(novaAlergia);
        _logger.LogInformation("Nova alergia alimentar adicionada");
    }

    [RelayCommand]
    private void RemoverAlergiaAlimentar(AlergiaAlimentar? alergia)
    {
        if (alergia != null && AlergiasAlimentares.Contains(alergia))
        {
            AlergiasAlimentares.Remove(alergia);
            _logger.LogInformation("Alergia alimentar removida");
        }
    }

    [RelayCommand]
    private void AdicionarAlergiaAmbiental()
    {
        var novaAlergia = new AlergiaAmbiental
        {
            Alergenio = "",
            Sintomas = ""
        };
        AlergiasAmbientais.Add(novaAlergia);
        _logger.LogInformation("Nova alergia ambiental adicionada");
    }

    [RelayCommand]
    private void RemoverAlergiaAmbiental(AlergiaAmbiental? alergia)
    {
        if (alergia != null && AlergiasAmbientais.Contains(alergia))
        {
            AlergiasAmbientais.Remove(alergia);
            _logger.LogInformation("Alergia ambiental removida");
        }
    }

    [RelayCommand]
    private void AdicionarIntoleranciaAlimentar()
    {
        var novaIntolerancia = new IntoleranciaAlimentar
        {
            Alimento = "",
            Sintomas = ""
        };
        IntoleranciasAlimentares.Add(novaIntolerancia);
        _logger.LogInformation("Nova intolerância alimentar adicionada");
    }

    [RelayCommand]
    private void RemoverIntoleranciaAlimentar(IntoleranciaAlimentar? intolerancia)
    {
        if (intolerancia != null && IntoleranciasAlimentares.Contains(intolerancia))
        {
            IntoleranciasAlimentares.Remove(intolerancia);
            _logger.LogInformation("Intolerância alimentar removida");
        }
    }

    [RelayCommand]
    private void AdicionarHistoriaFamiliar()
    {
        var novaHistoria = new HistoriaFamiliar
        {
            GrauParentesco = "",
            CondicaoDoenca = "",
            IdadeDiagnostico = null,
            Status = "Vivo"
        };
        HistoriaFamiliar.Add(novaHistoria);
        _logger.LogInformation("Nova história familiar adicionada");
    }

    [RelayCommand]
    private void RemoverHistoriaFamiliar(HistoriaFamiliar? historia)
    {
        if (historia != null && HistoriaFamiliar.Contains(historia))
        {
            HistoriaFamiliar.Remove(historia);
            _logger.LogInformation("História familiar removida");
        }
    }

    [RelayCommand]
    private void GuardarRascunho()
    {
        _logger.LogInformation("Guardando rascunho da declaração de saúde");
        // TODO: Implementar salvamento
    }

    [RelayCommand]
    private void ValidarEAvancar()
    {
        if (!PodeAvancar)
        {
            _logger.LogWarning("Tentativa de avançar sem completar declaração legal");
            return;
        }

        _logger.LogInformation("Validação da declaração de saúde passou, avançando para próxima aba");
        // TODO: Implementar navegação para Aba 3
    }

    #endregion
}
