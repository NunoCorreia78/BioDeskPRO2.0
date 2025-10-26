using System;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Services.Navigation;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel para Aba 2: Declaração de Saúde
/// Contém todos os dados médicos e histórico do paciente
/// </summary>
public partial class DeclaracaoSaudeViewModel : ObservableValidator
{
    private readonly ILogger<DeclaracaoSaudeViewModel> _logger;
    private readonly IUnitOfWork? _unitOfWork;
    private readonly INavigationService? _navigationService;

    [ObservableProperty] private Paciente? _pacienteAtual;

    public DeclaracaoSaudeViewModel(
        ILogger<DeclaracaoSaudeViewModel> logger,
        IUnitOfWork? unitOfWork = null,
        INavigationService? navigationService = null)
    {
        _logger = logger;
        _unitOfWork = unitOfWork;
        _navigationService = navigationService;

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
        OpcoesQualidadeSono = new ObservableCollection<string> { "Selecione...", "Boa", "Razoável", "Má", "Insónia" };  // ✅ ObservableCollection
        OpcoesSeveridade = new ObservableCollection<string> { "Selecione...", "Leve", "Moderada", "Grave", "Muito Grave" };  // ✅ ObservableCollection
        OpcoesStatusFamiliar = new ObservableCollection<string> { "Selecione...", "Ativo", "Controlado", "Em Remissão", "Curado", "Desconhecido" };  // ✅ ObservableCollection

        _logger.LogInformation("DeclaracaoSaudeViewModel inicializado");
    }

    #region === DADOS DO PACIENTE ===

    /// <summary>
    /// Nome do paciente para exibição na declaração
    /// </summary>
    [ObservableProperty]
    private string _nomePaciente = string.Empty;

    /// <summary>
    /// Define o nome do paciente (chamado pelo FichaPacienteView quando paciente muda)
    /// </summary>
    public void SetPacienteNome(string nome)
    {
        NomePaciente = nome;
        _logger.LogInformation("👤 Nome do paciente atualizado na Declaração: {Nome}", nome);
    }

    #endregion

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
    [NotifyPropertyChangedFor(nameof(MostraEspecificacaoOutras))]
    private bool _temOutrasDoencas;

    [ObservableProperty]
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
    public ObservableCollection<string> OpcoesQualidadeSono { get; }  // ✅ ObservableCollection
    public ObservableCollection<string> OpcoesSeveridade { get; }  // ✅ ObservableCollection
    public ObservableCollection<string> OpcoesStatusFamiliar { get; }  // ✅ ObservableCollection

    #endregion

    #region === COMMANDS ===

    [RelayCommand]
    private void AdicionarCirurgia()
    {
        var novaCirurgia = new Cirurgia
        {
            Data = default(DateTime), // ✅ CORRIGIDO: Campo vazio por padrão (01/01/0001)
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
            Data = default(DateTime), // ✅ CORRIGIDO: Campo vazio por padrão (01/01/0001)
            Motivo = "",
            DuracaoDias = 0, // ✅ CORRIGIDO: 0 dias por padrão
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
            DesdeQuando = default(DateTime) // ✅ CORRIGIDO: Campo vazio por padrão (01/01/0001)
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
    private async Task GuardarRascunho()
    {
        _logger.LogInformation("💾 Guardando rascunho da declaração de saúde");

        if (PacienteAtual != null && _unitOfWork != null)
        {
            try
            {
                // Rascunho salvo automaticamente via ObservableProperties
                // DeclaracaoSaude já é persistida via FichaPacienteViewModel
                await _unitOfWork.SaveChangesAsync();
                _logger.LogInformation("✅ Rascunho da declaração de saúde guardado");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao guardar rascunho da declaração de saúde");
            }
        }
        else
        {
            _logger.LogWarning("⚠️ Não foi possível guardar rascunho: PacienteAtual ou UnitOfWork é null");
        }
    }

    [RelayCommand]
    private void ValidarEAvancar()
    {
        if (!PodeAvancar)
        {
            _logger.LogWarning("⚠️ Tentativa de avançar sem completar declaração legal");
            return;
        }

        _logger.LogInformation("✅ Validação da declaração de saúde passou, avançando para Aba 3 (Consentimentos)");

        // ✅ NAVEGAR PARA ABA 3 (CONSENTIMENTOS)
        if (_navigationService != null)
        {
            // Informar ao FichaPacienteViewModel para mudar para aba 3
            // TODO: Implementar sistema de mensageria ou callback para mudar aba
            _logger.LogInformation("🔄 Navegação para Aba 3 solicitada");
        }
    }

    #endregion
}
