using BioDeskPro.Core.Entities;
using BioDeskPro.Core.Interfaces;
using BioDeskPro.Data.Services;
using System.Collections.ObjectModel;
using System.Windows.Input;

namespace BioDeskPro.UI.ViewModels;

public class FichaPacienteViewModel : BaseViewModel
{
    private readonly IPacienteService _pacienteService;
    private readonly IPacienteContext _pacienteContext;
    private readonly INavigationService _navigationService;
    private readonly IChangeTracker _changeTracker;
    private string _abaAtiva = "VisaoGeral";
    private bool _isLoading;
    
    public FichaPacienteViewModel(
        IPacienteService pacienteService,
        IPacienteContext pacienteContext,
        INavigationService navigationService,
        IChangeTracker changeTracker)
    {
        _pacienteService = pacienteService ?? throw new ArgumentNullException(nameof(pacienteService));
        _pacienteContext = pacienteContext ?? throw new ArgumentNullException(nameof(pacienteContext));
        _navigationService = navigationService ?? throw new ArgumentNullException(nameof(navigationService));
        _changeTracker = changeTracker ?? throw new ArgumentNullException(nameof(changeTracker));
        
        Abas = new ObservableCollection<AbaInfo>();
        InitializeCommands();
        ConfigureAbas();
        
        // Subscribir eventos
        _pacienteContext.PacienteChanged += OnPacienteChanged;
        _changeTracker.DirtyStateChanged += OnDirtyStateChanged;
    }
    
    #region Properties
    
    public Paciente? PacienteAtivo => _pacienteContext.PacienteAtivo;
    
    public string AbaAtiva
    {
        get => _abaAtiva;
        set => SetProperty(ref _abaAtiva, value, OnAbaChanged);
    }
    
    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }
    
    public bool IsDirty => _changeTracker.IsDirty;
    
    public string DirtyIndicator => IsDirty ? "● " : "";
    
    public ObservableCollection<AbaInfo> Abas { get; }
    
    // Propriedades do cabeçalho
    public string NomePaciente => PacienteAtivo?.Nome ?? "Sem paciente selecionado";
    public string IdadePaciente => PacienteAtivo?.IdadeText ?? "";
    public bool HasPacienteAtivo => PacienteAtivo != null;
    
    // Propriedades para controle de visibilidade das abas
    public bool IsDadosBiograficosVisible => HasPacienteAtivo && AbaAtiva == "DadosBiograficos";
    public bool IsOutraAbaVisible => HasPacienteAtivo && AbaAtiva != "DadosBiograficos";
    
    // Propriedades dos Dados Biográficos
    private string _generoSelecionado = string.Empty;
    private string _nifPaciente = string.Empty;
    private string _estadoCivilSelecionado = string.Empty;
    private string _profissaoPaciente = string.Empty;
    private string _telefoneFixo = string.Empty;
    private string _contactoEmergencia = string.Empty;
    private string _moradaPaciente = string.Empty;
    private string _codigoPostal = string.Empty;
    private string _localidadePaciente = string.Empty;
    private string _refereciadoPor = string.Empty;
    private DateTime? _dataPrimeiraConsulta;
    private bool _aceitaComunicacoes;
    
    public string GeneroSelecionado 
    { 
        get => _generoSelecionado; 
        set => SetProperty(ref _generoSelecionado, value); 
    }
    
    public string NifPaciente 
    { 
        get => _nifPaciente; 
        set => SetProperty(ref _nifPaciente, value); 
    }
    
    public string EstadoCivilSelecionado 
    { 
        get => _estadoCivilSelecionado; 
        set => SetProperty(ref _estadoCivilSelecionado, value); 
    }
    
    public string ProfissaoPaciente 
    { 
        get => _profissaoPaciente; 
        set => SetProperty(ref _profissaoPaciente, value); 
    }
    
    public string TelefoneFixo 
    { 
        get => _telefoneFixo; 
        set => SetProperty(ref _telefoneFixo, value); 
    }
    
    public string ContactoEmergencia 
    { 
        get => _contactoEmergencia; 
        set => SetProperty(ref _contactoEmergencia, value); 
    }
    
    public string MoradaPaciente 
    { 
        get => _moradaPaciente; 
        set => SetProperty(ref _moradaPaciente, value); 
    }
    
    public string CodigoPostal 
    { 
        get => _codigoPostal; 
        set => SetProperty(ref _codigoPostal, value); 
    }
    
    public string LocalidadePaciente 
    { 
        get => _localidadePaciente; 
        set => SetProperty(ref _localidadePaciente, value); 
    }
    
    public string RefereciadoPor 
    { 
        get => _refereciadoPor; 
        set => SetProperty(ref _refereciadoPor, value); 
    }
    
    public DateTime? DataPrimeiraConsulta 
    { 
        get => _dataPrimeiraConsulta; 
        set => SetProperty(ref _dataPrimeiraConsulta, value); 
    }
    
    public bool AceitaComunicacoes 
    { 
        get => _aceitaComunicacoes; 
        set => SetProperty(ref _aceitaComunicacoes, value); 
    }
    
    public int CharacterCount => PacienteAtivo?.Observacoes?.Length ?? 0;
    
    #endregion
    
    #region Commands
    
    public ICommand SelecionarAbaCommand { get; private set; } = null!;
    public ICommand GuardarCommand { get; private set; } = null!;
    public ICommand VoltarDashboardCommand { get; private set; } = null!;
    public ICommand NovoEncontroCommand { get; private set; } = null!;
    public ICommand HistoricoCommand { get; private set; } = null!;
    public ICommand NovaCapturaIrisCommand { get; private set; } = null!;
    public ICommand NovaSessaoQuanticaCommand { get; private set; } = null!;
    public ICommand PrescricaoCommand { get; private set; } = null!;
    public ICommand EnviarMensagemCommand { get; private set; } = null!;
    
    #endregion
    
    private void InitializeCommands()
    {
        SelecionarAbaCommand = new RelayCommand<string>(ExecuteSelecionarAba);
        GuardarCommand = new RelayCommand(ExecuteGuardar, CanExecuteGuardar);
        VoltarDashboardCommand = new RelayCommand(ExecuteVoltarDashboard);
        NovoEncontroCommand = new RelayCommand(ExecuteNovoEncontro, CanExecuteWithPaciente);
        HistoricoCommand = new RelayCommand(ExecuteHistorico, CanExecuteWithPaciente);
        NovaCapturaIrisCommand = new RelayCommand(ExecuteNovaCapturaIris, CanExecuteWithPaciente);
        NovaSessaoQuanticaCommand = new RelayCommand(ExecuteNovaSessaoQuantica, CanExecuteWithPaciente);
        PrescricaoCommand = new RelayCommand(ExecutePrescricao, CanExecuteWithPaciente);
        EnviarMensagemCommand = new RelayCommand(ExecuteEnviarMensagem, CanExecuteWithPaciente);
    }
    
    private void ConfigureAbas()
    {
        Abas.Clear();
        
        Abas.Add(new AbaInfo
        {
            Id = "VisaoGeral",
            Nome = "Visão Geral",
            Icone = "📊",
            Descricao = "Timeline e sugestões"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "DadosBiograficos",
            Nome = "Dados Biográficos",
            Icone = "👤",
            Descricao = "Informações pessoais"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "Historico",
            Nome = "Histórico",
            Icone = "📋",
            Descricao = "Consultas e evolução"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "Declaracao",
            Nome = "Declaração & Consentimentos",
            Icone = "📄",
            Descricao = "Documentos legais"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "Iridologia",
            Nome = "Iridologia",
            Icone = "👁️",
            Descricao = "Exames de íris"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "MedicinaQuantica",
            Nome = "Medicina Quântica",
            Icone = "⚡",
            Descricao = "Sessões terapêuticas"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "Documentos",
            Nome = "Documentos",
            Icone = "📁",
            Descricao = "Arquivos e relatórios"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "Mensagens",
            Nome = "Mensagens & Prescrições",
            Icone = "✉️",
            Descricao = "Comunicação e receitas"
        });
        
        Abas.Add(new AbaInfo
        {
            Id = "Conhecimento",
            Nome = "Conhecimento",
            Icone = "📚",
            Descricao = "Base de conhecimento"
        });
    }
    
    #region Event Handlers
    
    private void OnPacienteChanged(object? sender, Paciente? paciente)
    {
        OnPropertyChanged(nameof(PacienteAtivo));
        OnPropertyChanged(nameof(NomePaciente));
        OnPropertyChanged(nameof(IdadePaciente));
        OnPropertyChanged(nameof(HasPacienteAtivo));
        OnPropertyChanged(nameof(IsDadosBiograficosVisible));
        OnPropertyChanged(nameof(IsOutraAbaVisible));
        OnPropertyChanged(nameof(CharacterCount));
        
        // Carregar dados biográficos se houver paciente
        if (paciente != null)
        {
            LoadDadosBiograficos(paciente);
        }
        else
        {
            ClearDadosBiograficos();
        }
        
        // Refresh dos comandos que dependem do paciente
        CommandManager.InvalidateRequerySuggested();
    }
    
    private void OnDirtyStateChanged(object? sender, bool isDirty)
    {
        OnPropertyChanged(nameof(IsDirty));
        OnPropertyChanged(nameof(DirtyIndicator));
        CommandManager.InvalidateRequerySuggested();
    }
    
    private void OnAbaChanged()
    {
        // TODO: Carregar conteúdo específico da aba
        // Por enquanto apenas notificar a mudança
        OnPropertyChanged(nameof(AbaAtiva));
        OnPropertyChanged(nameof(IsDadosBiograficosVisible));
        OnPropertyChanged(nameof(IsOutraAbaVisible));
    }
    
    #endregion
    
    #region Command Implementations
    
    private void ExecuteSelecionarAba(string? abaId)
    {
        if (string.IsNullOrEmpty(abaId)) return;
        
        // Verificar IsDirty antes de mudar aba
        if (IsDirty)
        {
            // TODO: Mostrar modal Guardar/Sair sem guardar/Cancelar
            // Por enquanto, apenas mudar
        }
        
        AbaAtiva = abaId;
    }
    
    private bool CanExecuteGuardar() => IsDirty && HasPacienteAtivo;
    
    private void ExecuteGuardar()
    {
        // TODO: Implementar salvamento baseado na aba ativa
        _changeTracker.MarkClean();
    }
    
    private void ExecuteVoltarDashboard()
    {
        // Verificar IsDirty antes de navegar
        if (IsDirty)
        {
            // TODO: Mostrar modal Guardar/Sair sem guardar/Cancelar
            // Por enquanto, navegar diretamente
        }
        
        // Resetar contexto do paciente
        _pacienteContext.SetPacienteAtivo(null);
        
        // Navegar para dashboard (mostrar DashboardView no Frame)
        _navigationService.NavigateTo("Dashboard");
    }
    
    private bool CanExecuteWithPaciente() => HasPacienteAtivo;
    
    private void ExecuteNovoEncontro()
    {
        // TODO: Implementar criação de novo encontro
    }
    
    private void ExecuteHistorico()
    {
        AbaAtiva = "Historico";
    }
    
    private void ExecuteNovaCapturaIris()
    {
        // TODO: Implementar captura de íris
    }
    
    private void ExecuteNovaSessaoQuantica()
    {
        // TODO: Implementar sessão quântica
    }
    
    private void ExecutePrescricao()
    {
        // TODO: Implementar prescrição
    }
    
    private void ExecuteEnviarMensagem()
    {
        // TODO: Implementar envio de mensagem
    }
    
    #endregion
    
    #region Dados Biográficos
    
    private void LoadDadosBiograficos(Paciente paciente)
    {
        // Aqui carregaríamos dados adicionais do paciente se existissem
        // Por agora, vamos simular alguns dados baseados no que já temos
        
        // Dados que podem vir de campos adicionais no futuro
        GeneroSelecionado = ""; // Será implementado quando expandirmos a entidade Paciente
        NifPaciente = "";
        EstadoCivilSelecionado = "";
        ProfissaoPaciente = "";
        TelefoneFixo = "";
        ContactoEmergencia = "";
        MoradaPaciente = "";
        CodigoPostal = "";
        LocalidadePaciente = "";
        RefereciadoPor = "";
        DataPrimeiraConsulta = null;
        AceitaComunicacoes = false;
        
        // Alguns dados simulados baseados em pacientes existentes
        if (paciente.Nome.Contains("João"))
        {
            GeneroSelecionado = "Masculino";
            EstadoCivilSelecionado = "Casado(a)";
            ProfissaoPaciente = "Engenheiro";
            TelefoneFixo = "213456789";
            ContactoEmergencia = "912345678";
            MoradaPaciente = "Rua das Flores, 123";
            CodigoPostal = "1000-001";
            LocalidadePaciente = "Lisboa";
            RefereciadoPor = "Dr. António Silva";
            DataPrimeiraConsulta = DateTime.Now.AddDays(-30);
            AceitaComunicacoes = true;
        }
        else if (paciente.Nome.Contains("Maria"))
        {
            GeneroSelecionado = "Feminino";
            EstadoCivilSelecionado = "Solteiro(a)";
            ProfissaoPaciente = "Professora";
            TelefoneFixo = "229876543";
            ContactoEmergencia = "963852741";
            MoradaPaciente = "Avenida da República, 456";
            CodigoPostal = "4000-001";
            LocalidadePaciente = "Porto";
            RefereciadoPor = "Amiga Clara";
            DataPrimeiraConsulta = DateTime.Now.AddDays(-15);
            AceitaComunicacoes = true;
        }
        else if (paciente.Nome.Contains("Pedro"))
        {
            GeneroSelecionado = "Masculino";
            EstadoCivilSelecionado = "Divorciado(a)";
            ProfissaoPaciente = "Advogado";
            TelefoneFixo = "244555666";
            ContactoEmergencia = "927183456";
            MoradaPaciente = "Praça do Comércio, 789";
            CodigoPostal = "2000-001";
            LocalidadePaciente = "Santarém";
            RefereciadoPor = "Pesquisa na Internet";
            DataPrimeiraConsulta = DateTime.Now.AddDays(-60);
            AceitaComunicacoes = false;
        }
    }
    
    private void ClearDadosBiograficos()
    {
        GeneroSelecionado = "";
        NifPaciente = "";
        EstadoCivilSelecionado = "";
        ProfissaoPaciente = "";
        TelefoneFixo = "";
        ContactoEmergencia = "";
        MoradaPaciente = "";
        CodigoPostal = "";
        LocalidadePaciente = "";
        RefereciadoPor = "";
        DataPrimeiraConsulta = null;
        AceitaComunicacoes = false;
    }
    
    #endregion
}

public class AbaInfo
{
    public string Id { get; set; } = string.Empty;
    public string Nome { get; set; } = string.Empty;
    public string Icone { get; set; } = string.Empty;
    public string Descricao { get; set; } = string.Empty;
    public bool IsAtiva { get; set; }
}