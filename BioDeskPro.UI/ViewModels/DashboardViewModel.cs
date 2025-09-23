using BioDeskPro.Core.Entities;
using BioDeskPro.Core.Interfaces;
using BioDeskPro.UI.Services;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;

namespace BioDeskPro.UI.ViewModels;

public class DashboardViewModel : BaseViewModel
{
    private readonly IPacienteContext _pacienteContext;
    private readonly IDialogService _dialogService;
    private readonly INavigationService _navigationService;
    private readonly IChangeTracker _changeTracker;
    private string _searchText = string.Empty;
    private bool _isLoading;
    private string _statusMessage = "Sistema inicializado";
    
    public DashboardViewModel(
        IPacienteContext pacienteContext,
        IDialogService dialogService,
        INavigationService navigationService,
        IChangeTracker changeTracker)
    {
        _pacienteContext = pacienteContext ?? throw new ArgumentNullException(nameof(pacienteContext));
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
        _navigationService = navigationService ?? throw new ArgumentNullException(nameof(navigationService));
        _changeTracker = changeTracker ?? throw new ArgumentNullException(nameof(changeTracker));
        
        PacientesRecentes = new ObservableCollection<Paciente>();
        AcoesRapidas = new ObservableCollection<AcaoRapida>();
        
        InitializeCommands();
        LoadInitialData();
        
        // Subscribir eventos do ChangeTracker
        _changeTracker.DirtyStateChanged += OnDirtyStateChanged;
    }
    
    #region Properties
    
    public string SearchText
    {
        get => _searchText;
        set => SetProperty(ref _searchText, value, OnSearchTextChanged);
    }
    
    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }
    
    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }
    
    public ObservableCollection<Paciente> PacientesRecentes { get; }
    
    public ObservableCollection<AcaoRapida> AcoesRapidas { get; }
    
    public string? PacienteAtivoNome => _pacienteContext.PacienteAtivo?.Nome;
    
    public bool HasPacienteAtivo => _pacienteContext.HasPacienteAtivo;
    
    public bool IsDirty => _changeTracker.IsDirty;
    
    public string DirtyIndicator => IsDirty ? "●" : "";
    
    #endregion
    
    #region Commands
    
    public ICommand SearchCommand { get; private set; } = null!;
    public ICommand NovoPacienteCommand { get; private set; } = null!;
    public ICommand ListaPacientesCommand { get; private set; } = null!;
    public ICommand SelecionarPacienteCommand { get; private set; } = null!;
    public ICommand NovoEncontroCommand { get; private set; } = null!;
    public ICommand VerHistoricoCommand { get; private set; } = null!;
    public ICommand ConfiguracoesCommand { get; private set; } = null!;
    public ICommand SairCommand { get; private set; } = null!;
    public ICommand TestDirtyCommand { get; private set; } = null!;
    public ICommand SaveChangesCommand { get; private set; } = null!;
    
    #endregion
    
    private void InitializeCommands()
    {
        SearchCommand = new RelayCommand(ExecuteSearch, CanExecuteSearch);
        NovoPacienteCommand = new RelayCommand(ExecuteNovoPaciente);
        ListaPacientesCommand = new RelayCommand(ExecuteListaPacientes);
        SelecionarPacienteCommand = new RelayCommand<Paciente>(ExecuteSelecionarPaciente);
        NovoEncontroCommand = new RelayCommand(ExecuteNovoEncontro, CanExecuteNovoEncontro);
        VerHistoricoCommand = new RelayCommand(ExecuteVerHistorico, CanExecuteVerHistorico);
        ConfiguracoesCommand = new RelayCommand(ExecuteConfiguracoes);
        SairCommand = new RelayCommand(ExecuteSair);
        TestDirtyCommand = new RelayCommand(ExecuteTestDirty);
        SaveChangesCommand = new RelayCommand(ExecuteSaveChanges, CanExecuteSaveChanges);
        
        // Subscribir eventos do contexto de paciente
        _pacienteContext.PacienteChanged += OnPacienteContextChanged;
    }
    
    private void LoadInitialData()
    {
        // Carregar pacientes recentes (dados fake por enquanto)
        LoadPacientesRecentes();
        
        // Configurar ações rápidas
        ConfigureAcoesRapidas();
        
        StatusMessage = "Pronto";
    }
    
    private void LoadPacientesRecentes()
    {
        // Dados fake para demonstração
        PacientesRecentes.Clear();
        
        var pacientesFake = new[]
        {
            new Paciente { Id = 1, Nome = "João Silva", NumeroUtente = "123456789", CreatedAt = DateTime.Now.AddDays(-5) },
            new Paciente { Id = 2, Nome = "Maria Santos", NumeroUtente = "987654321", CreatedAt = DateTime.Now.AddDays(-3) },
            new Paciente { Id = 3, Nome = "Pedro Oliveira", NumeroUtente = "456789123", CreatedAt = DateTime.Now.AddDays(-1) }
        };
        
        foreach (var paciente in pacientesFake)
        {
            PacientesRecentes.Add(paciente);
        }
    }
    
    private void ConfigureAcoesRapidas()
    {
        AcoesRapidas.Clear();
        
        AcoesRapidas.Add(new AcaoRapida
        {
            Titulo = "Novo Paciente",
            Descricao = "Registrar novo paciente",
            Icone = "👤",
            Command = NovoPacienteCommand,
            Cor = "#2E8B57"
        });
        
        AcoesRapidas.Add(new AcaoRapida
        {
            Titulo = "Lista de Pacientes",
            Descricao = "Ver todos os pacientes",
            Icone = "📋",
            Command = ListaPacientesCommand,
            Cor = "#4A90E2"
        });
        
        AcoesRapidas.Add(new AcaoRapida
        {
            Titulo = "Nova Consulta",
            Descricao = "Iniciar nova consulta",
            Icone = "🩺",
            Command = NovoEncontroCommand,
            Cor = "#4682B4",
            RequeresPaciente = true
        });
        
        AcoesRapidas.Add(new AcaoRapida
        {
            Titulo = "Iridologia",
            Descricao = "Exame de íris",
            Icone = "👁️",
            Command = new RelayCommand(() => _dialogService.ShowInfo("Funcionalidade em desenvolvimento")),
            Cor = "#9370DB",
            RequeresPaciente = true
        });
        
        AcoesRapidas.Add(new AcaoRapida
        {
            Titulo = "Terapia Quântica",
            Descricao = "Sessão de terapia",
            Icone = "⚡",
            Command = new RelayCommand(() => _dialogService.ShowInfo("Funcionalidade em desenvolvimento")),
            Cor = "#FF6347",
            RequeresPaciente = true
        });
        
        // Ações de teste para demonstrar IsDirty
        AcoesRapidas.Add(new AcaoRapida
        {
            Titulo = "Teste IsDirty",
            Descricao = "Marcar como alterado",
            Icone = "🧪",
            Command = TestDirtyCommand,
            Cor = "#FFA500"
        });
        
        AcoesRapidas.Add(new AcaoRapida
        {
            Titulo = "Guardar",
            Descricao = "Guardar alterações",
            Icone = "💾",
            Command = SaveChangesCommand,
            Cor = "#32CD32"
        });
    }
    
    #region Command Implementations
    
    private bool CanExecuteSearch() => !string.IsNullOrWhiteSpace(SearchText);
    
    private void ExecuteSearch()
    {
        StatusMessage = $"A pesquisar por: {SearchText}";
        
        // TODO: Implementar pesquisa real na base de dados
        _dialogService.ShowInfo($"Pesquisa por '{SearchText}' será implementada em breve.", "Pesquisa");
    }
    
    private void ExecuteNovoPaciente()
    {
        StatusMessage = "A navegar para formulário de novo paciente...";
        
        // Debug detalhado
        Console.WriteLine("🔥 DEBUG: ExecuteNovoPaciente chamado");
        DebugLogger.LogDebug("ExecuteNovoPaciente chamado");
        Console.WriteLine($"🔥 DEBUG: NavigationService é null? {_navigationService == null}");
        DebugLogger.LogDebug($"NavigationService é null? {_navigationService == null}");
        
        try
        {
            Console.WriteLine("🔥 DEBUG: Chamando NavigateTo('NovoPaciente')");
            DebugLogger.LogDebug("Chamando NavigateTo('NovoPaciente')");
            _navigationService?.NavigateTo("NovoPaciente");
            Console.WriteLine("🔥 DEBUG: NavigateTo executado com sucesso");
            DebugLogger.LogInfo("NavigateTo executado com sucesso");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"🔥 DEBUG: ERRO ao navegar: {ex.Message}");
            DebugLogger.LogError($"Erro ao navegar: {ex.Message}", ex);
            _dialogService.ShowError($"Erro ao navegar: {ex.Message}", "Erro de Navegação");
        }
    }
    
    private void ExecuteListaPacientes()
    {
        StatusMessage = "A navegar para lista de pacientes...";
        
        // Debug detalhado
        DebugLogger.LogDebug("ExecuteListaPacientes chamado");
        DebugLogger.LogDebug($"NavigationService é null? {_navigationService == null}");
        
        try
        {
            DebugLogger.LogDebug("Chamando NavigateTo('ListaPacientes')");
            _navigationService?.NavigateTo("ListaPacientes");
            DebugLogger.LogInfo("NavigateTo executado com sucesso");
        }
        catch (Exception ex)
        {
            DebugLogger.LogError($"Erro ao navegar: {ex.Message}", ex);
            _dialogService.ShowError($"Erro ao navegar: {ex.Message}", "Erro de Navegação");
        }
    }
    
    private void ExecuteSelecionarPaciente(Paciente? paciente)
    {
        if (paciente == null) return;
        
        _pacienteContext.SetPacienteAtivo(paciente);
        StatusMessage = $"Paciente ativo: {paciente.Nome}";
    }
    
    private bool CanExecuteNovoEncontro() => _pacienteContext.HasPacienteAtivo;
    
    private void ExecuteNovoEncontro()
    {
        if (!_pacienteContext.HasPacienteAtivo)
        {
            _dialogService.ShowWarning("Selecione um paciente primeiro.", "Novo Encontro");
            return;
        }
        
        StatusMessage = $"A iniciar novo encontro para {_pacienteContext.PacienteAtivo!.Nome}...";
        
        // TODO: Navegar para formulário de novo encontro
        _dialogService.ShowInfo("Formulário de novo encontro será implementado em breve.", "Novo Encontro");
    }
    
    private bool CanExecuteVerHistorico() => _pacienteContext.HasPacienteAtivo;
    
    private void ExecuteVerHistorico()
    {
        if (!_pacienteContext.HasPacienteAtivo)
        {
            _dialogService.ShowWarning("Selecione um paciente primeiro.", "Histórico");
            return;
        }
        
        StatusMessage = $"A abrir histórico de {_pacienteContext.PacienteAtivo!.Nome}...";
        
        // TODO: Navegar para histórico do paciente
        _dialogService.ShowInfo("Histórico do paciente será implementado em breve.", "Histórico");
    }
    
    private void ExecuteConfiguracoes()
    {
        StatusMessage = "A abrir configurações...";
        
        // TODO: Navegar para configurações
        _dialogService.ShowInfo("Configurações serão implementadas em breve.", "Configurações");
    }
    
    private void ExecuteSair()
    {
        // O NavigationService já tem o guard de IsDirty integrado
        var result = _dialogService.ShowConfirmation("Tem certeza de que deseja sair?", "Sair");
        
        if (result == DialogResult.Yes)
        {
            // Se há alterações, perguntar antes de sair
            if (_changeTracker.IsDirty)
            {
                var saveResult = _dialogService.ShowSaveChangesDialog();
                
                switch (saveResult)
                {
                    case DialogResult.Save:
                        // TODO: Implementar guardar alterações
                        StatusMessage = "Alterações guardadas";
                        _changeTracker.MarkClean();
                        break;
                    
                    case DialogResult.DontSave:
                        // Descartar alterações
                        _changeTracker.MarkClean();
                        break;
                    
                    case DialogResult.Cancel:
                        return; // Cancelar saída
                }
            }
            
            Application.Current.Shutdown();
        }
    }
    
    private void ExecuteTestDirty()
    {
        // Comando para testar o sistema IsDirty
        _changeTracker.MarkDirty();
        StatusMessage = "Sistema marcado como dirty para teste";
    }
    
    private bool CanExecuteSaveChanges() => _changeTracker.IsDirty;
    
    private void ExecuteSaveChanges()
    {
        // TODO: Implementar lógica real de guardar
        _changeTracker.MarkClean();
        StatusMessage = "Alterações guardadas com sucesso";
    }
    
    #endregion
    
    #region Event Handlers
    
    private void OnSearchTextChanged()
    {
        // Notificar que o comando de pesquisa pode ter mudado
        ((RelayCommand)SearchCommand).RaiseCanExecuteChanged();
    }
    
    private void OnPacienteContextChanged(object? sender, Paciente? paciente)
    {
        OnPropertyChanged(nameof(PacienteAtivoNome));
        OnPropertyChanged(nameof(HasPacienteAtivo));
        
        // Atualizar disponibilidade de comandos
        ((RelayCommand)NovoEncontroCommand).RaiseCanExecuteChanged();
        ((RelayCommand)VerHistoricoCommand).RaiseCanExecuteChanged();
        
        // Atualizar ações rápidas
        foreach (var acao in AcoesRapidas.Where(a => a.RequeresPaciente))
        {
            acao.IsEnabled = HasPacienteAtivo;
        }
    }
    
    private void OnDirtyStateChanged(object? sender, bool isDirty)
    {
        OnPropertyChanged(nameof(IsDirty));
        OnPropertyChanged(nameof(DirtyIndicator));
        ((RelayCommand)SaveChangesCommand).RaiseCanExecuteChanged();
        
        StatusMessage = isDirty ? "Existem alterações não guardadas" : "Todas as alterações foram guardadas";
    }
    
    #endregion
}

public class AcaoRapida : BaseViewModel
{
    private bool _isEnabled = true;
    
    public string Titulo { get; set; } = string.Empty;
    public string Descricao { get; set; } = string.Empty;
    public string Icone { get; set; } = string.Empty;
    public string Cor { get; set; } = "#2E8B57";
    public ICommand? Command { get; set; }
    public bool RequeresPaciente { get; set; }
    
    public bool IsEnabled
    {
        get => _isEnabled;
        set => SetProperty(ref _isEnabled, value);
    }
}