using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System.Timers;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using OxyPlot;
using BioDesk.ViewModels.Base;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Dashboard;
using BioDesk.Services.Activity;
using BioDesk.Services.Consultas;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para o Dashboard (ecrã inicial)
/// Caminho de ouro: Dashboard → NovoPaciente(Salvar) → Ficha OU Dashboard → Pesquisa → Lista → SelecionarPaciente → Ficha
/// Comportamentos: SetPacienteAtivo + NavigateTo("FichaPaciente") sempre que confirma seleção/criação
/// </summary>
public partial class DashboardViewModel : NavigationViewModelBase
{
    private readonly ILogger<DashboardViewModel> _logger;
    private readonly IDashboardStatsService _dashboardStatsService;
    private readonly IActivityService _activityService;
    private readonly IConsultaService _consultaService;
    private readonly Timer _relogio;

    [ObservableProperty]
    private string _pesquisarTexto = string.Empty;

    [ObservableProperty]
    private List<Paciente> _pacientesRecentes = new();

    [ObservableProperty]
    private string _statusConexao = "Online";

    [ObservableProperty]
    private string _statusIridoscopio = "Não detectado";

    [ObservableProperty]
    private string _statusOsciloscopio = "Não detectado";

    [ObservableProperty]
    private DateTime _horaAtual = DateTime.Now;

    // 📊 Propriedades dos Gráficos OxyPlot
    [ObservableProperty]
    private PlotModel? _pacientesPorMesChart;

    [ObservableProperty]
    private PlotModel? _distribuicaoIdadeChart;

    [ObservableProperty]
    private DashboardStats? _dashboardStats;

    // 🩺 Propriedades dos Gráficos de Consultas
    [ObservableProperty]
    private PlotModel? _consultasPorSemanaChart;

    [ObservableProperty]
    private PlotModel? _tiposConsultaChart;

    [ObservableProperty]
    private ConsultaStats? _consultaStats;

    [ObservableProperty]
    private bool _carregandoGraficos;

    // 🔔 Propriedades de Atividade Recente
    [ObservableProperty]
    private ObservableCollection<PacienteRecenteItem> _pacientesRecentesItems = new();

    [ObservableProperty]
    private ObservableCollection<AtividadeItem> _atividadeRecente = new();

    [ObservableProperty]
    private EmailStats? _emailStats;

    [ObservableProperty]
    private bool _carregandoAtividade;

    [ObservableProperty]
    private int _selectedTabIndex = 0; // Aba selecionada (0=Atividade, 1=Gráficos, 2=Estatísticas)

    /// <summary>
    /// Data formatada em português europeu
    /// </summary>
    public string DataFormatadaPT => HoraAtual.ToString("dddd, dd/MM/yyyy", new CultureInfo("pt-PT"));

    public DashboardViewModel(
        INavigationService navigationService,
        IPacienteService pacienteService,
        IDashboardStatsService dashboardStatsService,
        IActivityService activityService,
        IConsultaService consultaService,
        ILogger<DashboardViewModel> logger)
        : base(navigationService, pacienteService)
    {
        _logger = logger;
        _dashboardStatsService = dashboardStatsService;
        _activityService = activityService;
        _consultaService = consultaService;

        // Inicia o relógio
        _relogio = new Timer(1000); // Atualiza a cada segundo
        IniciarRelogio();

        // Carrega dados iniciais
        _ = Task.Run(CarregarDashboardAsync);
    }

    /// <summary>
    /// Comando para navegar para criação de novo paciente
    /// </summary>
    [RelayCommand]
    private void NovoPaciente()
    {
        _logger.LogInformation("Preparando criação de novo paciente na ficha");

        var novoPaciente = new Paciente
        {
            Nome = string.Empty,
            Email = string.Empty,
            Telefone = string.Empty,
            DataNascimento = DateTime.Today.AddYears(-30)
        };

        PacienteService.SetPacienteAtivo(novoPaciente);
        NavigationService.NavigateTo("FichaPaciente");
    }

    /// <summary>
    /// Comando para navegar para lista de pacientes
    /// </summary>
    [RelayCommand]
    private void AbrirListaPacientes()
    {
        _logger.LogInformation("Navegando para lista de pacientes");
        NavigationService.NavigateTo("ListaPacientes");
    }

    /// <summary>
    /// Comando para pesquisar pacientes
    /// Enter/clicar → SearchAsync e navega para Lista com filtro aplicado
    /// </summary>
    [RelayCommand]
    private async Task PesquisarAsync()
    {
        if (string.IsNullOrWhiteSpace(PesquisarTexto))
        {
            AbrirListaPacientes();
            return;
        }

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Pesquisando pacientes com termo: {Termo}", PesquisarTexto);
            
            var resultados = await PacienteService.SearchAsync(PesquisarTexto);
            
            if (resultados.Count == 1)
            {
                // Se só há um resultado, navegar diretamente para a ficha
                var paciente = resultados.First();
                PacienteService.SetPacienteAtivo(paciente);
                NavigationService.NavigateTo("FichaPaciente");
            }
            else
            {
                // Múltiplos resultados ou nenhum → navegar para lista com filtro
                NavigationService.NavigateTo("ListaPacientes");
            }
        }, "Erro ao pesquisar pacientes");
    }

    /// <summary>
    /// Comando para selecionar um paciente recente
    /// SetPacienteAtivo → NavigateTo("FichaPaciente")
    /// </summary>
    [RelayCommand]
    private void SelecionarPacienteRecente(Paciente paciente)
    {
        if (paciente == null) return;

        _logger.LogInformation("Selecionando paciente recente: {Nome}", paciente.Nome);
        
        PacienteService.SetPacienteAtivo(paciente);
        NavigationService.NavigateTo("FichaPaciente");
    }

    /// <summary>
    /// Carrega os dados iniciais do dashboard
    /// </summary>
    public async Task CarregarDadosAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Carregando dados do dashboard");
            
            PacientesRecentes = await PacienteService.GetRecentesAsync(5);
            
            _logger.LogInformation("Dashboard carregado - {Quantidade} pacientes recentes", 
                PacientesRecentes.Count);

            // Dashboard fica no dashboard - utilizador escolhe quando navegar
            
        }, "ao carregar dados do dashboard", _logger);
    }

    /// <summary>
    /// Inicia o relógio que atualiza a hora em tempo real
    /// </summary>
    private void IniciarRelogio()
    {
        var timer = new System.Timers.Timer(1000); // 1 segundo
        timer.Elapsed += (s, e) => 
        {
            HoraAtual = DateTime.Now;
            OnPropertyChanged(nameof(DataFormatadaPT));
        };
        timer.Start();
    }

    /// <summary>
    /// Carregar dados do dashboard incluindo gráficos e estatísticas
    /// </summary>
    public async Task CarregarDashboardAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Iniciando carregamento do dashboard com gráficos e atividade");
            
            CarregandoGraficos = true;
            CarregandoAtividade = true;

            try
            {
                // Carregar dados básicos do dashboard
                var todosPacientes = await PacienteService.SearchAsync(string.Empty);
                PacientesRecentes = todosPacientes.Take(5).ToList();

                // Carregar estatísticas
                DashboardStats = await _dashboardStatsService.GetDashboardStatsAsync();
                ConsultaStats = await _consultaService.GetConsultaStatsAsync();

                // Carregar gráficos em paralelo
                var taskPacientesPorMes = _dashboardStatsService.GeneratePacientesPorMesChartAsync();
                var taskDistribuicaoIdade = _dashboardStatsService.GenerateDistribuicaoIdadeChartAsync();
                var taskConsultasPorSemana = _consultaService.GenerateConsultasPorSemanaChartAsync();
                var taskTiposConsulta = _consultaService.GenerateTiposConsultaChartAsync();

                // Carregar atividade recente em paralelo
                var taskPacientesRecentesItems = _activityService.GetPacientesRecentesAsync();
                var taskAtividadeRecente = _activityService.GetAtividadeRecenteAsync();
                var taskEmailStats = _activityService.GetEmailStatsAsync();

                // Aguardar todos os tasks
                PacientesPorMesChart = await taskPacientesPorMes;
                DistribuicaoIdadeChart = await taskDistribuicaoIdade;
                ConsultasPorSemanaChart = await taskConsultasPorSemana;
                TiposConsultaChart = await taskTiposConsulta;

                // Atualizar atividade
                var pacientesRecentesItems = await taskPacientesRecentesItems;
                var atividadeRecente = await taskAtividadeRecente;
                EmailStats = await taskEmailStats;

                // Atualizar ObservableCollections na UI thread
                PacientesRecentesItems.Clear();
                foreach (var item in pacientesRecentesItems)
                {
                    PacientesRecentesItems.Add(item);
                }

                AtividadeRecente.Clear();
                foreach (var item in atividadeRecente)
                {
                    AtividadeRecente.Add(item);
                }

                _logger.LogInformation("Dashboard carregado com {Pacientes} pacientes, 4 gráficos (2 pacientes + 2 consultas), {PacientesRecentes} pacientes recentes e {Atividades} atividades", 
                    PacientesRecentes.Count, PacientesRecentesItems.Count, AtividadeRecente.Count);
            }
            finally
            {
                CarregandoGraficos = false;
                CarregandoAtividade = false;
            }
            
        }, "ao carregar dashboard completo com gráficos", _logger);
    }
}
