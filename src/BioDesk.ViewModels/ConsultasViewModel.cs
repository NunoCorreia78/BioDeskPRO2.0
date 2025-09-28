using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Services.Consultas;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para gestão completa de consultas
/// Permite agendar, listar, editar e cancelar consultas
/// </summary>
public partial class ConsultasViewModel : NavigationViewModelBase
{
    private readonly IConsultaService _consultaService;
    private readonly ILogger<ConsultasViewModel> _logger;

    [ObservableProperty]
    private List<Consulta> _consultas = new();

    [ObservableProperty]
    private List<Consulta> _consultasProximas = new();

    [ObservableProperty]
    private Consulta? _consultaSelecionada;

    [ObservableProperty]
    private Consulta _novaConsulta = new();

    [ObservableProperty]
    private bool _mostrarDialogoNovaConsulta;

    [ObservableProperty]
    private string _filtroData = "Todas";

    [ObservableProperty]
    private string _filtroStatus = "Todas";

    [ObservableProperty]
    private DateTime _dataInicio = DateTime.Today;

    [ObservableProperty]
    private DateTime _dataFim = DateTime.Today.AddDays(30);

    [ObservableProperty]
    private List<Paciente> _pacientesDisponiveis = new();

    public List<string> TiposConsulta { get; } = new() { "Primeira", "Seguimento", "Revisão", "Urgente" };
    public List<string> StatusConsulta { get; } = new() { "Agendada", "Realizada", "Cancelada", "Faltou" };

    public ConsultasViewModel(
        INavigationService navigationService,
        IPacienteService pacienteService,
        IConsultaService consultaService,
        ILogger<ConsultasViewModel> logger) : base(navigationService, pacienteService)
    {
        _consultaService = consultaService;
        _logger = logger;
        
        // Inicializar nova consulta
        ResetarNovaConsulta();
    }

    /// <summary>
    /// Carrega consultas com filtros aplicados
    /// </summary>
    [RelayCommand]
    private async Task CarregarConsultasAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var todasConsultas = await _consultaService.ObterConsultasAsync();
            
            // Aplicar filtros
            var consultasFiltradas = todasConsultas.Where(c =>
            {
                // Filtro por data
                bool passaFiltroData = FiltroData switch
                {
                    "Hoje" => c.DataConsulta.Date == DateTime.Today,
                    "Esta Semana" => c.DataConsulta >= DateTime.Today && c.DataConsulta <= DateTime.Today.AddDays(7),
                    "Este Mês" => c.DataConsulta.Month == DateTime.Today.Month && c.DataConsulta.Year == DateTime.Today.Year,
                    "Personalizado" => c.DataConsulta.Date >= DataInicio.Date && c.DataConsulta.Date <= DataFim.Date,
                    _ => true
                };

                // Filtro por status
                bool passaFiltroStatus = FiltroStatus == "Todas" || c.Status == FiltroStatus;

                return passaFiltroData && passaFiltroStatus;
            }).OrderBy(c => c.DataConsulta).ToList();

            Consultas = consultasFiltradas;
            
            // Consultas próximas (próximos 7 dias)
            ConsultasProximas = consultasFiltradas
                .Where(c => c.DataConsulta >= DateTime.Today && 
                           c.DataConsulta <= DateTime.Today.AddDays(7) &&
                           c.Status == "Agendada")
                .Take(5)
                .ToList();

            _logger.LogInformation("Carregadas {Count} consultas", consultasFiltradas.Count);
        }, "ao carregar consultas");
    }

    /// <summary>
    /// Abre diálogo para nova consulta
    /// </summary>
    [RelayCommand]
    private async Task AbrirNovaConsultaAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            // Carregar pacientes disponíveis
            var pacientes = await PacienteService.GetRecentesAsync();
            PacientesDisponiveis = pacientes.ToList();

            ResetarNovaConsulta();
            MostrarDialogoNovaConsulta = true;
        }, "ao abrir diálogo de nova consulta");
    }

    /// <summary>
    /// Grava nova consulta
    /// </summary>
    [RelayCommand]
    private async Task GravarConsultaAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (!ValidarConsulta(NovaConsulta))
                return;

            var consultaCriada = await _consultaService.CriarConsultaAsync(NovaConsulta);
            
            MostrarDialogoNovaConsulta = false;
            await CarregarConsultasAsync();
            
            _logger.LogInformation("Consulta criada com sucesso: {Id}", consultaCriada.Id);
        }, "ao criar nova consulta");
    }

    /// <summary>
    /// Cancela criação de consulta
    /// </summary>
    [RelayCommand]
    private void CancelarNovaConsulta()
    {
        MostrarDialogoNovaConsulta = false;
        ResetarNovaConsulta();
    }

    /// <summary>
    /// Marca consulta como realizada
    /// </summary>
    [RelayCommand]
    private async Task MarcarComoRealizadaAsync(Consulta? consulta)
    {
        if (consulta == null) return;

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            consulta.Status = "Realizada";
            await _consultaService.AtualizarConsultaAsync(consulta);
            await CarregarConsultasAsync();
            
            _logger.LogInformation("Consulta {Id} marcada como realizada", consulta.Id);
        }, "ao marcar consulta como realizada");
    }

    /// <summary>
    /// Cancela consulta
    /// </summary>
    [RelayCommand]
    private async Task CancelarConsultaAsync(Consulta? consulta)
    {
        if (consulta == null) return;

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            consulta.Status = "Cancelada";
            await _consultaService.AtualizarConsultaAsync(consulta);
            await CarregarConsultasAsync();
            
            _logger.LogInformation("Consulta {Id} cancelada", consulta.Id);
        }, "ao cancelar consulta");
    }

    /// <summary>
    /// Navega para ficha do paciente da consulta
    /// </summary>
    [RelayCommand]
    private async Task VerPacienteAsync(Consulta? consulta)
    {
        if (consulta?.Paciente == null) return;

        await NavegarParaFichaPacienteAsync(consulta.Paciente);
    }

    /// <summary>
    /// Inicia fluxo para criação de um novo paciente a partir da área de consultas
    /// </summary>
    [RelayCommand]
    private async Task NovoPacienteAsync()
    {
        await ExecuteWithErrorHandlingAsync(() =>
        {
            var novoPaciente = new Paciente
            {
                Id = 0,
                Nome = string.Empty,
                Email = string.Empty,
                Telefone = string.Empty,
                CriadoEm = DateTime.Now
            };

            PacienteService.SetPacienteAtivo(novoPaciente);
            NavigationService.NavigateTo("FichaPaciente");

            _logger.LogInformation("Novo paciente iniciado a partir de Consultas");

            return Task.CompletedTask;
        }, "ao iniciar criação de novo paciente a partir de Consultas");
    }

    /// <summary>
    /// Aplica filtros às consultas
    /// </summary>
    [RelayCommand]
    private async Task AplicarFiltrosAsync()
    {
        await CarregarConsultasAsync();
    }

    /// <summary>
    /// Inicialização do ViewModel
    /// </summary>
    public async Task InicializarAsync()
    {
        await CarregarConsultasAsync();
    }

    private void ResetarNovaConsulta()
    {
        NovaConsulta = new Consulta
        {
            DataConsulta = DateTime.Today.AddHours(9), // 9:00 por defeito
            TipoConsulta = "Primeira",
            Status = "Agendada"
        };
    }

    private bool ValidarConsulta(Consulta consulta)
    {
        if (consulta.PacienteId <= 0)
        {
            ErrorMessage = "Deve selecionar um paciente para a consulta";
            return false;
        }

        if (consulta.DataConsulta < DateTime.Now.AddMinutes(-5))
        {
            ErrorMessage = "A data da consulta não pode ser no passado";
            return false;
        }

        if (string.IsNullOrWhiteSpace(consulta.TipoConsulta))
        {
            ErrorMessage = "Deve selecionar o tipo de consulta";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Carrega os dados iniciais da view de consultas
    /// </summary>
    public async Task CarregarDadosAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            ErrorMessage = string.Empty;

            // Carregar consultas do mês atual por padrão
            var dataInicio = DateTime.Today.AddDays(1 - DateTime.Today.Day);
            var dataFim = dataInicio.AddMonths(1).AddDays(-1);

            var todasConsultas = await _consultaService.ObterConsultasAsync(dataInicio, dataFim);
            Consultas = todasConsultas.ToList();

            // Carregar próximas consultas (próximos 7 dias)
            var proximasConsultas = await _consultaService.ObterConsultasAsync(DateTime.Today, DateTime.Today.AddDays(7));
            ConsultasProximas = proximasConsultas
                .Where(c => c.Status == "Agendada")
                .OrderBy(c => c.DataConsulta)
                .Take(5)
                .ToList();

            _logger.LogInformation($"📅 Dados de consultas carregados - {Consultas.Count} consultas, {ConsultasProximas.Count} próximas");
        });
    }
}