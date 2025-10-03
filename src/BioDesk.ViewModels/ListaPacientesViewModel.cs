using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Services.Navigation;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para lista/pesquisa de pacientes
/// Permite navegar para ficha de paciente existente
/// </summary>
public partial class ListaPacientesViewModel : NavigationViewModelBase
{
    private readonly ILogger<ListaPacientesViewModel> _logger;
    private readonly IUnitOfWork _unitOfWork;

    [ObservableProperty]
    private ObservableCollection<Paciente> _pacientes = new();

    [ObservableProperty]
    private Paciente? _pacienteSelecionado;

    [ObservableProperty]
    private string _textoPesquisa = string.Empty;

    [ObservableProperty]
    private int _totalPacientes;

    [ObservableProperty]
    private bool _isLoading;

    public ListaPacientesViewModel(
        ILogger<ListaPacientesViewModel> logger,
        INavigationService navigationService,
        IUnitOfWork unitOfWork)
        : base(navigationService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
    }

    /// <summary>
    /// Carregar todos os pacientes ao abrir a view
    /// </summary>
    public async Task OnNavigatedToAsync()
    {
        await CarregarTodosPacientesAsync();
    }

    /// <summary>
    /// Pesquisar pacientes por nome
    /// </summary>
    [RelayCommand]
    private async Task PesquisarAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            _logger.LogInformation("🔍 Pesquisando pacientes: {Termo}", TextoPesquisa);

            if (string.IsNullOrWhiteSpace(TextoPesquisa))
            {
                // Se vazio, carregar todos
                await CarregarTodosPacientesAsync();
            }
            else
            {
                // Pesquisar por nome (já implementado no Repository!)
                var resultados = await _unitOfWork.Pacientes.SearchByNomeAsync(TextoPesquisa);
                Pacientes = new ObservableCollection<Paciente>(resultados);
                TotalPacientes = Pacientes.Count;

                _logger.LogInformation("✅ {Count} pacientes encontrados", TotalPacientes);
            }

            IsLoading = false;
        }, "Erro ao pesquisar pacientes");
    }

    /// <summary>
    /// Carregar TODOS os pacientes ordenados alfabeticamente por nome
    /// </summary>
    private async Task CarregarTodosPacientesAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            _logger.LogInformation("📋 Carregando TODOS os pacientes (ordem alfabética)...");

            var todosPacientes = await _unitOfWork.Pacientes.GetAllOrderedByNomeAsync();
            Pacientes = new ObservableCollection<Paciente>(todosPacientes);
            TotalPacientes = Pacientes.Count;

            _logger.LogInformation("✅ {Count} pacientes carregados (A-Z)", TotalPacientes);

            IsLoading = false;
        }, "Erro ao carregar pacientes");
    }    /// <summary>
    /// Abrir ficha do paciente selecionado
    /// </summary>
    [RelayCommand]
    private void AbrirFichaPaciente(Paciente? paciente)
    {
        if (paciente == null)
        {
            _logger.LogWarning("⚠️ Nenhum paciente selecionado");
            return;
        }

        _logger.LogInformation("📂 Abrindo ficha do paciente: {Nome} (ID {Id})", paciente.NomeCompleto, paciente.Id);

        // ✅ DEFINIR PACIENTE ATIVO (cache global)
        PacienteService.Instance.SetPacienteAtivo(paciente);

        // ✅ NAVEGAR PARA FICHA
        NavigationService.NavigateTo("FichaPaciente");
    }

    /// <summary>
    /// Criar novo paciente (navega para ficha vazia)
    /// </summary>
    [RelayCommand]
    private void NovoPaciente()
    {
        _logger.LogInformation("➕ Criando novo paciente");

        // Limpar paciente ativo
        PacienteService.Instance.SetPacienteAtivo(null);

        // Navegar para ficha (vai criar novo)
        NavigationService.NavigateTo("NovoPaciente");
    }

    /// <summary>
    /// Voltar ao Dashboard
    /// </summary>
    [RelayCommand]
    private void VoltarDashboard()
    {
        NavigationService.NavigateTo("Dashboard");
    }

    /// <summary>
    /// Atualizar lista (refresh)
    /// </summary>
    [RelayCommand]
    private async Task AtualizarAsync()
    {
        TextoPesquisa = string.Empty;
        await CarregarTodosPacientesAsync();
    }
}

/// <summary>
/// Serviço singleton para compartilhar paciente ativo entre ViewModels
/// </summary>
public sealed class PacienteService
{
    private static readonly Lazy<PacienteService> _instance = new(() => new PacienteService());
    public static PacienteService Instance => _instance.Value;

    private Paciente? _pacienteAtivo;

    public Paciente? GetPacienteAtivo() => _pacienteAtivo;

    public void SetPacienteAtivo(Paciente? paciente)
    {
        _pacienteAtivo = paciente;
    }

    private PacienteService() { }
}
