using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Domain.Entities;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para a Lista de Pacientes
/// Funcionalidades completas: Listar, pesquisar, filtrar, navegar e gerenciar pacientes
/// </summary>
public partial class ListaPacientesViewModel : NavigationViewModelBase
{
    private readonly IPacienteService _pacienteService;

    public ListaPacientesViewModel(IPacienteService pacienteService, INavigationService navigationService)
        : base(navigationService, pacienteService)
    {
        _pacienteService = pacienteService;
        
        // Coleções
        PacientesTodos = new ObservableCollection<PacienteViewModel>();
        PacientesExibicao = new ObservableCollection<PacienteViewModel>();
        
        // Propriedades iniciais
        FiltroSelecionado = "Todos";
        PesquisarTexto = string.Empty;
        
        // Configurar atualização automática da pesquisa
        PropertyChanged += OnPropertyChanged;
    }

    #region Propriedades Observáveis

    [ObservableProperty]
    private string _pesquisarTexto = string.Empty;

    [ObservableProperty]
    private PacienteViewModel? _pacienteSelecionado;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _filtroSelecionado = "Todos";

    [ObservableProperty]
    private int _totalPacientes;

    [ObservableProperty]
    private int _pacientesExibidos;

    #endregion

    #region Coleções

    /// <summary>
    /// Todos os pacientes carregados
    /// </summary>
    public ObservableCollection<PacienteViewModel> PacientesTodos { get; }

    /// <summary>
    /// Pacientes filtrados para exibição no DataGrid
    /// </summary>
    public ObservableCollection<PacienteViewModel> PacientesExibicao { get; }

    #endregion

    #region Comandos

    [RelayCommand]
    private void VoltarDashboard()
    {
        NavigationService.NavigateTo("Dashboard");
    }

    [RelayCommand]
    private async Task AtualizarLista()
    {
        await CarregarDadosAsync();
    }

    [RelayCommand]
    private void NovoPaciente()
    {
        NavigationService.NavigateTo("FichaPaciente");
    }

    [RelayCommand]
    private void VerFicha(PacienteViewModel? pacienteVm)
    {
        if (pacienteVm?.PacienteOriginal == null) return;

        _pacienteService.SetPacienteAtivo(pacienteVm.PacienteOriginal);
        NavigationService.NavigateTo("FichaPaciente");
    }

    [RelayCommand]
    private void EditarPaciente(PacienteViewModel? pacienteVm)
    {
        if (pacienteVm?.PacienteOriginal == null) return;

        _pacienteService.SetPacienteAtivo(pacienteVm.PacienteOriginal);
        NavigationService.NavigateTo("FichaPaciente");
    }

    [RelayCommand]
    private void SelecionarPaciente(PacienteViewModel? pacienteVm)
    {
        PacienteSelecionado = pacienteVm;
    }

    #endregion

    #region Métodos Públicos

    /// <summary>
    /// Carrega todos os pacientes da base de dados
    /// </summary>
    public async Task CarregarDadosAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            
            var pacientes = await _pacienteService.GetTodosAsync();
            
            PacientesTodos.Clear();
            foreach (var paciente in pacientes)
            {
                PacientesTodos.Add(new PacienteViewModel(paciente));
            }
            
            TotalPacientes = PacientesTodos.Count;
            AplicarFiltros();
            
        }, "Erro ao carregar lista de pacientes");
    }

    #endregion

    #region Métodos Privados

    /// <summary>
    /// Aplica filtros à lista de pacientes
    /// </summary>
    private void AplicarFiltros()
    {
        var pacientesFiltrados = PacientesTodos.AsEnumerable();

        // Filtro por texto de pesquisa
        if (!string.IsNullOrWhiteSpace(PesquisarTexto))
        {
            var textoPesquisa = PesquisarTexto.ToLowerInvariant();
            pacientesFiltrados = pacientesFiltrados.Where(p =>
                p.Nome.ToLowerInvariant().Contains(textoPesquisa) ||
                (!string.IsNullOrEmpty(p.Telefone) && p.Telefone.Contains(textoPesquisa)) ||
                (!string.IsNullOrEmpty(p.Email) && p.Email.ToLowerInvariant().Contains(textoPesquisa))
            );
        }

        // Filtro por status
        if (FiltroSelecionado != "Todos")
        {
            pacientesFiltrados = FiltroSelecionado switch
            {
                "Ativo" => pacientesFiltrados.Where(p => p.StatusFormatado == "Ativo"),
                "Inativo" => pacientesFiltrados.Where(p => p.StatusFormatado == "Inativo"),
                "Recentes" => pacientesFiltrados.Where(p => p.PacienteOriginal.CriadoEm >= DateTime.Now.AddDays(-30)),
                _ => pacientesFiltrados
            };
        }

        // Ordenar por nome
        pacientesFiltrados = pacientesFiltrados.OrderBy(p => p.Nome);

        // Atualizar coleção de exibição
        PacientesExibicao.Clear();
        foreach (var paciente in pacientesFiltrados)
        {
            PacientesExibicao.Add(paciente);
        }

        PacientesExibidos = PacientesExibicao.Count;
    }

    /// <summary>
    /// Manipulador para mudanças de propriedades
    /// </summary>
    private void OnPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(PesquisarTexto):
            case nameof(FiltroSelecionado):
                AplicarFiltros();
                break;
        }
    }

    #endregion
}