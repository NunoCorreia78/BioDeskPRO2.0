using System;
using System.Collections.ObjectModel;
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
/// Funcionalidades: Listar, pesquisar e navegar para ficha do paciente
/// </summary>
public partial class ListaPacientesViewModel : ViewModelBase
{
    private readonly IPacienteService _pacienteService;
    private readonly INavigationService _navigationService;

    public ListaPacientesViewModel(IPacienteService pacienteService, INavigationService navigationService)
    {
        _pacienteService = pacienteService;
        _navigationService = navigationService;
        
        Pacientes = new ObservableCollection<Paciente>();
        
        // Comandos
        PesquisarCommand = new AsyncRelayCommand(PesquisarAsync);
        SelecionarPacienteCommand = new RelayCommand<Paciente>(SelecionarPaciente);
        NavegarParaFichaCommand = new RelayCommand<Paciente>(NavegarParaFicha);
    }

    [ObservableProperty]
    private string _pesquisarTexto = string.Empty;

    [ObservableProperty]
    private Paciente? _pacienteSelecionado;

    [ObservableProperty]
    private bool _isLoading;

    public ObservableCollection<Paciente> Pacientes { get; }

    public IAsyncRelayCommand PesquisarCommand { get; }
    public IRelayCommand<Paciente> SelecionarPacienteCommand { get; }
    public IRelayCommand<Paciente> NavegarParaFichaCommand { get; }

    /// <summary>
    /// Carrega dados iniciais da lista
    /// </summary>
    public async Task CarregarDadosAsync()
    {
        IsLoading = true;
        try
        {
            var pacientes = await _pacienteService.GetTodosAsync();
            
            Pacientes.Clear();
            foreach (var paciente in pacientes)
            {
                Pacientes.Add(paciente);
            }
        }
        catch (Exception ex)
        {
            // TODO: Implementar tratamento de erro adequado
            System.Diagnostics.Debug.WriteLine($"Erro ao carregar pacientes: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Pesquisa pacientes por nome
    /// </summary>
    private async Task PesquisarAsync()
    {
        if (string.IsNullOrWhiteSpace(PesquisarTexto))
        {
            await CarregarDadosAsync();
            return;
        }

        IsLoading = true;
        try
        {
            var pacientes = await _pacienteService.SearchAsync(PesquisarTexto);
            
            Pacientes.Clear();
            foreach (var paciente in pacientes)
            {
                Pacientes.Add(paciente);
            }
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Erro ao pesquisar pacientes: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Seleciona um paciente da lista
    /// </summary>
    private void SelecionarPaciente(Paciente? paciente)
    {
        PacienteSelecionado = paciente;
    }

    /// <summary>
    /// Navega para a ficha do paciente selecionado
    /// </summary>
    private void NavegarParaFicha(Paciente? paciente)
    {
        if (paciente == null) return;

        // Definir paciente ativo no serviço de pacientes
        _pacienteService.SetPacienteAtivo(paciente);
        
        // Navegar para a ficha
        _navigationService.NavigateTo("FichaPaciente");
    }
}