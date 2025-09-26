using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels.Base;

/// <summary>
/// Base comum para ViewModels que precisam de navegação
/// Elimina duplicação de código entre DashboardViewModel, ListaPacientesViewModel, etc.
/// Implementa padrão: SetPacienteAtivo + NavigateTo("FichaPaciente")
/// </summary>
public abstract partial class NavigationViewModelBase : ViewModelBase
{
    protected readonly INavigationService NavigationService;
    protected readonly IPacienteService PacienteService;

    protected NavigationViewModelBase(
        INavigationService navigationService,
        IPacienteService pacienteService)
    {
        NavigationService = navigationService;
        PacienteService = pacienteService;
    }

    /// <summary>
    /// Navega para o Dashboard
    /// </summary>
    [RelayCommand]
    protected virtual async Task NavegarParaDashboardAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            NavigationService.NavigateTo("Dashboard");
            await Task.CompletedTask;
        }, "ao navegar para Dashboard");
    }

    /// <summary>
    /// Navega para a lista de pacientes
    /// </summary>
    [RelayCommand]
    protected virtual async Task NavegarParaListaPacientesAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            NavigationService.NavigateTo("ListaPacientes");
            await Task.CompletedTask;
        }, "ao navegar para Lista de Pacientes");
    }

    /// <summary>
    /// Navega para novo paciente
    /// </summary>
    [RelayCommand]
    protected virtual async Task NavegarParaNovoPacienteAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            NavigationService.NavigateTo("FichaPaciente");
            await Task.CompletedTask;
        }, "ao navegar para Novo Paciente");
    }

    /// <summary>
    /// Padrão BioDeskPro2: Define paciente ativo e navega para ficha
    /// SEMPRE usar este método para navegar para ficha de paciente
    /// </summary>
    [RelayCommand]
    protected virtual async Task NavegarParaFichaPacienteAsync(Paciente? paciente)
    {
        if (paciente == null) return;

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            // Padrão BioDeskPro2: SetPacienteAtivo + NavigateTo
            PacienteService.SetPacienteAtivo(paciente);
            NavigationService.NavigateTo("FichaPaciente");
            await Task.CompletedTask;
        }, "ao navegar para Ficha do Paciente");
    }

    /// <summary>
    /// Seleciona paciente e prepara navegação para ficha
    /// </summary>
    protected virtual async Task SelecionarPacienteAsync(Paciente paciente)
    {
        await NavegarParaFichaPacienteAsync(paciente);
    }
}