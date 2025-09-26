using Microsoft.Extensions.Logging;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para criação de novos pacientes.
/// Redireciona para FichaPacienteView para manter consistência da interface.
/// </summary>
public class NovoPacienteViewModel : NavigationViewModelBase
{
    private readonly ILogger<NovoPacienteViewModel> _logger;

    public NovoPacienteViewModel(
        INavigationService navigationService,
        IPacienteService pacienteService,
        ILogger<NovoPacienteViewModel> logger)
        : base(navigationService, pacienteService)
    {
        _logger = logger;
        
        // Limpar paciente ativo ao criar novo (usando default! para evitar warning nullable)
        PacienteService.SetPacienteAtivo(default!);
        
        // Navegar imediatamente para FichaPacienteView em modo de criação
        NavigationService.NavigateTo("FichaPaciente");
        
        _logger.LogInformation("NovoPaciente: Redirecionando para FichaPaciente em modo criação");
    }
}