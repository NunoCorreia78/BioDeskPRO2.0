using System;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.ViewModels.Base;
using BioDesk.Domain.Entities;

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
        
        // Criar um novo paciente vazio para modo de criação
        var novoPaciente = new Paciente
        {
            Id = 0, // ID 0 indica novo paciente
            Nome = string.Empty,
            Email = string.Empty,
            Telefone = null
            // DataNascimento removido conforme solicitado
        };
        
        // Definir como paciente ativo
        PacienteService.SetPacienteAtivo(novoPaciente);
        
        // Navegar imediatamente para FichaPacienteView em modo de criação
        NavigationService.NavigateTo("FichaPaciente");
        
        _logger.LogInformation("NovoPaciente: Redirecionando para FichaPaciente com novo paciente (ID=0)");
    }
}