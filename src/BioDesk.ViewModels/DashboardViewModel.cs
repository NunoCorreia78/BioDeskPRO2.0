using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Services.Navigation;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// DashboardViewModel - Dashboard melhorado com estatísticas e estado do sistema
/// </summary>
public partial class DashboardViewModel : NavigationViewModelBase
{
    private readonly ILogger<DashboardViewModel> _logger;

    [ObservableProperty]
    private string statusMessage = "Sistema BioDeskPro2 ativo";

    [ObservableProperty]
    private bool isSystemActive = true;

    [ObservableProperty]
    private DateTime dataAtual = DateTime.Now;

    public DashboardViewModel(
        INavigationService navigationService,
        ILogger<DashboardViewModel> logger) : base(navigationService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Inicializar data atual sem timer para evitar crashes
        DataAtual = DateTime.Now;

        _logger.LogInformation("DashboardViewModel inicializado com dashboard melhorado");
    }

    [RelayCommand]
    private async Task NovoPaciente()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("🔍 INÍCIO: Comando NovoPaciente executado com ExecuteWithErrorHandlingAsync");
            
            // Debug: Verificar se NavigationService existe
            if (NavigationService == null)
            {
                _logger.LogError("❌ FATAL: NavigationService é NULL!");
                throw new InvalidOperationException("NavigationService não foi injetado corretamente");
            }
            
            _logger.LogInformation("✅ NavigationService existe, tipo: {Type}", NavigationService.GetType().Name);
            
            // Debug: Verificar views registradas
            _logger.LogInformation("🔍 Tentando navegar para 'FichaPaciente'...");
            
            // Navegar (operação síncrona)
            NavigationService.NavigateTo("FichaPaciente");
            
            _logger.LogInformation("✅ NavigateTo('FichaPaciente') executado - aguardando resultado...");
            
            // Aguardar um pouco para ver se o crash acontece após a navegação
            await Task.Delay(100);
            
            _logger.LogInformation("✅ Navegação concluída sem crash imediato");
            
        }, "Navegação para FichaPaciente", _logger);
    }

    [RelayCommand]
    private async Task NavegarParaFicha()
    {
        // Manter compatibilidade com o comando antigo
        await NovoPaciente();
    }
}
