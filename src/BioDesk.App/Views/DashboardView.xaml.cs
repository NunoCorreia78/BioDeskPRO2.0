using System;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Navigation;

namespace BioDesk.App.Views;

/// <summary>
/// DashboardView - Ecrã inicial do BioDeskPro2
/// Layout: Header com status, Pesquisa global, Cards de navegação, Pacientes recentes, Histórico
/// Paleta: Terroso pastel conforme especificações
/// </summary>
public partial class DashboardView : UserControl
{
    private readonly ILogger<DashboardView>? _logger;
    private readonly INavigationService? _navigationService;

    public DashboardView()
    {
        InitializeComponent();
    }

    public DashboardView(ILogger<DashboardView> logger, INavigationService navigationService)
    {
        InitializeComponent();
        _logger = logger;
        _navigationService = navigationService;
    }
}
