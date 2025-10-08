using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Navigation;
using BioDesk.ViewModels;

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

    private void AbrirConfiguracoes_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            _logger?.LogInformation("⚙️ Abrindo janela de Configurações...");

            // Obter o ServiceProvider da App
            var app = Application.Current as App;
            if (app?.ServiceProvider == null)
            {
                MessageBox.Show("Erro ao inicializar serviços", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // Criar a janela de configurações
            var configView = app.ServiceProvider.GetRequiredService<ConfiguracoesView>();
            configView.Owner = Window.GetWindow(this);

            // Mostrar como diálogo modal
            var result = configView.ShowDialog();

            if (result == true)
            {
                _logger?.LogInformation("✅ Configurações guardadas com sucesso");
                MessageBox.Show("Configurações guardadas com sucesso!", "Sucesso", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Erro ao abrir janela de Configurações");
            MessageBox.Show($"Erro ao abrir configurações: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
