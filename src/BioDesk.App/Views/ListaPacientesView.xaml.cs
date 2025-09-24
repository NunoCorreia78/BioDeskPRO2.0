using System;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using BioDesk.Services.Navigation;

namespace BioDesk.App.Views;

/// <summary>
/// ListaPacientesView - Tela para mostrar lista de pacientes (temporária para demonstração de navegação)
/// </summary>
public partial class ListaPacientesView : UserControl
{
    public ListaPacientesView()
    {
        InitializeComponent();
    }

    private void VoltarDashboard_Click(object sender, RoutedEventArgs e)
    {
        // Obter o serviço de navegação através da janela principal
        var mainWindow = Application.Current.MainWindow as MainWindow;
        if (mainWindow != null)
        {
            var serviceProvider = (IServiceProvider)mainWindow.Tag;
            var navigationService = serviceProvider?.GetService<INavigationService>();
            navigationService?.NavigateTo("Dashboard");
        }
    }
}