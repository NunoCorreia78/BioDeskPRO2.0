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
        // Obter o serviço de navegação através do App.ServiceProvider
        var app = Application.Current as App;
        if (app?.ServiceProvider != null)
        {
            var navigationService = app.ServiceProvider.GetService<INavigationService>();
            navigationService?.NavigateTo("Dashboard");
        }
    }
}