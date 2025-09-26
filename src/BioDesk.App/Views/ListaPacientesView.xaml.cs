using System;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Extensions.DependencyInjection;
using BioDesk.ViewModels;

namespace BioDesk.App.Views;

/// <summary>
/// ListaPacientesView - Interface completa para gestão de lista de pacientes
/// </summary>
public partial class ListaPacientesView : UserControl
{
    public ListaPacientesView()
    {
        InitializeComponent();
        
        // Configurar ViewModel através do DI
        var app = Application.Current as App;
        if (app?.ServiceProvider != null)
        {
            DataContext = app.ServiceProvider.GetService<ListaPacientesViewModel>();
        }
        
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is ListaPacientesViewModel viewModel)
        {
            await viewModel.CarregarDadosAsync();
        }
    }
}