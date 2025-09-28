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
        
        // Não definir DataContext aqui - deixar o MainWindow fazer isso
        // para evitar conflitos com a navegação
        
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