using System.Windows.Controls;
using BioDesk.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Windows;
using System.Windows.Input;

namespace BioDesk.App.Views;

/// <summary>
/// Interação lógica para FichaPacienteView.xaml
/// Exibe a ficha completa do paciente com possibilidade de edição
/// </summary>
public partial class FichaPacienteView : UserControl
{
    public FichaPacienteView()
    {
        InitializeComponent();
    }

    private void FichaPacienteView_Loaded(object sender, RoutedEventArgs e)
    {
        // O DataContext já é definido no MainWindow.xaml.cs
        // O ViewModel já é inicializado no construtor com o paciente ativo
    }

    /// <summary>
    /// DatePicker event handler removido conforme solicitado
    /// </summary>
    
    /// <summary>
    /// Impede que cliques no conteúdo do modal fechem o modal
    /// </summary>
    private void Border_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
    }

    /// <summary>
    /// Fecha o modal quando clica no overlay
    /// </summary>
    private void Modal_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is FichaPacienteViewModel viewModel)
        {
            viewModel.FecharModalCommand.Execute(null);
        }
    }
}