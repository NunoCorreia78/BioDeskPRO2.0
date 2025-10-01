using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using BioDesk.Domain.Entities;
using BioDesk.ViewModels;

namespace BioDesk.App.Views;

public partial class ListaPacientesView : UserControl
{
    public ListaPacientesView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Carregar pacientes quando view é exibida
        if (DataContext is ListaPacientesViewModel viewModel)
        {
            await viewModel.OnNavigatedToAsync();
        }
    }

    private void DataGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is DataGrid dataGrid && dataGrid.SelectedItem is Paciente paciente)
        {
            // Executar comando de abrir ficha
            if (DataContext is ListaPacientesViewModel viewModel)
            {
                viewModel.AbrirFichaPacienteCommand.Execute(paciente);
            }
        }
    }
}
