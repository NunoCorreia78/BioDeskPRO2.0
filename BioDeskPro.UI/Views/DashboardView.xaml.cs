using BioDeskPro.Core.Entities;
using BioDeskPro.UI.ViewModels;
using System.Windows.Controls;
using System.Windows.Input;

namespace BioDeskPro.UI.Views;

public partial class DashboardView : UserControl
{
    public DashboardView()
    {
        InitializeComponent();
    }
    
    private void SearchBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter && DataContext is DashboardViewModel viewModel)
        {
            if (viewModel.SearchCommand.CanExecute(null))
            {
                viewModel.SearchCommand.Execute(null);
            }
        }
    }
    
    private void PacienteItem_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is Border border && 
            border.Tag is Paciente paciente && 
            DataContext is DashboardViewModel viewModel)
        {
            viewModel.SelecionarPacienteCommand.Execute(paciente);
        }
    }
}