using System.Windows.Controls;
using BioDesk.Domain.Enums;
using BioDesk.ViewModels.FichaPaciente;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// Interaction logic for BancoCoreUserControl.xaml
/// Aba 7 - Banco Core Informacional (156 itens)
/// </summary>
public partial class BancoCoreUserControl : UserControl
{
    public BancoCoreUserControl()
    {
        InitializeComponent();
    }

    private void FiltrarTodos_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is TerapiasBioenergeticasViewModel viewModel)
        {
            viewModel.FiltrarPorCategoriaCommand.Execute(null);
        }
    }

    private void FiltrarCategoria_Click(object sender, System.Windows.RoutedEventArgs e)
    {
        if (sender is Button button && button.Tag is string tagValue)
        {
            if (int.TryParse(tagValue, out int categoriaInt))
            {
                var categoria = (CategoriaCore)categoriaInt;
                if (DataContext is TerapiasBioenergeticasViewModel viewModel)
                {
                    viewModel.FiltrarPorCategoriaCommand.Execute(categoria);
                }
            }
        }
    }
}
