using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels;

namespace BioDesk.App.Views;

public partial class ConfiguracoesView : Window
{
    private readonly ConfiguracoesViewModel _viewModel;

    public ConfiguracoesView(ConfiguracoesViewModel viewModel)
    {
        InitializeComponent();
        _viewModel = viewModel;
        DataContext = _viewModel;

        // Carregar password existente (se houver)
        Loaded += async (s, e) => await _viewModel.CarregarConfiguracoesAsync();
    }

    private void PasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (sender is PasswordBox pb)
        {
            _viewModel.EmailPassword = pb.Password;
        }
    }

    private void BtnCancelar_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
