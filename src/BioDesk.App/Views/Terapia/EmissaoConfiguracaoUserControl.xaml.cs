using System.Windows.Controls;
using BioDesk.ViewModels.UserControls.Terapia;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Terapia;

/// <summary>
/// UserControl para configuração de emissão de frequências.
/// </summary>
public partial class EmissaoConfiguracaoUserControl : UserControl
{
    public EmissaoConfiguracaoUserControl()
    {
        InitializeComponent();

        // DataContext será injetado via DI no TerapiasBioenergeticasUserControl
    }

    /// <summary>
    /// Carrega dispositivos ao abrir controlo.
    /// </summary>
    private async void UserControl_Loaded(object sender, System.Windows.RoutedEventArgs e)
    {
        if (DataContext is EmissaoConfiguracaoViewModel viewModel)
        {
            await viewModel.CarregarDispositivosCommand.ExecuteAsync(null);
        }
    }
}
