using System.Windows;
using System.Windows.Controls;
using BioDesk.App.Windows;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Terapia;

public partial class HistoricoView : UserControl
{
    public HistoricoView()
    {
        InitializeComponent();
    }

    private void OnVerHistoricoCompleto(object sender, RoutedEventArgs e)
    {
        // Obter ViewModel via DI
        var app = (App)Application.Current;
        var viewModel = app.ServiceProvider?.GetRequiredService<BioDesk.ViewModels.Windows.HistoricoViewModel>();

        if (viewModel == null) return;

        // Criar e mostrar janela
        var window = new HistoricoWindow(viewModel)
        {
            Owner = Window.GetWindow(this)
        };

        window.ShowDialog();
    }
}
