using System.Windows.Controls;
using BioDesk.ViewModels.UserControls;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// Interaction logic for TerapiasUserControl.xaml
/// ✅ Injeção do TerapiasBioenergeticasUserControlViewModel via DI
/// </summary>
public partial class TerapiasUserControl : UserControl
{
    public TerapiasUserControl()
    {
        InitializeComponent();
        
        // ✅ Obter ViewModel do DI e definir como DataContext
        var app = (App)System.Windows.Application.Current;
        if (app.ServiceProvider != null)
        {
            DataContext = app.ServiceProvider.GetRequiredService<TerapiasBioenergeticasUserControlViewModel>();
        }
    }
}
