using System.Windows.Controls;
using BioDesk.ViewModels.UserControls.Terapia;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

public partial class TerapiasUserControl : UserControl
{
    public TerapiasUserControl()
    {
        InitializeComponent();

        var app = (App)System.Windows.Application.Current;
        if (app.ServiceProvider != null)
        {
            DataContext = app.ServiceProvider.GetRequiredService<TerapiaCoreViewModel>();
        }
    }
}
