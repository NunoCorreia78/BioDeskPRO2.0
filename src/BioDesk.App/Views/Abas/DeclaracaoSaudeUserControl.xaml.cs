using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels.Abas;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// UserControl para Aba 2: Declaração de Saúde
/// Contém formulário completo de histórico médico e estilo de vida
/// </summary>
public partial class DeclaracaoSaudeUserControl : UserControl
{
    public DeclaracaoSaudeUserControl()
    {
        InitializeComponent();

        // Configura o DataContext através do DI container
        if (Application.Current is App app && app.ServiceProvider != null)
        {
            DataContext = app.ServiceProvider.GetRequiredService<DeclaracaoSaudeViewModel>();
        }
    }
}
