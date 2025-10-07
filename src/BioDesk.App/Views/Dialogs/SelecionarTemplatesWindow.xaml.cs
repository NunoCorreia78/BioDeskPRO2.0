using System.Windows;
using BioDesk.ViewModels.Abas;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Dialogs;

/// <summary>
/// Pop-up para seleção de templates PDF
/// Permite pesquisa, multi-seleção e preview
/// </summary>
public partial class SelecionarTemplatesWindow : Window
{
    private readonly SelecionarTemplatesViewModel _viewModel;

    public SelecionarTemplatesWindow()
    {
        InitializeComponent();

        // Obter ViewModel do DI container
        _viewModel = ((App)Application.Current).ServiceProvider
            .GetRequiredService<SelecionarTemplatesViewModel>();

        DataContext = _viewModel;

        // Carregar templates ao abrir a janela
        Loaded += async (s, e) =>
        {
            await _viewModel.InicializarAsync();
        };
    }

    /// <summary>
    /// Templates selecionados pelo utilizador
    /// </summary>
    public System.Collections.Generic.List<TemplatePdfViewModel> TemplatesSelecionados
        => _viewModel.TemplatesSelecionados;

    /// <summary>
    /// Botão Cancelar - fecha sem selecionar
    /// </summary>
    private void BtnCancelar_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    /// <summary>
    /// Botão Adicionar - retorna templates selecionados
    /// </summary>
    private void BtnAdicionar_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }
}
