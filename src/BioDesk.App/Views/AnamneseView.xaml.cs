using System.Windows.Controls;
using BioDesk.ViewModels;

namespace BioDesk.App.Views;

/// <summary>
/// UserControl para o sistema de Anamnese/Declaração inteligente
/// Suporta Modo Edição vs Modo Documento + Sistema de Reconciliação
/// </summary>
public partial class AnamneseView : UserControl
{
    public AnamneseView()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Define o ViewModel da anamnese integrado
    /// </summary>
    public void SetViewModel(AnamneseViewModelIntegrado viewModel)
    {
        DataContext = viewModel;
    }
}