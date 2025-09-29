using System.Windows.Controls;
using System.Windows;
using BioDesk.ViewModels;
using System.ComponentModel;

namespace BioDesk.App.Views;

/// <summary>
/// UserControl para ficha completa de paciente com navegação por separadores
/// Sistema de 6 abas sequenciais: Dados Biográficos → Declaração → Consentimentos → Consultas → Íris → Terapias
/// </summary>
public partial class FichaPacienteView : UserControl
{
    public FichaPacienteView()
    {
        InitializeComponent();
        DataContextChanged += OnDataContextChanged;
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        // Unsubscribe do ViewModel anterior
        if (e.OldValue is FichaPacienteViewModel oldViewModel)
        {
            oldViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        // Subscribe ao novo ViewModel
        if (e.NewValue is FichaPacienteViewModel newViewModel)
        {
            newViewModel.PropertyChanged += OnViewModelPropertyChanged;
            // Atualizar imediatamente com o valor atual
            AtualizarVisibilidadeAbas(newViewModel.AbaAtiva);
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(FichaPacienteViewModel.AbaAtiva) &&
            sender is FichaPacienteViewModel viewModel)
        {
            AtualizarVisibilidadeAbas(viewModel.AbaAtiva);
        }
    }

    private void AtualizarVisibilidadeAbas(int abaAtiva)
    {
        // CONTROLO DIRETO - SEM CONVERTERS
        System.Diagnostics.Debug.WriteLine($"🔧 CODE-BEHIND: Mudando para aba {abaAtiva}");

        // Todos invisíveis primeiro
        DadosBiograficosUserControl.Visibility = Visibility.Collapsed;
        DeclaracaoSaudeUserControl.Visibility = Visibility.Collapsed;
        ConsentimentosUserControl.Visibility = Visibility.Collapsed;

        // Mostrar o correto
        switch (abaAtiva)
        {
            case 1:
                DadosBiograficosUserControl.Visibility = Visibility.Visible;
                System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: DadosBiograficos VISÍVEL");
                break;
            case 2:
                DeclaracaoSaudeUserControl.Visibility = Visibility.Visible;
                System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: DeclaracaoSaude VISÍVEL");
                break;
            case 3:
                ConsentimentosUserControl.Visibility = Visibility.Visible;
                System.Diagnostics.Debug.WriteLine("✅ CODE-BEHIND: Consentimentos VISÍVEL");
                break;
            default:
                System.Diagnostics.Debug.WriteLine($"⚠️ CODE-BEHIND: Aba {abaAtiva} não implementada");
                break;
        }
    }
}
