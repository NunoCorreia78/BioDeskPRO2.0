using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// UserControl para Dados Biográficos - Aba 1
/// Formulário de identificação pessoal e contactos
/// </summary>
public partial class DadosBiograficosUserControl : UserControl
{
    public DadosBiograficosUserControl()
    {
        InitializeComponent();
        Loaded += OnLoaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Subscrever eventos de mudança em todos os controles
        SubscribeToControlChanges(this);
    }

    /// <summary>
    /// Subscrever recursivamente a mudanças em TextBox e ComboBox
    /// para marcar formulário como "dirty" (IsDirty = true)
    /// </summary>
    private void SubscribeToControlChanges(DependencyObject parent)
    {
        int childCount = System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < childCount; i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);

            if (child is TextBox textBox)
            {
                textBox.TextChanged -= OnControlValueChanged;
                textBox.TextChanged += OnControlValueChanged;
            }
            else if (child is ComboBox comboBox)
            {
                comboBox.SelectionChanged -= OnControlValueChanged;
                comboBox.SelectionChanged += OnControlValueChanged;
            }

            // Recursivo para filhos
            SubscribeToControlChanges(child);
        }
    }

    /// <summary>
    /// Marcar formulário como alterado (IsDirty = true)
    /// </summary>
    private void OnControlValueChanged(object sender, RoutedEventArgs e)
    {
        if (DataContext is FichaPacienteViewModel viewModel)
        {
            viewModel.MarcarComoAlterado();
        }
    }
}
