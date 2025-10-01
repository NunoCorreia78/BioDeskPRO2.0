using System.Windows.Controls;
using System.Windows;
using BioDesk.ViewModels.Abas;
using System.ComponentModel;

namespace BioDesk.App.Views.Abas;

public partial class RegistoConsultasUserControl : UserControl
{
    public RegistoConsultasUserControl()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        DataContextChanged += OnDataContextChanged;

        // ✅ GARANTIR que modal começa oculto
        if (ModalPrescricao != null)
        {
            ModalPrescricao.Visibility = Visibility.Collapsed;
        }
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Subscrever eventos de mudança em todos os controles
        SubscribeToControlChanges(this);
    }

    /// <summary>
    /// Subscrever recursivamente a mudanças em TextBox, ComboBox e CheckBox
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
            else if (child is CheckBox checkBox)
            {
                checkBox.Checked -= OnControlValueChanged;
                checkBox.Unchecked -= OnControlValueChanged;
                checkBox.Checked += OnControlValueChanged;
                checkBox.Unchecked += OnControlValueChanged;
            }

            SubscribeToControlChanges(child);
        }
    }

    private void OnControlValueChanged(object sender, RoutedEventArgs e)
    {
        var window = Window.GetWindow(this);
        if (window?.DataContext is BioDesk.ViewModels.FichaPacienteViewModel viewModel)
        {
            viewModel.MarcarComoAlterado();
        }
    }

    private void OnDataContextChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        // Unsubscribe do ViewModel anterior
        if (e.OldValue is RegistoConsultasViewModel oldViewModel)
        {
            oldViewModel.PropertyChanged -= OnViewModelPropertyChanged;
        }

        // Subscribe ao novo ViewModel
        if (e.NewValue is RegistoConsultasViewModel newViewModel)
        {
            newViewModel.PropertyChanged += OnViewModelPropertyChanged;
        }
    }

    private void OnViewModelPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(RegistoConsultasViewModel.MostrarPrescricao) &&
            DataContext is RegistoConsultasViewModel viewModel)
        {
            // ✅ Atualizar visibilidade do modal manualmente
            ModalPrescricao.Visibility = viewModel.MostrarPrescricao ? Visibility.Visible : Visibility.Collapsed;
        }
    }
}
