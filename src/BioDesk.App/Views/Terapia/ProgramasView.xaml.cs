using System.Linq;
using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Windows;
using BioDesk.App.Windows;

namespace BioDesk.App.Views.Terapia;

public partial class ProgramasView : UserControl
{
    public ProgramasView()
    {
        InitializeComponent();
        
        // Escutar evento de solicitação de terapia local
        Loaded += (s, e) =>
        {
            if (DataContext is ProgramasViewModel vm)
            {
                vm.TerapiaLocalRequested += OnTerapiaLocalRequested;
            }
        };
        
        Unloaded += (s, e) =>
        {
            if (DataContext is ProgramasViewModel vm)
            {
                vm.TerapiaLocalRequested -= OnTerapiaLocalRequested;
            }
        };
    }

    private void OnTerapiaLocalRequested(object? sender, TerapiaLocalRequestedEventArgs e)
    {
        // Criar ViewModel do modal e popular com frequências da BD
        var viewModel = new TerapiaLocalViewModel();
        foreach (var freq in e.Frequencias)
        {
            viewModel.Frequencias.Add(new BioDesk.ViewModels.Windows.FrequenciaStep(
                Hz: freq.Hz,
                DutyPercent: freq.DutyPercent,
                DuracaoSegundos: freq.DuracaoSegundos));
        }

        // Abrir modal
        var window = new TerapiaLocalWindow
        {
            DataContext = viewModel,
            Owner = System.Windows.Window.GetWindow(this)
        };
        window.ShowDialog();
    }

    private void ListBoxItem_Selected(object sender, RoutedEventArgs e)
    {
        if (DataContext is not ProgramasViewModel vm) return;

        // Encontrar ListBox pai
        if (sender is not ListBoxItem listBoxItem) return;
        var listBox = FindParent<ListBox>(listBoxItem);
        if (listBox == null) return;

        // Sincronizar seleção múltipla com ViewModel
        vm.SelectedPrograms.Clear();
        foreach (var item in listBox.SelectedItems.Cast<string>())
        {
            vm.SelectedPrograms.Add(item);
        }
    }

    private static T? FindParent<T>(DependencyObject child) where T : DependencyObject
    {
        var parent = System.Windows.Media.VisualTreeHelper.GetParent(child);
        if (parent == null) return null;
        return parent is T typedParent ? typedParent : FindParent<T>(parent);
    }
}
