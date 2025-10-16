using System.Linq;
using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels.UserControls.Terapia;

namespace BioDesk.App.Views.Terapia;

public partial class ProgramasView : UserControl
{
    public ProgramasView()
    {
        InitializeComponent();
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
