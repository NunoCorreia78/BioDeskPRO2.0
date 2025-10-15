using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels;

namespace BioDesk.App.Views;

/// <summary>
/// Interaction logic for ItensCoreUserControl.xaml
/// </summary>
public partial class ItensCoreUserControl : UserControl
{
    public ItensCoreUserControl()
    {
        InitializeComponent();
    }

    private async void UserControl_Loaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is ItensCoreViewModel viewModel)
        {
            await viewModel.InitializeAsync();
        }
    }
}
