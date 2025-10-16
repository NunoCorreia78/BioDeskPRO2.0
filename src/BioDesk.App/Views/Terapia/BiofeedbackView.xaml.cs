using System;
using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Windows;
using BioDesk.App.Windows;

namespace BioDesk.App.Views.Terapia;

public partial class BiofeedbackView : UserControl
{
    public BiofeedbackView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is BiofeedbackViewModel vm)
        {
            vm.BiofeedbackSessaoRequested += OnBiofeedbackSessaoRequested;
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is BiofeedbackViewModel vm)
        {
            vm.BiofeedbackSessaoRequested -= OnBiofeedbackSessaoRequested;
        }
    }

    private void OnBiofeedbackSessaoRequested(object? sender, BiofeedbackSessaoRequestedEventArgs e)
    {
        // Modal autónoma - não precisa de dados pré-carregados
        var viewModel = new BiofeedbackSessionViewModel();

        var window = new BiofeedbackSessionWindow
        {
            DataContext = viewModel,
            Owner = Window.GetWindow(this)
        };
        window.ShowDialog();
    }
}
