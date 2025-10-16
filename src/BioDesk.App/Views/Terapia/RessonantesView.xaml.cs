using System;
using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Windows;
using BioDesk.App.Windows;

namespace BioDesk.App.Views.Terapia;

public partial class RessonantesView : UserControl
{
    public RessonantesView()
    {
        InitializeComponent();
        Loaded += OnLoaded;
        Unloaded += OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is RessonantesViewModel vm)
        {
            vm.TerapiaLocalRequested += OnTerapiaLocalRequested;
        }
    }

    private void OnUnloaded(object sender, RoutedEventArgs e)
    {
        if (DataContext is RessonantesViewModel vm)
        {
            vm.TerapiaLocalRequested -= OnTerapiaLocalRequested;
        }
    }

    private void OnTerapiaLocalRequested(object? sender, TerapiaLocalRequestedEventArgs e)
    {
        var viewModel = new TerapiaLocalViewModel();
        
        // Converter FrequenciaInfo → FrequenciaStep
        foreach (var freq in e.Frequencias)
        {
            viewModel.Frequencias.Add(new FrequenciaStep(
                Hz: freq.Hz,
                DutyPercent: freq.DutyPercent,
                DuracaoSegundos: freq.DuracaoSegundos
            ));
        }

        var window = new TerapiaLocalWindow
        {
            DataContext = viewModel,
            Owner = Window.GetWindow(this)
        };
        window.ShowDialog();
    }
}
