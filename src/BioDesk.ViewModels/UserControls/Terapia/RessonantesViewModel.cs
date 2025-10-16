using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Domain.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.UserControls.Terapia;

public partial class RessonantesViewModel : ObservableObject
{
    private readonly IResonantFrequencyFinder _finder;

    [ObservableProperty] private double _startHz = 10;
    [ObservableProperty] private double _stopHz = 2000;
    [ObservableProperty] private double _stepHz = 1;
    [ObservableProperty] private int _dwellMs = 150;
    [ObservableProperty] private SweepPointVM? _selectedPoint;

    public ObservableCollection<SweepPointVM> SweepResults { get; } = new();
    public ObservableCollection<SweepPointVM> SelectedPoints { get; } = new(); // Seleção múltipla

    /// <summary>
    /// Evento disparado quando user pede para iniciar terapia local com Hz ressonantes.
    /// View (XAML.cs) escuta este evento e abre TerapiaLocalWindow.
    /// </summary>
    public event EventHandler<TerapiaLocalRequestedEventArgs>? TerapiaLocalRequested;

    public RessonantesViewModel(IResonantFrequencyFinder finder)
    {
        _finder = finder;
    }

    [RelayCommand]
    private async Task RunSweepAsync()
    {
        SweepResults.Clear();
        await foreach (var (hz, score) in _finder.RunAsync(
                           new SweepConfig(StartHz, StopHz, StepHz, DwellMs),
                           CancellationToken.None))
        {
            SweepResults.Add(new SweepPointVM(hz, score, null));
        }
    }

    /// <summary>
    /// Prepara dados e solicita abertura de modal de Terapia Local com Hz ressonantes.
    /// User requirement: Usa Hz detectados no scan (não da BD), voltagem controlável 0-12V.
    /// </summary>
    [RelayCommand]
    private void IniciarTerapiaLocal()
    {
        // Usar pontos selecionados (multi-seleção) ou ponto único
        var pontosParaUsar = SelectedPoints.Count > 0
            ? SelectedPoints.ToList()
            : (SelectedPoint != null ? new List<SweepPointVM> { SelectedPoint } : new List<SweepPointVM>());

        if (pontosParaUsar.Count == 0)
        {
            // TODO: Mostrar mensagem "Nenhuma frequência ressonante selecionada"
            return;
        }

        // Converter Hz ressonantes para FrequenciaInfo
        // Nota: Hz do scan ressonante não têm duty/duração pré-definidos,
        // usar defaults: Duty 50%, Duração 180s (3 min)
        var frequencias = pontosParaUsar.Select(p => new FrequenciaInfo(
            Hz: p.Hz,
            DutyPercent: 50, // Default duty cycle
            DuracaoSegundos: 180 // Default 3 minutos por Hz
        )).ToList();

        // Disparar evento para View abrir modal
        TerapiaLocalRequested?.Invoke(this, new TerapiaLocalRequestedEventArgs(frequencias));
    }
}

public sealed record SweepPointVM(double Hz, double Score, string? Notes);
