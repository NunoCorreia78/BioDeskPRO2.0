using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Domain.Terapia;
using BioDesk.ViewModels.Services.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.UserControls.Terapia;

public partial class RessonantesViewModel : ObservableObject
{
    private readonly IResonantFrequencyFinder _finder;
    private readonly IActiveListService _activeList;

    [ObservableProperty] private double _startHz = 10;
    [ObservableProperty] private double _stopHz = 2000;
    [ObservableProperty] private double _stepHz = 1;
    [ObservableProperty] private int _dwellMs = 150;
    [ObservableProperty] private SweepPointVM? _selectedPoint;

    public ObservableCollection<SweepPointVM> SweepResults { get; } = new();

    public RessonantesViewModel(IResonantFrequencyFinder finder, IActiveListService activeList)
    {
        _finder = finder;
        _activeList = activeList;
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

    [RelayCommand]
    private void AddSelectedToActiveList()
    {
        if (SelectedPoint is null)
        {
            return;
        }

        var item = new ScanResultItem(
            ItemId: (int)SelectedPoint.Hz,
            Code: $"SWEEP::{SelectedPoint.Hz:F2}",
            Name: $"Sweep {SelectedPoint.Hz:F2} Hz",
            Category: "Sweep",
            ScorePercent: SelectedPoint.Score,
            ZScore: 0,
            QValue: 0,
            ImprovementPercent: 0,
            Rank: 0);

        _activeList.AddOrUpdate(item);
    }
}

public sealed record SweepPointVM(double Hz, double Score, string? Notes);
