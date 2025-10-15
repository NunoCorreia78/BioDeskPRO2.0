using System;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Application.Terapia.Impl;
using BioDesk.Core.Domain.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.ViewModels.Services.Terapia;

namespace BioDesk.ViewModels.UserControls.Terapia;

public partial class AvaliacaoViewModel : ObservableObject
{
    private readonly IResonanceEngine _engine;
    private readonly IActiveListService _activeList;

    [ObservableProperty] private string _sessionSalt = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
    [ObservableProperty] private string _selectedSeedSource = "Nome+DataNasc";
    [ObservableProperty] private string _selectedRngEngine = "XorShift128+";
    [ObservableProperty] private int _iterations = 50000;

    public ObservableCollection<string> SeedSources { get; } =
        new(["Nome+DataNasc", "Âncora Custom", "FotoHash", "UUID Sessão"]);

    public ObservableCollection<string> RngEngines { get; } =
        new(["XorShift128+", "PCG64", "HardwareNoiseMix"]);

    public ObservableCollection<ScanResultItem> Results { get; } = new();

    public AvaliacaoViewModel(IResonanceEngine engine, IActiveListService activeList)
    {
        _engine = engine;
        _activeList = activeList;
    }

    [RelayCommand]
    private void RegenerateSalt() => SessionSalt = Guid.NewGuid().ToString();

    [RelayCommand]
    private async Task RunScanAsync()
    {
        var cfg = DemoConfigs.BuildScanConfig(SelectedSeedSource, SessionSalt, SelectedRngEngine, Iterations);
        var list = await _engine.RunScanAsync(cfg, CancellationToken.None);

        Results.Clear();
        foreach (var item in list)
        {
            Results.Add(item);
        }
    }

    [RelayCommand]
    private void AddSelectedToActiveList()
    {
        foreach (var item in Results)
        {
            _activeList.AddOrUpdate(item);
        }
    }

    [RelayCommand]
    private Task SaveSessionAsync()
    {
        // TODO: persistir sessão em base de dados
        return Task.CompletedTask;
    }
}
