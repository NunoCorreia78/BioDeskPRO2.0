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
    [ObservableProperty] private string _selectedCategoryFilter = "Todas";

    public ObservableCollection<string> SeedSources { get; } =
        new(["Nome+DataNasc", "Âncora Custom", "FotoHash", "UUID Sessão"]);

    public ObservableCollection<string> RngEngines { get; } =
        new(["XorShift128+", "PCG64", "HardwareNoiseMix"]);

    public ObservableCollection<string> CategoryFilters { get; } =
        new(["Todas", "Chakra", "Meridiano", "Órgão", "Florais", "Vitamina", "Patógeno", "Emocional"]);

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
        
        // Aplicar filtro de categoria se não for "Todas"
        if (SelectedCategoryFilter != "Todas")
        {
            cfg = cfg with 
            { 
                Filter = new ItemFilter(
                    IncludeCategories: new[] { SelectedCategoryFilter },
                    ExcludeCategories: Array.Empty<string>())
            };
        }
        
        var list = await _engine.RunScanAsync(cfg, CancellationToken.None);

        Results.Clear();
        
        // Debug: Se não houver resultados, mostrar mensagem
        if (list.Count == 0)
        {
            Results.Add(new ScanResultItem(
                ItemId: 0,
                Code: "DEBUG",
                Name: $"Nenhum resultado encontrado para categoria: {SelectedCategoryFilter}",
                Category: "Info",
                ScorePercent: 0,
                ZScore: 0,
                QValue: 0));
        }
        else
        {
            foreach (var item in list)
            {
                Results.Add(item);
            }
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
