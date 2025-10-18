using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Application.Terapia.Impl;
using BioDesk.Core.Domain.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.UserControls.Terapia;

/// <summary>
/// EventArgs para solicitação de terapia remota.
/// Contém lista de protocolos selecionados pelo user na avaliação.
/// </summary>
public class TerapiaRemotaRequestedEventArgs : EventArgs
{
    public List<string> ProtocolosSelecionados { get; }

    public TerapiaRemotaRequestedEventArgs(List<string> protocolos)
    {
        ProtocolosSelecionados = protocolos;
    }
}

public partial class AvaliacaoViewModel : ObservableObject
{
    private readonly IResonanceEngine _engine;

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
        new(["Todas", "Chakra", "Meridiano", "Orgao", "FloraisBach", "FloraisCalifornianos", "Vitamina", "Mineral", "Emocao", "Frequencia", "Homeopatia", "Suplemento", "Alimento"]);

    public ObservableCollection<ScanResultItem> Results { get; } = new();

    public AvaliacaoViewModel(IResonanceEngine engine)
    {
        _engine = engine;
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

    /// <summary>
    /// Evento disparado quando user pede para iniciar terapia remota.
    /// View (XAML.cs) escuta este evento e abre TerapiaRemotaWindow.
    /// </summary>
    public event EventHandler<TerapiaRemotaRequestedEventArgs>? TerapiaRemotaRequested;

    /// <summary>
    /// Prepara dados e solicita abertura de modal de Terapia Remota.
    /// User requirement: Terapia remota = 14 dias default, seeds/RNG, sem emissão Hz.
    /// </summary>
    [RelayCommand]
    private void IniciarTerapiaRemota()
    {
        // Extrair nomes dos itens selecionados
        var protocolosSelecionados = Results
            .Where(r => r.Category != "Info") // Excluir mensagens debug
            .Select(r => r.Name)
            .ToList();

        if (protocolosSelecionados.Count == 0)
        {
            // TODO: Mostrar mensagem ao user "Nenhum item selecionado"
            return;
        }

        // Disparar evento para View abrir modal
        TerapiaRemotaRequested?.Invoke(this, new TerapiaRemotaRequestedEventArgs(protocolosSelecionados));
    }

    [RelayCommand]
    private Task SaveSessionAsync()
    {
        // TODO: persistir sessão em base de dados
        return Task.CompletedTask;
    }
}
