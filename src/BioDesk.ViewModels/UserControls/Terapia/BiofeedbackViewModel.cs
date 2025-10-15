using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Domain.Terapia;
using BioDesk.ViewModels.Services.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.UserControls.Terapia;

public partial class BiofeedbackViewModel : ObservableObject
{
    private readonly IBiofeedbackRunner _runner;
    private readonly IActiveListService _activeList;

    public ObservableCollection<ScanResultItem> ActiveList => _activeList.ActiveItems;

    public IReadOnlyList<string> Modes { get; } = new[] { "Local (Energia)", "Remoto (Informação)" };
    [ObservableProperty] private string _selectedMode = "Local (Energia)";

    public IReadOnlyList<string> Waveforms { get; } = new[] { "Sine", "Square", "Pulse" };
    [ObservableProperty] private string _selectedWaveform = "Square";
    [ObservableProperty] private double _frequencyHz = 728;
    [ObservableProperty] private double _duty = 50;
    [ObservableProperty] private double _vpp = 3.0;
    [ObservableProperty] private double _currentLimitmA = 0.8;
    [ObservableProperty] private double _complianceV = 12.0;
    [ObservableProperty] private int _perItemSeconds = 20;

    [ObservableProperty] private string _anchor = string.Empty;
    public IReadOnlyList<string> HashAlgos { get; } = new[] { "SHA256", "BLAKE3" };
    [ObservableProperty] private string _selectedHashAlgo = "SHA256";
    public IReadOnlyList<string> Modulations { get; } = new[] { "AM-Ruído", "FM-Ruído", "PSK" };
    [ObservableProperty] private string _selectedModulation = "AM-Ruído";
    [ObservableProperty] private int _onMs = 800;
    [ObservableProperty] private int _offMs = 200;
    [ObservableProperty] private int _cycles = 3;
    [ObservableProperty] private bool _nullDriftCheck = true;
    [ObservableProperty] private int? _rescanLightMinutes = 5;

    [ObservableProperty] private string _status = "Pronto";
    [ObservableProperty] private string _telemetry = string.Empty;

    public bool IsLocalMode => SelectedMode.StartsWith("Local", StringComparison.OrdinalIgnoreCase);
    public bool IsRemoteMode => !IsLocalMode;

    public BiofeedbackViewModel(IBiofeedbackRunner runner, IActiveListService activeList)
    {
        _runner = runner;
        _activeList = activeList;
    }

    partial void OnSelectedModeChanged(string value)
    {
        OnPropertyChanged(nameof(IsLocalMode));
        OnPropertyChanged(nameof(IsRemoteMode));
    }

    [RelayCommand]
    private async Task StartAsync()
    {
        if (ActiveList.Count == 0)
        {
            Status = "Lista vazia";
            return;
        }

        Status = "A emitir...";

        if (IsLocalMode)
        {
            var cfg = new LocalEmissionConfig(
                SelectedWaveform,
                FrequencyHz,
                Duty,
                Vpp,
                CurrentLimitmA,
                ComplianceV,
                TimeSpan.FromSeconds(PerItemSeconds));

            await _runner.RunLocalAsync(ActiveList.ToList(), cfg, CancellationToken.None);
        }
        else
        {
            var cfg = new RemoteEmissionConfig(
                Anchor,
                SelectedHashAlgo,
                SelectedModulation,
                Cycles,
                TimeSpan.FromSeconds(PerItemSeconds),
                OnMs,
                OffMs,
                NullDriftCheck,
                RescanLightMinutes is null ? null : TimeSpan.FromMinutes(RescanLightMinutes.Value));

            await _runner.RunRemoteAsync(ActiveList.ToList(), cfg, CancellationToken.None);
        }

        Status = "Concluído";
    }

    [RelayCommand] private void Pause() => Status = "Pausado (stub)";
    [RelayCommand] private void Stop() => Status = "Parado (stub)";
    [RelayCommand] private void EStop() => Status = "Emergência!";
}
