using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Domain.Terapia;
using BioDesk.Services.Audio;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.UserControls.Terapia;

/// <summary>
/// EventArgs para solicitação de sessão de biofeedback.
/// Modal é autónomo (não precisa dados pré-carregados).
/// </summary>
public class BiofeedbackSessaoRequestedEventArgs : EventArgs { }

/// <summary>
/// Item do histórico de sessões de biofeedback.
/// </summary>
public sealed record BiofeedbackSessionHistoryItem(
    DateTime DataSessao,
    string Modo,
    int DuracaoMinutos,
    int Ciclos,
    string Status
);

public partial class BiofeedbackViewModel : ObservableObject, IDisposable
{
    private readonly IBiofeedbackRunner _runner;
    private readonly IFrequencyEmissionService? _emissionService;
    private readonly ITerapiaStateService? _stateService;
    private readonly ILogger<BiofeedbackViewModel>? _logger;
    private CancellationTokenSource? _sessaoCts;
    private bool _disposed;

    // Histórico de sessões (stub - será preenchido com dados reais futuramente)
    public ObservableCollection<BiofeedbackSessionHistoryItem> SessionHistory { get; } = new()
    {
        // Dados exemplo (remover quando implementar persistência)
        new BiofeedbackSessionHistoryItem(DateTime.Now.AddDays(-2), "Local", 45, 3, "Concluída"),
        new BiofeedbackSessionHistoryItem(DateTime.Now.AddDays(-5), "Remoto", 30, 2, "Interrompida"),
    };

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

    // Propriedades de progresso de sessão
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(IniciarSessaoCommand))]
    private bool _sessaoEmAndamento = false;
    [ObservableProperty] private string _cicloAtual = "";
    [ObservableProperty] private int _tempoRestanteSegundos = 0;
    [ObservableProperty] private int _cicloAtualIndex = 0;
    [ObservableProperty] private int _totalCiclos = 0;
    [ObservableProperty] private double _progressoPercentual = 0;

    // Propriedades para TerapiaProgressoUserControl (REDESIGN 20OUT2025)
    [ObservableProperty] private double _frequenciaAtualHz = 0;
    [ObservableProperty] private double _frequenciaOriginalHz = 0;
    [ObservableProperty] private double _ajusteAplicadoHz = 0;
    [ObservableProperty] private string _tempoRestanteFormatado = "";
    [ObservableProperty] private int _frequenciaAtualIndex = 0;
    [ObservableProperty] private int _totalFrequencias = 1; // Biofeedback: 1 frequência configurada

    public bool IsLocalMode => SelectedMode.StartsWith("Local", StringComparison.OrdinalIgnoreCase);
    public bool IsRemoteMode => !IsLocalMode;

    /// <summary>
    /// Evento disparado quando user pede para iniciar sessão de biofeedback.
    /// View (XAML.cs) escuta este evento e abre BiofeedbackSessionWindow.
    /// </summary>
    public event EventHandler<BiofeedbackSessaoRequestedEventArgs>? BiofeedbackSessaoRequested;

    public BiofeedbackViewModel(
        IBiofeedbackRunner runner,
        IFrequencyEmissionService? emissionService = null,
        ITerapiaStateService? stateService = null,
        ILogger<BiofeedbackViewModel>? logger = null)
    {
        _runner = runner;
        _emissionService = emissionService;
        _stateService = stateService;
        _logger = logger;
    }

    partial void OnSelectedModeChanged(string value)
    {
        OnPropertyChanged(nameof(IsLocalMode));
        OnPropertyChanged(nameof(IsRemoteMode));
    }

    /// <summary>
    /// Verifica se pode iniciar sessão de biofeedback.
    /// </summary>
    private bool CanIniciarSessao(TerapiaParametros? parametros)
    {
        var podeExecutar = !SessaoEmAndamento;
        System.Diagnostics.Debug.WriteLine($"🔐 CanIniciarSessao? {podeExecutar} (SessaoEmAndamento={SessaoEmAndamento})");
        return podeExecutar;
    }

    /// <summary>
    /// Inicia sessão de biofeedback diretamente com progresso em tempo real.
    /// Loop: scan → emit → re-scan → repeat (ciclos configuráveis).
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanIniciarSessao))]
    private async Task IniciarSessaoAsync(TerapiaParametros? parametros)
    {
        var parametrosEfetivos = parametros ?? new TerapiaParametros(
            VoltagemV: 0,
            DuracaoTotalMinutos: 0,
            TempoFrequenciaSegundos: PerItemSeconds,
            AjusteHz: 0);

        if (parametros is null)
        {
            System.Diagnostics.Debug.WriteLine("⚪ BiofeedbackViewModel: Parâmetros nulos recebidos via comando. A usar defaults internos.");
        }

        System.Diagnostics.Debug.WriteLine("🚀 BiofeedbackViewModel: IniciarSessaoAsync CHAMADO");
        System.Diagnostics.Debug.WriteLine($"📦 Parâmetros recebidos: V={parametrosEfetivos.VoltagemV}, Duração={parametrosEfetivos.DuracaoTotalMinutos}min, Tempo/Freq={parametrosEfetivos.TempoFrequenciaSegundos}s");

        if (SessaoEmAndamento)
        {
            System.Diagnostics.Debug.WriteLine("⚠️ BiofeedbackViewModel: Sessão já em andamento, ignorando");
            return;
        }

        SessaoEmAndamento = true;
        TotalCiclos = Cycles;
        CicloAtualIndex = 0;
        Status = "Sessão iniciada...";

        // Criar CancellationToken para parar sessão
        _sessaoCts = new CancellationTokenSource();

        try
        {
            // CICLO INFINITO: Repete sessões biofeedback continuamente
            int sessaoAtual = 1;
            while (SessaoEmAndamento) // Continua até user cancelar
            {
                System.Diagnostics.Debug.WriteLine($"🔄 BiofeedbackViewModel: SESSÃO {sessaoAtual} INICIADA");
                Status = $"[Sessão {sessaoAtual}] Em execução...";

                // Simular ciclos de biofeedback (scan + emit + re-scan)
                for (int i = 1; i <= Cycles && SessaoEmAndamento; i++)
                {
                    if (_sessaoCts.Token.IsCancellationRequested)
                    {
                        break;
                    }

                    CicloAtualIndex = i;
                    CicloAtual = $"[Sessão {sessaoAtual}] Ciclo {i}/{Cycles} - Scanning...";

                    // ✅ PROPRIEDADES REDESIGN: Frequência configurada
                    FrequenciaOriginalHz = FrequencyHz;
                    AjusteAplicadoHz = 0; // Biofeedback não usa ajuste manual
                    FrequenciaAtualHz = FrequencyHz;
                    FrequenciaAtualIndex = 1;
                    TotalFrequencias = 1;

                    // Fase 1: Scan (20s) - Detectar frequências ressonantes
                    // TODO: Integrar com IBiofeedbackRunner.ScanAsync()
                    TempoRestanteSegundos = 20;
                    while (TempoRestanteSegundos > 0 && !_sessaoCts.Token.IsCancellationRequested)
                    {
                        await Task.Delay(1000, _sessaoCts.Token);
                        TempoRestanteSegundos--;
                    }

                    // Fase 2: Emit (duração configurável) - Emitir frequências detectadas
                    CicloAtual = $"[Sessão {sessaoAtual}] Ciclo {i}/{Cycles} - Emitindo...";
                    TempoRestanteSegundos = PerItemSeconds;

                    // ✅ EMISSÃO REAL DE FREQUÊNCIA (NAudio + WASAPI)
                    if (_emissionService != null)
                    {
                        // Usar frequência configurada (FrequencyHz)
                        _logger?.LogInformation("🎵 Emitindo {Hz} Hz (Biofeedback Ciclo {Cycle}/{Total})",
                            FrequencyHz, i, Cycles);

                        // Obter configurações do TerapiaStateService
                        var volume = _stateService?.VolumePercent ?? 70;
                        // Usar forma de onda configurada no BiofeedbackViewModel
                        var waveForm = SelectedWaveform.ToLower() switch
                        {
                            "square" => WaveForm.Square,
                            "pulse" => WaveForm.Square, // Pulse = Square com duty diferente
                            "sine" => WaveForm.Sine,
                            _ => WaveForm.Sine
                        };

                        // Task de emissão
                        var emissionTask = _emissionService.EmitFrequencyAsync(
                            frequencyHz: FrequencyHz,
                            durationSeconds: PerItemSeconds,
                            volumePercent: volume,
                            waveForm: waveForm,
                            cancellationToken: _sessaoCts.Token);

                        // Contagem decrescente paralela
                        while (TempoRestanteSegundos > 0 && !_sessaoCts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(1000, _sessaoCts.Token);
                            TempoRestanteSegundos--;

                            // ✅ REDESIGN: Formatar tempo restante (18min 45s)
                            int minutos = TempoRestanteSegundos / 60;
                            int segundos = TempoRestanteSegundos % 60;
                            TempoRestanteFormatado = minutos > 0
                                ? $"{minutos}min {segundos}s"
                                : $"{segundos}s";

                            ProgressoPercentual = ((i - 1) * 100.0 / Cycles) +
                                                 ((PerItemSeconds - TempoRestanteSegundos) * 100.0 / (Cycles * PerItemSeconds));
                        }

                        // Aguardar emissão completar
                        var result = await emissionTask;
                        if (!result.Success)
                        {
                            _logger?.LogWarning("⚠️ Emissão biofeedback falhou: {Message}", result.Message);
                        }
                    }
                    else
                    {
                        // Fallback: Simulação sem hardware
                        while (TempoRestanteSegundos > 0 && !_sessaoCts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(1000, _sessaoCts.Token);
                            TempoRestanteSegundos--;

                            // ✅ REDESIGN: Formatar tempo restante (18min 45s)
                            int minutos = TempoRestanteSegundos / 60;
                            int segundos = TempoRestanteSegundos % 60;
                            TempoRestanteFormatado = minutos > 0
                                ? $"{minutos}min {segundos}s"
                                : $"{segundos}s";

                            ProgressoPercentual = ((i - 1) * 100.0 / Cycles) +
                                                 ((PerItemSeconds - TempoRestanteSegundos) * 100.0 / (Cycles * PerItemSeconds));
                        }
                    }

                    // Fase 3: Re-scan (opcional, apenas se não for último ciclo)
                    if (i < Cycles && !_sessaoCts.Token.IsCancellationRequested)
                    {
                        CicloAtual = $"[Sessão {sessaoAtual}] Ciclo {i}/{Cycles} - Re-scanning...";
                        TempoRestanteSegundos = 10;
                        while (TempoRestanteSegundos > 0 && !_sessaoCts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(1000, _sessaoCts.Token);
                            TempoRestanteSegundos--;
                        }
                    }
                }

                if (_sessaoCts.Token.IsCancellationRequested)
                {
                    break;
                }

                ProgressoPercentual = 100;
                CicloAtual = $"Sessão {sessaoAtual} concluída! Iniciando próxima...";
                Status = $"Sessão {sessaoAtual} concluída";
                sessaoAtual++;
                await Task.Delay(2000, _sessaoCts.Token); // Pausa de 2s entre sessões
            }
        }
        catch (OperationCanceledException)
        {
            System.Diagnostics.Debug.WriteLine("⏹️ Sessão biofeedback cancelada pelo utilizador");
            _logger?.LogInformation("⏹️ Sessão biofeedback cancelada");
        }
        finally
        {
            Debug.WriteLine($"🏁 BiofeedbackViewModel: FINALLY - Estado ANTES: SessaoEmAndamento={SessaoEmAndamento}");
            SessaoEmAndamento = false;
            _sessaoCts?.Dispose();
            _sessaoCts = null;
            Debug.WriteLine($"🏁 BiofeedbackViewModel: FINALLY - Estado DEPOIS de set false: SessaoEmAndamento={SessaoEmAndamento}");
            Debug.WriteLine($"🔓 BiofeedbackViewModel: CanIniciarSessao agora = {CanIniciarSessao(null)}");
        }
    }

    /// <summary>
    /// Para sessão em andamento.
    /// </summary>
    [RelayCommand]
    private async Task PararSessaoAsync()
    {
        if (_sessaoCts != null && SessaoEmAndamento)
        {
            _logger?.LogInformation("⏹️ Parando sessão biofeedback...");
            _sessaoCts.Cancel();

            // Parar emissão de áudio
            if (_emissionService != null)
            {
                await _emissionService.StopAsync();
            }
        }
    }

    /// <summary>
    /// Dispose pattern (CA1063 compliant).
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _sessaoCts?.Cancel();
            _sessaoCts?.Dispose();
            _sessaoCts = null;
        }
        _disposed = true;
    }

    // NOTA: StartAsync, Pause, Stop, EStop são comandos legados (manter por compatibilidade)
    // Nova arquitetura usa modal BiofeedbackSessionWindow com loop autónomo

    /* LEGADO - Comentado (dependia de ActiveList obsoleto)
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
    */
}
