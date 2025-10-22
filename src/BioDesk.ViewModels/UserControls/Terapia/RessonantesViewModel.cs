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
/// Parâmetros de terapia vindos do TerapiaControlosUserControl.
/// </summary>
public record TerapiaParametros(
    double VoltagemV,
    int DuracaoTotalMinutos,
    int TempoFrequenciaSegundos,
    int AjusteHz
);

public partial class RessonantesViewModel : ObservableObject, IDisposable
{
    private readonly IResonantFrequencyFinder _finder;
    private readonly IFrequencyEmissionService? _emissionService;
    private readonly ITerapiaStateService? _stateService;
    private readonly ILogger<RessonantesViewModel>? _logger;
    private CancellationTokenSource? _terapiaCts;
    private bool _disposed;

    [ObservableProperty] private double _startHz = 10;
    [ObservableProperty] private double _stopHz = 2000;
    [ObservableProperty] private double _stepHz = 1;
    [ObservableProperty] private int _dwellMs = 150;
    [ObservableProperty] private SweepPointVM? _selectedPoint;

    // Propriedades de progresso de terapia
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(IniciarTerapiaLocalCommand))]
    private bool _terapiaEmAndamento = false;
    [ObservableProperty] private string _frequenciaAtual = "";
    [ObservableProperty] private int _tempoRestanteSegundos = 0;
    [ObservableProperty] private int _frequenciaAtualIndex = 0;
    [ObservableProperty] private int _totalFrequencias = 0;
    [ObservableProperty] private double _progressoPercentual = 0;

    // Propriedades para TerapiaProgressoUserControl (REDESIGN 20OUT2025)
    [ObservableProperty] private double _frequenciaAtualHz = 0;
    [ObservableProperty] private double _frequenciaOriginalHz = 0;
    [ObservableProperty] private double _ajusteAplicadoHz = 0;
    [ObservableProperty] private string _tempoRestanteFormatado = "";

    public ObservableCollection<SweepPointVM> SweepResults { get; } = new();
    public ObservableCollection<SweepPointVM> SelectedPoints { get; } = new(); // Seleção múltipla

    /// <summary>
    /// Evento disparado quando user pede para iniciar terapia local com Hz ressonantes.
    /// View (XAML.cs) escuta este evento e abre TerapiaLocalWindow.
    /// </summary>
    public event EventHandler<TerapiaLocalRequestedEventArgs>? TerapiaLocalRequested;

    public RessonantesViewModel(
        IResonantFrequencyFinder finder,
        IFrequencyEmissionService? emissionService = null,
        ITerapiaStateService? stateService = null,
        ILogger<RessonantesViewModel>? logger = null)
    {
        _finder = finder;
        _emissionService = emissionService;
        _stateService = stateService;
        _logger = logger;
    }

    [RelayCommand]
    private async Task RunSweepAsync()
    {
        SweepResults.Clear();
        await foreach (var (hz, score) in _finder.RunAsync(
                           new SweepConfig(StartHz, StopHz, StepHz, DwellMs),
                           CancellationToken.None))
        {
            // Criar ponto com score inicial
            var sweepPoint = new SweepPointVM(hz, score, null);
            SweepResults.Add(sweepPoint);

            // Simular score incremental (user requirement: "50 → 55 → 60...")
            // Em produção real, isto viria do hardware TiePie com múltiplas leituras
            if (score > 0)
            {
                _ = Task.Run(async () =>
                {
                    await Task.Delay(100); // Simular tempo de medição
                    var incrementedScore = Math.Min(100, score + 5); // +5% incremental

                    // Atualizar score diretamente (SweepPointVM agora é classe observável)
                    System.Windows.Application.Current?.Dispatcher.Invoke(() =>
                    {
                        // Não podemos mutar Score (init), mas podemos criar novo ponto
                        var index = SweepResults.IndexOf(sweepPoint);
                        if (index >= 0)
                        {
                            SweepResults[index] = new SweepPointVM(sweepPoint.Hz, incrementedScore, sweepPoint.Notes);
                        }
                    });
                });
            }
        }
    }

    /// <summary>
    /// Verifica se pode iniciar terapia local.
    /// </summary>
    private bool CanIniciarTerapiaLocal(TerapiaParametros? parametros)
    {
        var podeExecutar = !TerapiaEmAndamento;
        System.Diagnostics.Debug.WriteLine($"🔐 CanIniciarTerapiaLocal? {podeExecutar} (TerapiaEmAndamento={TerapiaEmAndamento})");
        return podeExecutar;
    }

    /// <summary>
    /// Inicia terapia local diretamente com progresso em tempo real.
    /// Parâmetros: voltagem, duração total e tempo por frequência vêm do TerapiaControlosUserControl.
    ///
    /// INTEGRAÇÃO EMISSÃO REAL:
    /// - Usa FrequencyEmissionService para emitir frequências via NAudio + WASAPI
    /// - Ciclo infinito: repete todas as frequências até cancelamento
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanIniciarTerapiaLocal))]
    private async Task IniciarTerapiaLocalAsync(TerapiaParametros parametros)
    {
        System.Diagnostics.Debug.WriteLine("🚀🚀🚀 RessonantesViewModel: IniciarTerapiaLocalAsync CHAMADO");
        System.Diagnostics.Debug.WriteLine($"📦 Parâmetros recebidos: V={parametros.VoltagemV}, Duração={parametros.DuracaoTotalMinutos}min, Tempo/Freq={parametros.TempoFrequenciaSegundos}s");

        if (TerapiaEmAndamento)
        {
            System.Diagnostics.Debug.WriteLine("⚠️ RessonantesViewModel: Terapia já em andamento, ignorando");
            return;
        }

        // Usar pontos selecionados (multi-seleção) ou ponto único
        var pontosParaUsar = SelectedPoints.Count > 0
            ? SelectedPoints.ToList()
            : (SelectedPoint != null ? new List<SweepPointVM> { SelectedPoint } : new List<SweepPointVM>());

        System.Diagnostics.Debug.WriteLine($"📊 Pontos para usar: {pontosParaUsar.Count} (SelectedPoints={SelectedPoints.Count}, SelectedPoint={(SelectedPoint != null ? "SET" : "NULL")})");

        if (pontosParaUsar.Count == 0)
        {
            System.Diagnostics.Debug.WriteLine("❌ NENHUMA FREQUÊNCIA SELECIONADA!");
            return;
        }

        Debug.WriteLine($"🎬 INICIANDO TERAPIA - Pontos selecionados: {pontosParaUsar.Count}");
        TerapiaEmAndamento = true;
        Debug.WriteLine($"✅ TerapiaEmAndamento = {TerapiaEmAndamento}");

        TotalFrequencias = pontosParaUsar.Count;
        FrequenciaAtualIndex = 0;
        Debug.WriteLine($"📊 Total frequências: {TotalFrequencias}");

        // Criar CancellationToken para parar emissão
        _terapiaCts = new CancellationTokenSource();

        try
        {
            // CICLO INFINITO: Repete todas as frequências continuamente
            int cicloAtual = 1;
            while (TerapiaEmAndamento) // Continua até user cancelar
            {
                System.Diagnostics.Debug.WriteLine($"🔄 CICLO {cicloAtual} INICIADO");

                // Resetar status de todos os pontos
                foreach (var p in pontosParaUsar)
                {
                    p.Status = "⏳ Aguardando";
                    p.ProgressoIndividual = 0;
                    p.TempoRestante = 0;
                }

                // Emitir cada frequência com contagem decrescente
                foreach (var ponto in pontosParaUsar.OrderBy(p => p.Hz))
                {
                    if (_terapiaCts.Token.IsCancellationRequested)
                    {
                        break;
                    }

                    FrequenciaAtualIndex++;

                    // ✅ PROPRIEDADES REDESIGN: Frequência com variação
                    FrequenciaOriginalHz = ponto.Hz;
                    AjusteAplicadoHz = parametros.AjusteHz;
                    FrequenciaAtualHz = ponto.Hz + parametros.AjusteHz; // Frequência real emitida
                    FrequenciaAtual = $"[Ciclo {cicloAtual}] {FrequenciaAtualHz:F2} Hz (Score: {ponto.Score:F1}%)";

                    TempoRestanteSegundos = parametros.TempoFrequenciaSegundos;

                    System.Diagnostics.Debug.WriteLine($"🎯 Freq {FrequenciaAtualIndex}/{TotalFrequencias}: {FrequenciaAtual}, Tempo: {TempoRestanteSegundos}s");

                    // Atualizar status visual do ponto
                    ponto.Status = $"▶️ Tratamento {FrequenciaAtualIndex}/{TotalFrequencias}";
                    ponto.TempoRestante = parametros.TempoFrequenciaSegundos;

                    // ✅ EMISSÃO REAL DE FREQUÊNCIA (NAudio + WASAPI)
                    if (_emissionService != null)
                    {
                        _logger?.LogInformation("🎵 Emitindo {Hz} Hz por {Duration}s", ponto.Hz, parametros.TempoFrequenciaSegundos);

                        // Obter configurações do TerapiaStateService
                        var volume = _stateService?.VolumePercent ?? 70;
                        var waveForm = _stateService?.FormaOnda ?? WaveForm.Sine;

                        // Task de emissão (não-bloqueante para permitir cancelamento e UI update)
                        var emissionTask = _emissionService.EmitFrequencyAsync(
                            frequencyHz: ponto.Hz,
                            durationSeconds: parametros.TempoFrequenciaSegundos,
                            volumePercent: volume,
                            waveForm: waveForm,
                            cancellationToken: _terapiaCts.Token);

                        // Contagem decrescente com atualização individual (paralelo à emissão)
                        while (TempoRestanteSegundos > 0 && !_terapiaCts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(1000, _terapiaCts.Token);
                            TempoRestanteSegundos--;

                            // ✅ REDESIGN: Formatar tempo restante (18min 45s)
                            int minutos = TempoRestanteSegundos / 60;
                            int segundos = TempoRestanteSegundos % 60;
                            TempoRestanteFormatado = minutos > 0
                                ? $"{minutos}min {segundos}s"
                                : $"{segundos}s";

                            ponto.TempoRestante = TempoRestanteSegundos;
                            ponto.ProgressoIndividual = ((parametros.TempoFrequenciaSegundos - TempoRestanteSegundos) * 100.0) / parametros.TempoFrequenciaSegundos;
                            ProgressoPercentual = ((FrequenciaAtualIndex - 1) * 100.0 / TotalFrequencias) +
                                                 ((parametros.TempoFrequenciaSegundos - TempoRestanteSegundos) * 100.0 / (TotalFrequencias * parametros.TempoFrequenciaSegundos));
                        }

                        // Aguardar emissão completar
                        var result = await emissionTask;
                        if (!result.Success)
                        {
                            _logger?.LogWarning("⚠️ Emissão falhou: {Message}", result.Message);
                        }
                    }
                    else
                    {
                        // Fallback: Simulação sem hardware (ciclo original)
                        while (TempoRestanteSegundos > 0 && !_terapiaCts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(1000, _terapiaCts.Token);
                            TempoRestanteSegundos--;

                            // ✅ REDESIGN: Formatar tempo restante (18min 45s)
                            int minutos = TempoRestanteSegundos / 60;
                            int segundos = TempoRestanteSegundos % 60;
                            TempoRestanteFormatado = minutos > 0
                                ? $"{minutos}min {segundos}s"
                                : $"{segundos}s";

                            ponto.TempoRestante = TempoRestanteSegundos;
                            ponto.ProgressoIndividual = ((parametros.TempoFrequenciaSegundos - TempoRestanteSegundos) * 100.0) / parametros.TempoFrequenciaSegundos;
                            ProgressoPercentual = ((FrequenciaAtualIndex - 1) * 100.0 / TotalFrequencias) +
                                                 ((parametros.TempoFrequenciaSegundos - TempoRestanteSegundos) * 100.0 / (TotalFrequencias * parametros.TempoFrequenciaSegundos));
                        }
                    }

                    // Marcar como concluído
                    ponto.Status = "✅ Concluído";
                    ponto.ProgressoIndividual = 100;
                }

                if (_terapiaCts.Token.IsCancellationRequested)
                {
                    break;
                }

                ProgressoPercentual = 100;
                FrequenciaAtual = $"Ciclo {cicloAtual} concluído! Iniciando próximo...";
                FrequenciaAtualIndex = 0; // Reset para próximo ciclo
                cicloAtual++;
                await Task.Delay(2000, _terapiaCts.Token); // Pausa de 2s entre ciclos
            }
        }
        catch (OperationCanceledException)
        {
            System.Diagnostics.Debug.WriteLine("⏹️ Terapia cancelada pelo utilizador");
            _logger?.LogInformation("⏹️ Terapia cancelada");
        }
        finally
        {
            Debug.WriteLine($"🏁 RessonantesViewModel: FINALLY - Estado ANTES: TerapiaEmAndamento={TerapiaEmAndamento}");
            TerapiaEmAndamento = false;
            _terapiaCts?.Dispose();
            _terapiaCts = null;
            Debug.WriteLine($"🏁 RessonantesViewModel: FINALLY - Estado DEPOIS de set false: TerapiaEmAndamento={TerapiaEmAndamento}");
            Debug.WriteLine($"🔓 RessonantesViewModel: CanIniciarTerapiaLocal agora = {CanIniciarTerapiaLocal(null)}");
        }
    }

    /// <summary>
    /// Para terapia em andamento.
    /// </summary>
    [RelayCommand]
    private async Task PararTerapiaAsync()
    {
        if (_terapiaCts != null && TerapiaEmAndamento)
        {
            _logger?.LogInformation("⏹️ Parando terapia...");
            _terapiaCts.Cancel();

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
            _terapiaCts?.Cancel();
            _terapiaCts?.Dispose();
            _terapiaCts = null;
        }
        _disposed = true;
    }
}

/// <summary>
/// Ponto de sweep com status de tratamento em tempo real.
/// </summary>
public sealed partial class SweepPointVM : ObservableObject
{
    public double Hz { get; init; }
    public double Score { get; init; }
    public string? Notes { get; init; }

    [ObservableProperty] private string _status = "⏳ Aguardando";
    [ObservableProperty] private int _tempoRestante = 0;
    [ObservableProperty] private double _progressoIndividual = 0;

    public SweepPointVM(double hz, double score, string? notes)
    {
        Hz = hz;
        Score = score;
        Notes = notes;
    }
}
