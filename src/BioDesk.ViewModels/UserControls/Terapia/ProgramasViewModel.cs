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
/// EventArgs para solicitação de terapia local.
/// Contém lista de frequências (Hz) extraídas dos protocolos selecionados.
/// </summary>
public class TerapiaLocalRequestedEventArgs : EventArgs
{
    public List<FrequenciaInfo> Frequencias { get; }

    public TerapiaLocalRequestedEventArgs(List<FrequenciaInfo> frequencias)
    {
        Frequencias = frequencias;
    }
}

/// <summary>
/// Informação de uma frequência para terapia local.
/// </summary>
public record FrequenciaInfo(double Hz, int DutyPercent, int DuracaoSegundos);

public partial class ProgramasViewModel : ObservableObject, IDisposable
{
    private readonly IProgramLibrary _library;
    private readonly IFrequencyEmissionService? _emissionService;
    private readonly ITerapiaStateService? _stateService;
    private readonly ILogger<ProgramasViewModel>? _logger;
    private CancellationTokenSource? _terapiaCts;
    private bool _disposed;

    [ObservableProperty] private string _search = string.Empty;
    [ObservableProperty] private string? _selectedProgram;

    public ObservableCollection<string> Programs { get; } = new();
    public ObservableCollection<string> SelectedPrograms { get; } = new(); // Seleção múltipla
    public ObservableCollection<ProgramStepVM> SelectedProgramSteps { get; } = new();

    // Propriedades de progresso de terapia
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(IniciarTerapiaLocalCommand))]
    private bool _terapiaEmAndamento = false;
    [ObservableProperty] private string _programaAtual = "";
    [ObservableProperty] private string _frequenciaAtual = "";
    [ObservableProperty] private int _tempoRestanteSegundos = 0;
    [ObservableProperty] private int _frequenciaAtualIndex = 0;
    [ObservableProperty] private int _totalFrequencias = 0;
    [ObservableProperty] private double _progressoPercentual = 0;

    /// <summary>
    /// Evento disparado quando user pede para iniciar terapia local.
    /// View (XAML.cs) escuta este evento e abre TerapiaLocalWindow.
    /// </summary>
    public event EventHandler<TerapiaLocalRequestedEventArgs>? TerapiaLocalRequested;

    public ProgramasViewModel(
        IProgramLibrary library,
        IFrequencyEmissionService? emissionService = null,
        ITerapiaStateService? stateService = null,
        ILogger<ProgramasViewModel>? logger = null)
    {
        _library = library;
        _emissionService = emissionService;
        _stateService = stateService;
        _logger = logger;

        // Auto-load ao instanciar
        _ = LoadAllProgramsAsync();
    }

    private async Task LoadAllProgramsAsync()
    {
        Programs.Clear();
        var list = await _library.ListProgramsAsync(null, CancellationToken.None);
        foreach (var program in list)
        {
            Programs.Add(program);
        }
    }

    partial void OnSearchChanged(string value)
    {
        _ = FilterProgramsAsync(value);
    }

    private async Task FilterProgramsAsync(string searchTerm)
    {
        Programs.Clear();
        var list = await _library.ListProgramsAsync(searchTerm, CancellationToken.None);
        foreach (var program in list)
        {
            Programs.Add(program);
        }
    }

    partial void OnSelectedProgramChanged(string? value)
    {
        _ = LoadProgramAsync(value);
    }

    private async Task LoadProgramAsync(string? value)
    {
        SelectedProgramSteps.Clear();
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        var steps = await _library.GetProgramAsync(value, CancellationToken.None);
        var index = 1;
        foreach (var step in steps)
        {
            SelectedProgramSteps.Add(new ProgramStepVM(index++, step.Hz, step.Duty, step.Seconds, step.Notes));
        }
    }

    /// <summary>
    /// Verifica se pode iniciar terapia local.
    /// </summary>
    private bool CanIniciarTerapiaLocal(TerapiaParametros? parametros)
    {
        var podeExecutar = !TerapiaEmAndamento;
        System.Diagnostics.Debug.WriteLine($"🔐 CanIniciarProgramas? {podeExecutar} (TerapiaEmAndamento={TerapiaEmAndamento})");
        return podeExecutar;
    }

    /// <summary>
    /// Inicia terapia local diretamente com progresso em tempo real.
    /// Executa todos os protocolos selecionados sequencialmente.
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanIniciarTerapiaLocal))]
    private async Task IniciarTerapiaLocalAsync(TerapiaParametros parametros)
    {
        System.Diagnostics.Debug.WriteLine("🚀 ProgramasViewModel: IniciarTerapiaLocalAsync CHAMADO");
        System.Diagnostics.Debug.WriteLine($"📦 Parâmetros recebidos: V={parametros.VoltagemV}, Duração={parametros.DuracaoTotalMinutos}min, Tempo/Freq={parametros.TempoFrequenciaSegundos}s");

        if (TerapiaEmAndamento)
        {
            System.Diagnostics.Debug.WriteLine("⚠️ ProgramasViewModel: Terapia já em andamento, ignorando");
            return;
        }

        // Processar múltiplos protocolos selecionados
        var programsToAdd = SelectedPrograms.Count > 0
            ? SelectedPrograms.ToList()
            : (SelectedProgram != null ? new List<string> { SelectedProgram } : new List<string>());

        if (programsToAdd.Count == 0)
        {
            // TODO: Mostrar mensagem ao user "Nenhum protocolo selecionado"
            return;
        }

        // Buscar Hz reais da BD para todos os protocolos
        var todasFrequencias = new List<(string Programa, FrequenciaInfo Freq)>();
        foreach (var program in programsToAdd)
        {
            if (string.IsNullOrWhiteSpace(program)) continue;

            var steps = await _library.GetProgramAsync(program!, CancellationToken.None);
            foreach (var step in steps)
            {
                todasFrequencias.Add((program, new FrequenciaInfo(
                    Hz: step.Hz,
                    DutyPercent: (int)step.Duty,
                    DuracaoSegundos: step.Seconds)));
            }
        }

        if (todasFrequencias.Count == 0)
        {
            // TODO: Mostrar mensagem "Nenhuma frequência encontrada"
            return;
        }

        TerapiaEmAndamento = true;
        TotalFrequencias = todasFrequencias.Count;
        FrequenciaAtualIndex = 0;

        // Criar CancellationToken para parar emissão
        _terapiaCts = new CancellationTokenSource();

        try
        {
            // CICLO INFINITO: Repete todas as frequências continuamente
            int cicloAtual = 1;
            while (TerapiaEmAndamento) // Continua até user cancelar
            {
                System.Diagnostics.Debug.WriteLine($"🔄 ProgramasViewModel: CICLO {cicloAtual} INICIADO");
                FrequenciaAtualIndex = 0;

                // Executar cada frequência com contagem decrescente
                foreach (var (programa, freq) in todasFrequencias)
                {
                    if (_terapiaCts.Token.IsCancellationRequested)
                    {
                        break;
                    }

                    FrequenciaAtualIndex++;
                    ProgramaAtual = $"[Ciclo {cicloAtual}] {programa}";
                    FrequenciaAtual = $"{freq.Hz:F2} Hz (Duty: {freq.DutyPercent}%)";
                    TempoRestanteSegundos = parametros.TempoFrequenciaSegundos > 0
                        ? parametros.TempoFrequenciaSegundos
                        : freq.DuracaoSegundos;

                    int duracaoTotal = TempoRestanteSegundos;

                    // ✅ EMISSÃO REAL DE FREQUÊNCIA (NAudio + WASAPI)
                    if (_emissionService != null)
                    {
                        _logger?.LogInformation("🎵 Emitindo {Hz} Hz por {Duration}s (Programa: {Program})",
                            freq.Hz, duracaoTotal, programa);

                        // Obter configurações do TerapiaStateService
                        var volume = _stateService?.VolumePercent ?? 70;
                        var waveForm = _stateService?.FormaOnda ?? WaveForm.Sine;

                        // Task de emissão (não-bloqueante)
                        var emissionTask = _emissionService.EmitFrequencyAsync(
                            frequencyHz: freq.Hz,
                            durationSeconds: duracaoTotal,
                            volumePercent: volume,
                            waveForm: waveForm,
                            cancellationToken: _terapiaCts.Token);

                        // Contagem decrescente paralela à emissão
                        while (TempoRestanteSegundos > 0 && !_terapiaCts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(1000, _terapiaCts.Token);
                            TempoRestanteSegundos--;
                            ProgressoPercentual = ((FrequenciaAtualIndex - 1) * 100.0 / TotalFrequencias) +
                                                 ((duracaoTotal - TempoRestanteSegundos) * 100.0 / (TotalFrequencias * duracaoTotal));
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
                        // Fallback: Simulação sem hardware
                        while (TempoRestanteSegundos > 0 && !_terapiaCts.Token.IsCancellationRequested)
                        {
                            await Task.Delay(1000, _terapiaCts.Token);
                            TempoRestanteSegundos--;
                            ProgressoPercentual = ((FrequenciaAtualIndex - 1) * 100.0 / TotalFrequencias) +
                                                 ((duracaoTotal - TempoRestanteSegundos) * 100.0 / (TotalFrequencias * duracaoTotal));
                        }
                    }
                }

                if (_terapiaCts.Token.IsCancellationRequested)
                {
                    break;
                }

                ProgressoPercentual = 100;
                FrequenciaAtual = $"Ciclo {cicloAtual} concluído! Iniciando próximo...";
                cicloAtual++;
                await Task.Delay(2000, _terapiaCts.Token); // Pausa de 2s entre ciclos
            }
        }
        catch (OperationCanceledException)
        {
            System.Diagnostics.Debug.WriteLine("⏹️ Terapia cancelada pelo utilizador");
            _logger?.LogInformation("⏹️ Terapia de programas cancelada");
        }
        finally
        {
            Debug.WriteLine($"🏁 ProgramasViewModel: FINALLY - Estado ANTES: TerapiaEmAndamento={TerapiaEmAndamento}");
            TerapiaEmAndamento = false;
            _terapiaCts?.Dispose();
            _terapiaCts = null;
            Debug.WriteLine($"🏁 ProgramasViewModel: FINALLY - Estado DEPOIS de set false: TerapiaEmAndamento={TerapiaEmAndamento}");
            Debug.WriteLine($"🔓 ProgramasViewModel: CanIniciarTerapiaLocal agora = {CanIniciarTerapiaLocal(null)}");
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
            _logger?.LogInformation("⏹️ Parando terapia de programas...");
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

public sealed record ProgramStepVM(int Index, double Hz, double Duty, int Seconds, string? Notes);
