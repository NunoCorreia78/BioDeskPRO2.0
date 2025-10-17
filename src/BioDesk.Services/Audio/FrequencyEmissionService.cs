using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NAudio.Wave;
using NAudio.Wave.SampleProviders;
using NAudio.CoreAudioApi;

namespace BioDesk.Services.Audio;

/// <summary>
/// Implementação real de emissão de frequências via NAudio + WASAPI.
///
/// MÉTODO COMPROVADO (CoRe System):
/// 1. Detecta TiePie Handyscope HS3 (interface USB de áudio)
/// 2. Gera tons com SignalGenerator (NAudio)
/// 3. Envia para dispositivo via WasapiOut
/// 4. HS3 converte sinal digital → emissão física
///
/// PARÂMETROS TÉCNICOS:
/// - Sample Rate: 44100 Hz
/// - Channels: 1 (Mono)
/// - Bit Depth: 16-bit
/// - Volume: 0-100% (70% padrão = ~7V no HS3)
/// </summary>
public sealed class FrequencyEmissionService : IFrequencyEmissionService
{
    private readonly ILogger<FrequencyEmissionService> _logger;
    private WasapiOut? _waveOut;
    private SignalGenerator? _signalGenerator;
    private AudioDevice? _currentDevice;
    private bool _isEmitting;
    private bool _disposed;
    private CancellationTokenSource? _emissionCts;

    // Constantes técnicas (baseadas em CoRe System)
    private const int SAMPLE_RATE = 44100;
    private const int CHANNELS = 1; // Mono
    private const double MIN_FREQUENCY = 10.0;
    private const double MAX_FREQUENCY = 20000.0;

    public AudioDevice? CurrentDevice => _currentDevice;
    public bool IsEmitting => _isEmitting;

    public FrequencyEmissionService(ILogger<FrequencyEmissionService> logger)
    {
        _logger = logger;
        _logger.LogInformation("🎵 FrequencyEmissionService inicializado");
    }

    /// <summary>
    /// Obtém dispositivos de áudio disponíveis, priorizando TiePie HS3.
    /// </summary>
    public Task<List<AudioDevice>> GetAvailableDevicesAsync()
    {
        var devices = new List<AudioDevice>();

        try
        {
            using var enumerator = new MMDeviceEnumerator();
            var endpoints = enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.Active);

            foreach (var endpoint in endpoints)
            {
                var device = new AudioDevice(
                    Id: endpoint.ID,
                    Name: endpoint.FriendlyName,
                    IsDefault: endpoint.ID == enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia).ID
                );
                devices.Add(device);

                _logger.LogDebug("🔊 Dispositivo detectado: {Name} (Default: {IsDefault})", device.Name, device.IsDefault);
            }

            // Priorizar TiePie HS3 se encontrado
            var tiepie = devices.FirstOrDefault(d =>
                d.Name.Contains("TiePie", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("Handyscope", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("HS3", StringComparison.OrdinalIgnoreCase));

            if (tiepie != null)
            {
                _logger.LogInformation("✅ TiePie Handyscope HS3 detectado: {Name}", tiepie.Name);
                devices.Remove(tiepie);
                devices.Insert(0, tiepie); // Colocar no topo
            }
            else
            {
                _logger.LogWarning("⚠️ TiePie HS3 não detectado - usando dispositivo padrão");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao enumerar dispositivos de áudio");
        }

        return Task.FromResult(devices);
    }

    /// <summary>
    /// Seleciona dispositivo para emissão (null = padrão do sistema).
    /// </summary>
    public async Task<bool> SelectDeviceAsync(string? deviceId = null)
    {
        try
        {
            // Limpar dispositivo anterior
            DisposeWaveOut();

            using var enumerator = new MMDeviceEnumerator();
            MMDevice? device;

            if (string.IsNullOrWhiteSpace(deviceId))
            {
                // Usar dispositivo padrão
                device = enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia);
                _logger.LogInformation("🔊 Selecionado dispositivo padrão: {Name}", device.FriendlyName);
            }
            else
            {
                // Buscar dispositivo específico
                var devices = await GetAvailableDevicesAsync();
                var targetDevice = devices.FirstOrDefault(d => d.Id == deviceId);

                if (targetDevice == null)
                {
                    _logger.LogError("❌ Dispositivo {DeviceId} não encontrado", deviceId);
                    return false;
                }

                device = enumerator.GetDevice(deviceId);
                _logger.LogInformation("🔊 Selecionado dispositivo: {Name}", device.FriendlyName);
            }

            _currentDevice = new AudioDevice(device.ID, device.FriendlyName, deviceId == null);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao selecionar dispositivo");
            return false;
        }
    }

    /// <summary>
    /// Emite frequência única com parâmetros especificados.
    /// </summary>
    public async Task<EmissionResult> EmitFrequencyAsync(
        double frequencyHz,
        int durationSeconds,
        int volumePercent = 70,
        WaveForm waveForm = WaveForm.Sine,
        CancellationToken cancellationToken = default)
    {
        // Validações
        if (frequencyHz < MIN_FREQUENCY || frequencyHz > MAX_FREQUENCY)
        {
            var msg = $"Frequência {frequencyHz} Hz fora do intervalo permitido ({MIN_FREQUENCY}-{MAX_FREQUENCY} Hz)";
            _logger.LogWarning("⚠️ {Message}", msg);
            return new EmissionResult(false, msg, frequencyHz, TimeSpan.Zero);
        }

        if (volumePercent < 0 || volumePercent > 100)
        {
            var msg = $"Volume {volumePercent}% inválido (0-100%)";
            _logger.LogWarning("⚠️ {Message}", msg);
            return new EmissionResult(false, msg, frequencyHz, TimeSpan.Zero);
        }

        if (_isEmitting)
        {
            var msg = "Emissão já em andamento";
            _logger.LogWarning("⚠️ {Message}", msg);
            return new EmissionResult(false, msg, frequencyHz, TimeSpan.Zero);
        }

        var startTime = DateTime.UtcNow;

        try
        {
            _isEmitting = true;
            _emissionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            _logger.LogInformation("🎵 Emitindo {Frequency} Hz por {Duration}s (Volume: {Volume}%, Forma: {WaveForm})",
                frequencyHz, durationSeconds, volumePercent, waveForm);

            // Selecionar dispositivo se não selecionado
            if (_currentDevice == null)
            {
                await SelectDeviceAsync(); // Padrão
            }

            // Criar gerador de sinal
            _signalGenerator = new SignalGenerator(SAMPLE_RATE, CHANNELS)
            {
                Frequency = frequencyHz,
                Gain = volumePercent / 100.0,
                Type = ConvertWaveForm(waveForm)
            };

            // Criar output WASAPI
            using var enumerator = new MMDeviceEnumerator();
            var device = _currentDevice != null
                ? enumerator.GetDevice(_currentDevice.Id)
                : enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia);

            _waveOut = new WasapiOut(device, AudioClientShareMode.Shared, false, 100);
            _waveOut.Init(_signalGenerator);
            _waveOut.Play();

            // Aguardar duração especificada ou cancelamento
            await Task.Delay(TimeSpan.FromSeconds(durationSeconds), _emissionCts.Token);

            _waveOut.Stop();

            var actualDuration = DateTime.UtcNow - startTime;
            _logger.LogInformation("✅ Emissão concluída: {Frequency} Hz ({Duration}s real)",
                frequencyHz, actualDuration.TotalSeconds);

            return new EmissionResult(true, "Emissão concluída com sucesso", frequencyHz, actualDuration);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("⏹️ Emissão cancelada: {Frequency} Hz", frequencyHz);
            return new EmissionResult(false, "Emissão cancelada pelo utilizador", frequencyHz, DateTime.UtcNow - startTime);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao emitir frequência {Frequency} Hz", frequencyHz);
            return new EmissionResult(false, $"Erro: {ex.Message}", frequencyHz, DateTime.UtcNow - startTime);
        }
        finally
        {
            _isEmitting = false;
            DisposeWaveOut();
            _emissionCts?.Dispose();
            _emissionCts = null;
        }
    }

    /// <summary>
    /// Emite lista de frequências sequencialmente (ciclo único).
    /// Para ciclo infinito, o chamador deve repetir este método.
    /// </summary>
    public async Task<EmissionResult> EmitFrequencyListAsync(
        IEnumerable<double> frequencies,
        int durationPerFrequencySeconds,
        int volumePercent = 70,
        WaveForm waveForm = WaveForm.Sine,
        Action<int, int, double>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var freqList = frequencies.ToList();
        if (freqList.Count == 0)
        {
            return new EmissionResult(false, "Lista de frequências vazia", 0, TimeSpan.Zero);
        }

        _logger.LogInformation("🎵 Iniciando emissão de {Count} frequências", freqList.Count);

        var startTime = DateTime.UtcNow;
        int currentIndex = 0;
        int totalFrequencies = freqList.Count;

        try
        {
            foreach (var freq in freqList)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    _logger.LogInformation("⏹️ Emissão de lista cancelada no índice {Index}", currentIndex);
                    break;
                }

                currentIndex++;
                progressCallback?.Invoke(currentIndex, totalFrequencies, freq);

                var result = await EmitFrequencyAsync(freq, durationPerFrequencySeconds, volumePercent, waveForm, cancellationToken);

                if (!result.Success && !cancellationToken.IsCancellationRequested)
                {
                    _logger.LogWarning("⚠️ Falha ao emitir {Frequency} Hz: {Message}", freq, result.Message);
                }
            }

            var totalDuration = DateTime.UtcNow - startTime;
            _logger.LogInformation("✅ Emissão de lista concluída: {Count} frequências em {Duration}s",
                currentIndex, totalDuration.TotalSeconds);

            return new EmissionResult(true, $"{currentIndex} frequências emitidas", 0, totalDuration);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao emitir lista de frequências");
            return new EmissionResult(false, $"Erro: {ex.Message}", 0, DateTime.UtcNow - startTime);
        }
    }

    /// <summary>
    /// Testa emissão com Lá musical (440 Hz) por 2 segundos.
    /// </summary>
    public async Task<EmissionResult> TestEmissionAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("🎹 Teste de emissão: 440 Hz (Lá musical)");
        return await EmitFrequencyAsync(440, 2, 70, WaveForm.Sine, cancellationToken);
    }

    /// <summary>
    /// Para emissão atual.
    /// </summary>
    public Task StopAsync()
    {
        _emissionCts?.Cancel();
        DisposeWaveOut();
        _isEmitting = false;
        _logger.LogInformation("⏹️ Emissão parada");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Converte WaveForm para SignalGeneratorType (NAudio).
    /// </summary>
    private static SignalGeneratorType ConvertWaveForm(WaveForm waveForm) => waveForm switch
    {
        WaveForm.Sine => SignalGeneratorType.Sin,
        WaveForm.Square => SignalGeneratorType.Square,
        WaveForm.Triangle => SignalGeneratorType.Triangle,
        WaveForm.Sawtooth => SignalGeneratorType.SawTooth,
        _ => SignalGeneratorType.Sin
    };

    /// <summary>
    /// Libera recursos WaveOut/SignalGenerator.
    /// </summary>
    private void DisposeWaveOut()
    {
        if (_waveOut != null)
        {
            try
            {
                if (_waveOut.PlaybackState == PlaybackState.Playing)
                {
                    _waveOut.Stop();
                }
                _waveOut.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ Erro ao liberar WaveOut");
            }
            finally
            {
                _waveOut = null;
            }
        }

        _signalGenerator = null;
    }

    /// <summary>
    /// Dispose pattern (CA1063 compliant).
    /// </summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        DisposeWaveOut();
        _emissionCts?.Cancel();
        _emissionCts?.Dispose();
        _emissionCts = null;

        _disposed = true;
        _logger.LogInformation("🗑️ FrequencyEmissionService liberado");
    }
}
