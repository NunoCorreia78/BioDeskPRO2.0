using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Services.Hardware.TiePie;
using Microsoft.Extensions.Logging;
using NAudio.CoreAudioApi;
using NAudio.Wave;
using NAudio.Wave.SampleProviders;

namespace BioDesk.Services.Audio;

/// <summary>
/// Emits frequencies either through standard Windows audio devices (NAudio/WASAPI)
/// or directly through the TiePie Handyscope HS3 hardware.
/// </summary>
public sealed class FrequencyEmissionService : IFrequencyEmissionService
{
    private const int SampleRate = 44100;
    private const int Channels = 1;
    private const double MinFrequency = 10.0;
    private const double MaxFrequency = 20000.0;
    private const string Hs3DeviceId = "HS3_HARDWARE";

    private readonly ILogger<FrequencyEmissionService> _logger;
    private readonly ITiePieHS3Service? _hs3Service;

    private WasapiOut? _waveOut;
    private SignalGenerator? _signalGenerator;
    private AudioDevice? _currentDevice;
    private bool _isEmitting;
    private bool _disposed;
    private CancellationTokenSource? _emissionCts;

    private bool IsHs3Selected =>
        _currentDevice != null &&
        string.Equals(_currentDevice.Id, Hs3DeviceId, StringComparison.OrdinalIgnoreCase);

    public AudioDevice? CurrentDevice => _currentDevice;
    public bool IsEmitting => _isEmitting;

    public FrequencyEmissionService(ILogger<FrequencyEmissionService> logger, ITiePieHS3Service? hs3Service = null)
    {
        _logger = logger;
        _hs3Service = hs3Service;
        _logger.LogInformation("FrequencyEmissionService inicializado");
    }

    public Task<List<AudioDevice>> GetAvailableDevicesAsync()
    {
        var devices = new List<AudioDevice>();

        try
        {
            using var enumerator = new MMDeviceEnumerator();
            var defaultEndpoint = enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia);
            var endpoints = enumerator.EnumerateAudioEndPoints(DataFlow.Render, DeviceState.Active);

            foreach (var endpoint in endpoints)
            {
                var device = new AudioDevice(
                    endpoint.ID,
                    endpoint.FriendlyName,
                    endpoint.ID == defaultEndpoint.ID);

                devices.Add(device);
                _logger.LogDebug("Dispositivo de audio detectado: {Name} (Default: {IsDefault})", device.Name, device.IsDefault);
            }

            var tiePie = devices.FirstOrDefault(d =>
                d.Name.Contains("TiePie", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("Handyscope", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("HS3", StringComparison.OrdinalIgnoreCase));

            if (tiePie != null)
            {
                _logger.LogInformation("TiePie Handyscope HS3 detectado na lista de audio: {Name}", tiePie.Name);
                devices.Remove(tiePie);
                devices.Insert(0, tiePie);
            }
            else
            {
                _logger.LogWarning("TiePie HS3 nao aparece como dispositivo de audio Windows (provavelmente modo direto).");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao enumerar dispositivos de audio");
        }

        return Task.FromResult(devices);
    }

    public async Task<bool> SelectDeviceAsync(string? deviceId = null)
    {
        try
        {
            DisposeWaveOut();

            if (string.Equals(deviceId, Hs3DeviceId, StringComparison.OrdinalIgnoreCase))
            {
                if (_hs3Service == null)
                {
                    _logger.LogWarning("Servico TiePie HS3 nao disponivel (DI nao injetou instancias).");
                    return false;
                }

                if (!await _hs3Service.InitializeAsync())
                {
                    _logger.LogWarning("Falha ao inicializar TiePie HS3. Mantendo dispositivo anterior.");
                    return false;
                }

                _currentDevice = new AudioDevice(
                    Hs3DeviceId,
                    $"TiePie HS3 (SN: {_hs3Service.SerialNumber})",
                    false);

                _logger.LogInformation("TiePie HS3 selecionado para emissao direta.");
                return true;
            }

            using var enumerator = new MMDeviceEnumerator();
            MMDevice device;

            if (string.IsNullOrWhiteSpace(deviceId))
            {
                device = enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia);
                _logger.LogInformation("Selecionado dispositivo padrao: {Name}", device.FriendlyName);
            }
            else
            {
                var devices = await GetAvailableDevicesAsync();
                var targetDevice = devices.FirstOrDefault(d => d.Id == deviceId);

                if (targetDevice == null)
                {
                    _logger.LogError("Dispositivo {DeviceId} nao encontrado", deviceId);
                    return false;
                }

                device = enumerator.GetDevice(deviceId);
                _logger.LogInformation("Selecionado dispositivo: {Name}", device.FriendlyName);
            }

            _currentDevice = new AudioDevice(device.ID, device.FriendlyName, string.IsNullOrWhiteSpace(deviceId));
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao selecionar dispositivo");
            return false;
        }
    }

    public async Task<EmissionResult> EmitFrequencyAsync(
        double frequencyHz,
        int durationSeconds,
        int volumePercent = 70,
        WaveForm waveForm = WaveForm.Sine,
        CancellationToken cancellationToken = default)
    {
        if (frequencyHz < MinFrequency || frequencyHz > MaxFrequency)
        {
            var msg = $"Frequencia {frequencyHz} Hz fora do intervalo permitido ({MinFrequency}-{MaxFrequency} Hz)";
            _logger.LogWarning(msg);
            return new EmissionResult(false, msg, frequencyHz, TimeSpan.Zero);
        }

        if (volumePercent < 0 || volumePercent > 100)
        {
            var msg = $"Volume {volumePercent}% invalido (0-100%)";
            _logger.LogWarning(msg);
            return new EmissionResult(false, msg, frequencyHz, TimeSpan.Zero);
        }

        if (_isEmitting)
        {
            var msg = "Ja existe uma emissao em andamento";
            _logger.LogWarning(msg);
            return new EmissionResult(false, msg, frequencyHz, TimeSpan.Zero);
        }

        _logger.LogInformation("Emitindo {Frequency} Hz por {Duration}s (Volume: {Volume}%, Wave: {Wave})",
            frequencyHz, durationSeconds, volumePercent, waveForm);

        _isEmitting = true;
        _emissionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        try
        {
            if (IsHs3Selected)
            {
                return await EmitWithHs3Async(frequencyHz, durationSeconds, volumePercent, waveForm, _emissionCts.Token);
            }

            if (_currentDevice == null)
            {
                await SelectDeviceAsync();
            }

            return await EmitWithAudioAsync(frequencyHz, durationSeconds, volumePercent, waveForm, _emissionCts.Token);
        }
        finally
        {
            _isEmitting = false;
            _emissionCts?.Dispose();
            _emissionCts = null;
        }
    }

    public async Task<EmissionResult> EmitFrequencyListAsync(
        IEnumerable<double> frequencies,
        int durationPerFrequencySeconds,
        int volumePercent = 70,
        WaveForm waveForm = WaveForm.Sine,
        Action<int, int, double>? progressCallback = null,
        CancellationToken cancellationToken = default)
    {
        var list = frequencies.ToList();
        if (list.Count == 0)
        {
            return new EmissionResult(false, "Lista de frequencias vazia", 0, TimeSpan.Zero);
        }

        _logger.LogInformation("Iniciando emissao sequencial de {Count} frequencias", list.Count);

        var startTime = DateTime.UtcNow;
        int index = 0;

        try
        {
            foreach (var frequency in list)
            {
                if (cancellationToken.IsCancellationRequested)
                {
                    _logger.LogInformation("Emissao sequencial cancelada no indice {Index}", index);
                    break;
                }

                index++;
                progressCallback?.Invoke(index, list.Count, frequency);

                var result = await EmitFrequencyAsync(
                    frequency,
                    durationPerFrequencySeconds,
                    volumePercent,
                    waveForm,
                    cancellationToken);

                if (!result.Success && !cancellationToken.IsCancellationRequested)
                {
                    _logger.LogWarning("Falha ao emitir {Frequency} Hz: {Message}", frequency, result.Message);
                }
            }

            var total = DateTime.UtcNow - startTime;
            return new EmissionResult(true, $"{index} frequencias emitidas", 0, total);
        }
        catch (Exception ex)
        {
            var elapsed = DateTime.UtcNow - startTime;
            _logger.LogError(ex, "Erro ao emitir lista de frequencias");
            return new EmissionResult(false, $"Erro: {ex.Message}", 0, elapsed);
        }
    }

    public Task<EmissionResult> TestEmissionAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Teste rapido de emissao: 440 Hz por 2 segundos");
        return EmitFrequencyAsync(440, 2, 70, WaveForm.Sine, cancellationToken);
    }

    public async Task StopAsync()
    {
        _emissionCts?.Cancel();

        if (IsHs3Selected && _hs3Service != null)
        {
            try
            {
                await _hs3Service.StopEmissionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Erro ao parar emissao HS3");
            }
        }

        DisposeWaveOut();
        _isEmitting = false;
        _logger.LogInformation("Emissao parada manualmente");
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _emissionCts?.Cancel();
        _emissionCts?.Dispose();
        _emissionCts = null;

        DisposeWaveOut();

        _disposed = true;
        _logger.LogInformation("FrequencyEmissionService libertado");
    }

    private async Task<EmissionResult> EmitWithAudioAsync(
        double frequencyHz,
        int durationSeconds,
        int volumePercent,
        WaveForm waveForm,
        CancellationToken cancellationToken)
    {
        var startTime = DateTime.UtcNow;

        try
        {
            _signalGenerator = new SignalGenerator(SampleRate, Channels)
            {
                Frequency = frequencyHz,
                Gain = volumePercent / 100.0,
                Type = ConvertWaveForm(waveForm)
            };

            using var enumerator = new MMDeviceEnumerator();
            var device = _currentDevice != null
                ? enumerator.GetDevice(_currentDevice.Id)
                : enumerator.GetDefaultAudioEndpoint(DataFlow.Render, Role.Multimedia);

            _waveOut = new WasapiOut(device, AudioClientShareMode.Shared, false, 100);
            _waveOut.Init(_signalGenerator);
            _waveOut.Play();

            await Task.Delay(TimeSpan.FromSeconds(durationSeconds), cancellationToken);

            _waveOut.Stop();

            var elapsed = DateTime.UtcNow - startTime;
            _logger.LogInformation("Emissao via audio concluida: {Frequency} Hz ({Duration}s)", frequencyHz, elapsed.TotalSeconds);
            return new EmissionResult(true, "Emissao concluida com sucesso", frequencyHz, elapsed);
        }
        catch (OperationCanceledException)
        {
            var elapsed = DateTime.UtcNow - startTime;
            _logger.LogInformation("Emissao via audio cancelada: {Frequency} Hz", frequencyHz);
            return new EmissionResult(false, "Emissao cancelada pelo utilizador", frequencyHz, elapsed);
        }
        catch (Exception ex)
        {
            var elapsed = DateTime.UtcNow - startTime;
            _logger.LogError(ex, "Erro ao emitir frequencia {Frequency} Hz via audio", frequencyHz);
            return new EmissionResult(false, $"Erro: {ex.Message}", frequencyHz, elapsed);
        }
        finally
        {
            DisposeWaveOut();
        }
    }

    private async Task<EmissionResult> EmitWithHs3Async(
        double frequencyHz,
        int durationSeconds,
        int volumePercent,
        WaveForm waveForm,
        CancellationToken cancellationToken)
    {
        if (_hs3Service == null)
        {
            return new EmissionResult(false, "Servico TiePie HS3 nao disponivel", frequencyHz, TimeSpan.Zero);
        }

        if (!_hs3Service.IsConnected)
        {
            if (!await _hs3Service.InitializeAsync())
            {
                return new EmissionResult(false, "TiePie HS3 nao pode ser inicializado", frequencyHz, TimeSpan.Zero);
            }
        }

        var amplitude = ConvertVolumePercentToAmplitude(volumePercent);
        var waveform = MapWaveformToHs3(waveForm);
        var startTime = DateTime.UtcNow;

        try
        {
            var started = await _hs3Service.EmitFrequencyAsync(frequencyHz, amplitude, waveform);
            if (!started)
            {
                return new EmissionResult(false, "TiePie HS3 rejeitou os parametros solicitados", frequencyHz, TimeSpan.Zero);
            }

            try
            {
                await Task.Delay(TimeSpan.FromSeconds(durationSeconds), cancellationToken);
                var elapsed = DateTime.UtcNow - startTime;
                _logger.LogInformation("Emissao HS3 concluida: {Frequency} Hz ({Duration}s)", frequencyHz, elapsed.TotalSeconds);
                return new EmissionResult(true, "Emissao concluida com sucesso (HS3)", frequencyHz, elapsed);
            }
            catch (OperationCanceledException)
            {
                var elapsed = DateTime.UtcNow - startTime;
                _logger.LogInformation("Emissao HS3 cancelada: {Frequency} Hz", frequencyHz);
                return new EmissionResult(false, "Emissao cancelada pelo utilizador", frequencyHz, elapsed);
            }
        }
        catch (Exception ex)
        {
            var elapsed = DateTime.UtcNow - startTime;
            _logger.LogError(ex, "Erro ao emitir frequencia {Frequency} Hz via TiePie HS3", frequencyHz);
            return new EmissionResult(false, $"Erro: {ex.Message}", frequencyHz, elapsed);
        }
        finally
        {
            try
            {
                await _hs3Service.StopEmissionAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao parar emissao HS3");
            }
        }
    }

    private static SignalGeneratorType ConvertWaveForm(WaveForm waveForm) => waveForm switch
    {
        WaveForm.Sine => SignalGeneratorType.Sin,
        WaveForm.Square => SignalGeneratorType.Square,
        WaveForm.Triangle => SignalGeneratorType.Triangle,
        WaveForm.Sawtooth => SignalGeneratorType.SawTooth,
        _ => SignalGeneratorType.Sin
    };

    private static string MapWaveformToHs3(WaveForm waveForm) => waveForm switch
    {
        WaveForm.Sine => "Sine",
        WaveForm.Square => "Square",
        WaveForm.Triangle => "Triangle",
        WaveForm.Sawtooth => "Triangle",
        _ => "Sine"
    };

    private static double ConvertVolumePercentToAmplitude(int volumePercent)
    {
        var amplitude = Math.Clamp(volumePercent, 0, 100) / 10.0;
        return amplitude <= 0 ? 0.1 : amplitude;
    }

    private void DisposeWaveOut()
    {
        if (_waveOut == null)
        {
            return;
        }

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
            _logger.LogWarning(ex, "Erro ao libertar recursos de audio");
        }
        finally
        {
            _waveOut = null;
            _signalGenerator = null;
        }
    }
}
