using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Hardware.TiePie;

public interface ITiePieHS3Service : IDisposable
{
    /// <summary>
    /// Indicates whether the HS3 device is connected and initialized.
    /// </summary>
    bool IsConnected { get; }

    /// <summary>
    /// Device serial number (0 when not connected).
    /// </summary>
    uint SerialNumber { get; }

    /// <summary>
    /// Initializes the native library and opens the first HS3 device.
    /// </summary>
    Task<bool> InitializeAsync();

    /// <summary>
    /// Starts emitting a signal with the requested parameters.
    /// </summary>
    Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine");

    /// <summary>
    /// Stops the current emission.
    /// </summary>
    Task StopEmissionAsync();

    /// <summary>
    /// Returns live information about the connected device.
    /// </summary>
    Task<string> GetDeviceInfoAsync();

    /// <summary>
    /// Performs a quick hardware validation (100 Hz, 10 V, square wave for 3 seconds).
    /// </summary>
    Task<bool> TestEmissionAsync();
}

public sealed class TiePieHS3Service : ITiePieHS3Service
{
    private readonly ILogger<TiePieHS3Service> _logger;
    private readonly object _syncRoot = new();
    private nint _deviceHandle = nint.Zero;
    private bool _isLibraryInitialized;
    private bool _disposed;

    public bool IsConnected => _deviceHandle != nint.Zero;
    public uint SerialNumber { get; private set; }

    public TiePieHS3Service(ILogger<TiePieHS3Service> logger)
    {
        _logger = logger;
    }

    ~TiePieHS3Service()
    {
        Dispose(false);
    }

    public async Task<bool> InitializeAsync()
    {
        ThrowIfDisposed();

        return await Task.Run(() =>
        {
            lock (_syncRoot)
            {
                if (IsConnected)
                {
                    _logger.LogInformation("[HS3] Already initialized (SN: {Serial})", SerialNumber);
                    return true;
                }

                try
                {
                    _logger.LogInformation("[HS3] Initializing Inergetix API...");

                    if (!_isLibraryInitialized)
                    {
                        // InitInstrument retorna handle (int) ou 0 se erro
                        int handle = HS3Native.InitInstrument();

                        if (handle <= 0)
                        {
                            _logger.LogError("[HS3] InitInstrument() failed (returned {Handle}). Check USB/driver.", handle);
                            return false;
                        }

                        _deviceHandle = (nint)handle;
                        _isLibraryInitialized = true;

                        _logger.LogInformation("[HS3] InitInstrument() succeeded (handle: {Handle})", handle);
                    }
                    else
                    {
                        _logger.LogDebug("[HS3] Already initialized in this session.");
                    }

                    // Obter número de série (não precisa de handle na API Inergetix)
                    SerialNumber = HS3Native.GetSerialNumber();

                    _logger.LogInformation("[HS3] Device ready. Serial: {Serial}", SerialNumber);

                    // Configuração inicial: desligar output e definir defaults
                    HS3Native.SetFuncGenOutputOn(false);
                    HS3Native.SetFuncGenEnable(false);

                    return true;
                }
                catch (DllNotFoundException ex)
                {
                    _logger.LogError(ex, "[HS3] hs3.dll not found. Ensure the DLL is in the application folder.");
                    ResetStateOnFailure();
                    return false;
                }
                catch (BadImageFormatException ex)
                {
                    _logger.LogError(ex, "[HS3] Architecture mismatch. Application MUST run as x86 (32-bit).");
                    ResetStateOnFailure();
                    return false;
                }
                catch (EntryPointNotFoundException ex)
                {
                    _logger.LogError(ex, "[HS3] Function not found in DLL. Verify hs3.dll version (expecting Inergetix CoRe wrapper).");
                    ResetStateOnFailure();
                    return false;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[HS3] Unexpected error during initialization.");
                    ResetStateOnFailure();
                    return false;
                }
            }
        });
    }

    public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine")
    {
        ThrowIfDisposed();

        return await Task.Run(() =>
        {
            lock (_syncRoot)
            {
                if (!IsConnected)
                {
                    _logger.LogWarning("[HS3] Cannot emit - device not initialized.");
                    return false;
                }

                try
                {
                    _logger.LogInformation("[HS3] Configuring: {Frequency} Hz @ {Amplitude} V ({Waveform})",
                        frequencyHz, amplitudeVolts, waveform);

                    // 1. Parar emissão anterior (se houver)
                    HS3Native.SetFuncGenEnable(false);
                    HS3Native.SetFuncGenOutputOn(false);

                    // 2. Configurar parâmetros
                    var signalType = MapWaveform(waveform);

                    int resultType = HS3Native.SetFuncGenSignalType((int)signalType);
                    int resultFreq = HS3Native.SetFuncGenFrequency(frequencyHz);
                    int resultAmp = HS3Native.SetFuncGenAmplitude(amplitudeVolts);

                    if (resultType != 0 || resultFreq != 0 || resultAmp != 0)
                    {
                        _logger.LogWarning("[HS3] Configuration warnings: Type={Type}, Freq={Freq}, Amp={Amp}",
                            resultType, resultFreq, resultAmp);
                    }

                    // 3. Verificar valores reais
                    double actualFreq = HS3Native.GetFuncGenFrequency();
                    double actualAmp = HS3Native.GetFuncGenAmplitude();
                    int actualType = HS3Native.GetFuncGenSignalType();

                    _logger.LogDebug("[HS3] Configured: {Type} @ {Frequency} Hz, {Amplitude} V",
                        (HS3Native.SignalType)actualType, actualFreq, actualAmp);

                    // 4. Ativar output
                    int resultOutput = HS3Native.SetFuncGenOutputOn(true);
                    if (resultOutput != 0)
                    {
                        _logger.LogError("[HS3] Failed to enable output (error {Code})", resultOutput);
                        return false;
                    }

                    // 5. Ativar gerador
                    int resultEnable = HS3Native.SetFuncGenEnable(true);
                    if (resultEnable != 0)
                    {
                        _logger.LogError("[HS3] Failed to enable generator (error {Code})", resultEnable);
                        HS3Native.SetFuncGenOutputOn(false);
                        return false;
                    }

                    _logger.LogInformation("[HS3] ✅ Emission started successfully!");
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[HS3] Error during emission configuration.");

                    // Cleanup
                    try
                    {
                        HS3Native.SetFuncGenEnable(false);
                        HS3Native.SetFuncGenOutputOn(false);
                    }
                    catch { /* best effort */ }

                    return false;
                }
            }
        });
    }

    public async Task StopEmissionAsync()
    {
        ThrowIfDisposed();

        await Task.Run(() =>
        {
            lock (_syncRoot)
            {
                if (!IsConnected)
                {
                    return;
                }

                try
                {
                    _logger.LogInformation("[HS3] Stopping emission...");
                    HS3Native.SetFuncGenEnable(false);
                    HS3Native.SetFuncGenOutputOn(false);
                    _logger.LogInformation("[HS3] ✅ Emission stopped.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[HS3] Error while stopping emission.");
                }
            }
        });
    }

    public async Task<string> GetDeviceInfoAsync()
    {
        ThrowIfDisposed();

        return await Task.Run(() =>
        {
            lock (_syncRoot)
            {
                if (!IsConnected)
                {
                    return "[HS3] Device not initialized.";
                }

                try
                {
                    uint serial = HS3Native.GetSerialNumber();
                    double frequency = HS3Native.GetFuncGenFrequency();
                    double amplitude = HS3Native.GetFuncGenAmplitude();
                    int signalType = HS3Native.GetFuncGenSignalType();
                    bool outputOn = HS3Native.GetFuncGenOutputOn();
                    bool genEnabled = HS3Native.GetFuncGenEnable();
                    int status = HS3Native.GetFunctionGenStatus();

                    return
$@"[HS3] TiePie Handyscope HS3 (Inergetix API)
Serial Number: {serial}

Current Configuration:
- Frequency: {frequency:F2} Hz
- Amplitude: {amplitude:F2} V
- Waveform: {(HS3Native.SignalType)signalType}
- Output enabled: {outputOn}
- Generator enabled: {genEnabled}
- Status code: 0x{status:X}";
                }
                catch (Exception ex)
                {
                    return $"[HS3] Error reading device info: {ex.Message}";
                }
            }
        });
    }

    public async Task<bool> TestEmissionAsync()
    {
        if (!await InitializeAsync())
        {
            return false;
        }

        var started = await EmitFrequencyAsync(100.0, 10.0, "Square");
        if (!started)
        {
            return false;
        }

        try
        {
            await Task.Delay(3000);
            return true;
        }
        finally
        {
            await StopEmissionAsync();
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        lock (_syncRoot)
        {
            if (IsConnected)
            {
                try
                {
                    // Parar emissão
                    HS3Native.SetFuncGenEnable(false);
                    HS3Native.SetFuncGenOutputOn(false);
                }
                catch (Exception ex) when (!disposing)
                {
                    _logger.LogDebug(ex, "[HS3] Ignoring stop errors during finalizer.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[HS3] Error stopping emission during dispose.");
                }

                _deviceHandle = nint.Zero;
            }

            if (_isLibraryInitialized)
            {
                try
                {
                    // Finalizar instrumento (API Inergetix)
                    HS3Native.ExitInstrument();
                }
                catch (Exception ex) when (!disposing)
                {
                    _logger.LogDebug(ex, "[HS3] Ignoring ExitInstrument errors during finalizer.");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[HS3] Error during ExitInstrument.");
                }
                finally
                {
                    _isLibraryInitialized = false;
                }
            }

            SerialNumber = 0;
        }

        _disposed = true;
    }

    private void ResetStateOnFailure()
    {
        if (_deviceHandle != nint.Zero)
        {
            try
            {
                HS3Native.SetFuncGenEnable(false);
                HS3Native.SetFuncGenOutputOn(false);
            }
            catch
            {
                // best effort only
            }
            finally
            {
                _deviceHandle = nint.Zero;
            }
        }

        if (_isLibraryInitialized)
        {
            try
            {
                HS3Native.ExitInstrument();
            }
            catch
            {
                // best effort only
            }
            finally
            {
                _isLibraryInitialized = false;
            }
        }

        SerialNumber = 0;
    }

    private static HS3Native.SignalType MapWaveform(string waveform) =>
        waveform?.ToLowerInvariant() switch
        {
            "square" => HS3Native.SignalType.Square,
            "triangle" => HS3Native.SignalType.Triangle,
            "dc" => HS3Native.SignalType.DC,
            "noise" => HS3Native.SignalType.Noise,
            "pulse" => HS3Native.SignalType.Pulse,
            _ => HS3Native.SignalType.Sine
        };

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TiePieHS3Service));
        }
    }
}
