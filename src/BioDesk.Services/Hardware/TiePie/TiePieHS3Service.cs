using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Hardware.TiePie.Protocol;

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

/// <summary>
/// TiePie HS3 service using direct USB protocol communication (no DLL dependency).
/// Based on reverse-engineering of Inergetix CoRe via API Monitor.
///
/// Features:
/// - Direct USB protocol via DeviceIoControl (no hs3.dll)
/// - Automatic retry with exponential backoff
/// - Circuit breaker for cascading failure prevention
/// - Comprehensive telemetry and diagnostics
/// </summary>
public sealed class TiePieHS3Service : ITiePieHS3Service
{
    private readonly ILogger<TiePieHS3Service> _logger;
    private readonly HS3DeviceDiscovery _discovery;
    private readonly HS3DeviceProtocol _protocol;
    private readonly HS3RobustnessHelpers _robustness;
    private readonly object _syncRoot = new();

    private HS3DeviceCapabilities _deviceCapabilities;
    private bool _isEmitting = false;
    private bool _disposed;

    public bool IsConnected => _protocol.IsDeviceOpen();
    public uint SerialNumber { get; private set; }

    public TiePieHS3Service(
        ILogger<TiePieHS3Service> logger,
        HS3DeviceDiscovery discovery,
        HS3DeviceProtocol protocol)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _discovery = discovery ?? throw new ArgumentNullException(nameof(discovery));
        _protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));

        // Create robustness helpers with a basic logger wrapper
        _robustness = new HS3RobustnessHelpers(
            new LoggerWrapper<HS3RobustnessHelpers>(logger),
            protocol);
    }

    /// <summary>
    /// Lightweight logger wrapper to adapt ILogger{T} to ILogger{U}.
    /// </summary>
    private class LoggerWrapper<T> : ILogger<T>
    {
        private readonly ILogger _innerLogger;

        public LoggerWrapper(ILogger innerLogger)
        {
            _innerLogger = innerLogger;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull =>
            _innerLogger.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) =>
            _innerLogger.IsEnabled(logLevel);

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            _innerLogger.Log(logLevel, eventId, state, exception, formatter);
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
                    _logger.LogInformation("[HS3] 🔍 Discovering TiePie HS3 devices via USB...");

                    // 1. Discover device using SetupDi APIs
                    string? devicePath = _discovery.FindFirstHS3Device();

                    if (string.IsNullOrEmpty(devicePath))
                    {
                        _logger.LogError("[HS3] ❌ No TiePie HS3 devices found.");
                        _logger.LogError("[HS3] Check: USB connected + Device Manager shows TiePie HS3 + Drivers installed");
                        return false;
                    }

                    _logger.LogInformation("[HS3] ✅ Found HS3 device: {Path}", devicePath);

                    // 2. Open device using CreateFile
                    if (!_protocol.OpenDevice(devicePath))
                    {
                        _logger.LogError("[HS3] ❌ Failed to open device at {Path}", devicePath);
                        return false;
                    }

                    _logger.LogInformation("[HS3] ✅ Device opened successfully.");

                    // 3. Get device capabilities via IOCTL 0x222000 (GET_DEVICE_INFO)
                    if (!_protocol.GetDeviceCapabilities(out _deviceCapabilities))
                    {
                        _logger.LogError("[HS3] ❌ Failed to retrieve device capabilities (IOCTL 0x222000).");
                        _protocol.CloseDevice();
                        return false;
                    }

                    // 4. Validate VID/PID match expected values
                    if (_deviceCapabilities.VendorId != HS3Protocol.USB_VENDOR_ID ||
                        _deviceCapabilities.ProductId != HS3Protocol.USB_PRODUCT_ID)
                    {
                        _logger.LogError("[HS3] ❌ VID/PID mismatch! Expected VID={ExpectedVID:X4}/PID={ExpectedPID:X4}, Got VID={ActualVID:X4}/PID={ActualPID:X4}",
                            HS3Protocol.USB_VENDOR_ID, HS3Protocol.USB_PRODUCT_ID,
                            _deviceCapabilities.VendorId, _deviceCapabilities.ProductId);
                        _protocol.CloseDevice();
                        return false;
                    }

                    SerialNumber = _deviceCapabilities.SerialNumber;

                    _logger.LogInformation("[HS3] ✅ Device capabilities retrieved:");
                    _logger.LogInformation("[HS3]    - VID: 0x{VID:X4}, PID: 0x{PID:X4}",
                        _deviceCapabilities.VendorId, _deviceCapabilities.ProductId);
                    _logger.LogInformation("[HS3]    - Serial Number: {Serial}", SerialNumber);
                    _logger.LogInformation("[HS3]    - Firmware Version: {Firmware}",
                        _deviceCapabilities.FirmwareVersion);

                    // 5. Configure device via IOCTL 0x222059 (CONFIG_QUERY)
                    if (!_protocol.ConfigureDevice(null))
                    {
                        _logger.LogWarning("[HS3] ⚠️ Device configuration returned warning (may be normal during init).");
                    }

                    _logger.LogInformation("[HS3] ✅ Device initialized successfully!");
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[HS3] ❌ Unexpected error during initialization.");
                    ResetStateOnFailure();
                    return false;
                }
            }
        });
    }

    public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine")
    {
        ThrowIfDisposed();

        return await Task.Run(async () =>
        {
            lock (_syncRoot)
            {
                if (!IsConnected)
                {
                    _logger.LogWarning("[HS3] Cannot emit - device not initialized.");
                    return false;
                }

                if (_isEmitting)
                {
                    _logger.LogWarning("[HS3] Emission already in progress - call StopEmissionAsync first.");
                    return false;
                }
            }

            try
            {
                _logger.LogInformation(
                    "[HS3] 🔊 Emitting: {Frequency} Hz @ {Amplitude} V ({Waveform})",
                    frequencyHz, amplitudeVolts, waveform);

                // TO VALIDATE WITH HARDWARE: These commands are based on API Monitor logs and are hypothetical
                // Sequence: SET_FREQUENCY → SET_AMPLITUDE → SET_WAVEFORM → START_EMISSION

                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)))
                {
                    // 1. Set frequency (OpCode 0x40)
                    var freqCommand = HS3CommandPresets.SetFrequency(frequencyHz);
                    bool freqSuccess = await _robustness.SendCommandWithCircuitBreakerAsync(
                        freqCommand,
                        maxRetries: 3,
                        cancellationToken: cts.Token);

                    if (!freqSuccess)
                    {
                        _logger.LogError("[HS3] ❌ Failed to set frequency");
                        return false;
                    }

                    // 2. Set amplitude (OpCode 0x41) - convert Volts to percentage
                    // Assuming range: 0-10V maps to 0-100%
                    double amplitudePercent = Math.Clamp(amplitudeVolts / 10.0 * 100.0, 0, 100);
                    var ampCommand = HS3CommandPresets.SetAmplitude(amplitudePercent);
                    bool ampSuccess = await _robustness.SendCommandWithCircuitBreakerAsync(
                        ampCommand,
                        maxRetries: 3,
                        cancellationToken: cts.Token);

                    if (!ampSuccess)
                    {
                        _logger.LogError("[HS3] ❌ Failed to set amplitude");
                        return false;
                    }

                    // 3. Set waveform (OpCode 0x44)
                    var waveCommand = HS3CommandPresets.SetWaveform(HS3CommandPresets.Waveform.Sine);
                    bool waveSuccess = await _robustness.SendCommandWithCircuitBreakerAsync(
                        waveCommand,
                        maxRetries: 3,
                        cancellationToken: cts.Token);

                    if (!waveSuccess)
                    {
                        _logger.LogError("[HS3] ❌ Failed to set waveform");
                        return false;
                    }

                    // 4. Start emission (OpCode 0x42)
                    var startCommand = HS3CommandPresets.StartEmission();
                    bool startSuccess = await _robustness.SendCommandWithCircuitBreakerAsync(
                        startCommand,
                        maxRetries: 3,
                        cancellationToken: cts.Token);

                    if (startSuccess)
                    {
                        _isEmitting = true;
                        _logger.LogInformation("[HS3] ✅ Emission started successfully");
                        return true;
                    }
                    else
                    {
                        _logger.LogError("[HS3] ❌ Failed to start emission");
                        return false;
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogError("[HS3] ❌ Emission setup timeout (10s)");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HS3] Error during emission configuration.");
                return false;
            }
        });
    }

    public async Task StopEmissionAsync()
    {
        ThrowIfDisposed();

        await Task.Run(async () =>
        {
            lock (_syncRoot)
            {
                if (!IsConnected)
                {
                    _logger.LogInformation("[HS3] Device not connected - nothing to stop.");
                    return;
                }

                if (!_isEmitting)
                {
                    _logger.LogInformation("[HS3] No emission in progress.");
                    return;
                }
            }

            try
            {
                _logger.LogInformation("[HS3] ⏹️ Stopping emission...");

                // TO VALIDATE WITH HARDWARE: OpCode 0x43 for STOP_EMISSION
                var stopCommand = HS3CommandPresets.StopEmission();

                using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5)))
                {
                    bool success = await _robustness.SendCommandWithCircuitBreakerAsync(
                        stopCommand,
                        maxRetries: 3,
                        cancellationToken: cts.Token);

                    if (success)
                    {
                        lock (_syncRoot)
                        {
                            _isEmitting = false;
                        }
                        _logger.LogInformation("[HS3] ✅ Emission stopped successfully");
                    }
                    else
                    {
                        _logger.LogError("[HS3] ❌ Failed to stop emission (device may still be emitting)");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogError("[HS3] ❌ Stop emission timeout (5s)");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[HS3] Error while stopping emission.");
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
                    return
$@"[HS3] TiePie Handyscope HS3 (Direct USB Protocol)
Serial Number: {SerialNumber}
VID/PID: 0x{_deviceCapabilities.VendorId:X4}/0x{_deviceCapabilities.ProductId:X4}
Firmware: {_deviceCapabilities.FirmwareVersion}
Hardware Rev: {_deviceCapabilities.HardwareRevision}

Protocol: Direct USB via DeviceIoControl (no DLL dependency)
IOCTL Codes: 0x222000 (info), 0x222059 (config), 0x222051 (read), 0x22204E (write)

⚠️ Emission control requires hardware validation.";
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

        _logger.LogWarning("[HS3] TestEmissionAsync() requires hardware validation (emission commands not implemented yet).");
        return false;
    }

    /// <summary>
    /// Gets comprehensive diagnostics report for troubleshooting.
    /// </summary>
    public string GetDiagnosticsReport()
    {
        lock (_syncRoot)
        {
            return $@"
╔══════════════════════════════════════════════════════════════════╗
║           TiePie HS3 Service Diagnostics Report                  ║
╠══════════════════════════════════════════════════════════════════╣
║ Connection Status:    {(IsConnected ? "✅ CONNECTED" : "❌ DISCONNECTED"),9}                     │
║ Serial Number:        {SerialNumber,9}                            │
║ Emitting:             {(_isEmitting ? "🔊 YES" : "⏹️ NO"),9}                              │
║ VID/PID:              0x{_deviceCapabilities.VendorId:X4}/0x{_deviceCapabilities.ProductId:X4}                             │
║ Firmware:             {_deviceCapabilities.FirmwareVersion,9}                          │
╠══════════════════════════════════════════════════════════════════╣
{_robustness.GetDiagnosticsReport()}
╚══════════════════════════════════════════════════════════════════╝
";
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
            if (disposing)
            {
                try
                {
                    _robustness?.Dispose();
                    _protocol?.Dispose();
                    _discovery?.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "[HS3] Error disposing robustness/protocol/discovery.");
                }
            }

            SerialNumber = 0;
        }

        _disposed = true;
    }

    private void ResetStateOnFailure()
    {
        try
        {
            _protocol?.CloseDevice();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "[HS3] Error closing device during reset.");
        }

        SerialNumber = 0;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TiePieHS3Service));
        }
    }
}
