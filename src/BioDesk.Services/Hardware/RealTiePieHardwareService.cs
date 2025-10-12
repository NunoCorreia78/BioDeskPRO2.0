using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Hardware;

/// <summary>
/// Implementação REAL para comunicação com TiePie Handyscope HS5 via LibTiePie SDK
/// Requer: libtiepie.dll (32-bit ou 64-bit dependendo da arquitetura)
/// </summary>
public class RealTiePieHardwareService : ITiePieHardwareService, IDisposable
{
    private readonly ILogger<RealTiePieHardwareService> _logger;
    private IntPtr _deviceHandle = IntPtr.Zero;
    private bool _disposed = false;
    private readonly object _lockObject = new object();

    #region P/Invoke Declarations

    // Verificar arquitetura (x64 ou x86) e carregar DLL correta
    private const string LibTiePieDll = "libtiepie";

    // === LIBRARY INITIALIZATION ===
    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void LibInit();

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void LibExit();

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint LibGetVersion();

    // === DEVICE LISTING ===
    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern void LstUpdate();

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint LstGetCount();

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr LstOpenDevice(uint dwIdKind, uint dwId, uint dwDeviceType);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint LstDevGetSerialNumber(uint dwIdKind, uint dwId);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint LstDevGetNameShort(uint dwIdKind, uint dwId, IntPtr pBuffer, uint dwBufferLength);

    // === DEVICE CONTROL ===
    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool ObjClose(IntPtr hHandle);

    // === GENERATOR (Handyscope HS5 como gerador de sinais) ===
    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool GenSetOutputOn(IntPtr hDevice, bool bOutputOn);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool GenSetFrequency(IntPtr hDevice, double dFrequency);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern double GenGetFrequency(IntPtr hDevice);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool GenSetAmplitude(IntPtr hDevice, double dAmplitude);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern double GenGetAmplitude(IntPtr hDevice);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool GenSetSignalType(IntPtr hDevice, uint dwSignalType);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern uint GenGetSignalType(IntPtr hDevice);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool GenStart(IntPtr hDevice);

    [DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
    private static extern bool GenStop(IntPtr hDevice);

    // === CONSTANTES ===
    private const uint IDKIND_INDEX = 0;
    private const uint DEVICETYPE_GENERATOR = 0x00000002;

    // Signal Types (LibTiePie SDK)
    private const uint ST_SINE = 0x00000001;
    private const uint ST_TRIANGLE = 0x00000002;
    private const uint ST_SQUARE = 0x00000004;
    private const uint ST_SAWTOOTH = 0x00000008;

    #endregion

    public RealTiePieHardwareService(ILogger<RealTiePieHardwareService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        try
        {
            _logger.LogInformation("🔌 RealTiePieHardwareService: Inicializando LibTiePie SDK...");
            LibInit();

            var version = LibGetVersion();
            _logger.LogInformation("✅ LibTiePie SDK v{Version} inicializado com sucesso", version);
        }
        catch (DllNotFoundException ex)
        {
            _logger.LogError(ex, "❌ libtiepie.dll NÃO ENCONTRADO! Instale o LibTiePie SDK.");
            throw new InvalidOperationException("LibTiePie SDK não encontrado. Instale o driver TiePie.", ex);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao inicializar LibTiePie SDK");
            throw;
        }
    }

    public async Task<HardwareStatus> GetStatusAsync()
    {
        return await Task.Run(() =>
        {
            lock (_lockObject)
            {
                try
                {
                    _logger.LogInformation("📡 GetStatus: Detectando dispositivos TiePie...");

                    LstUpdate();
                    var deviceCount = LstGetCount();

                    if (deviceCount == 0)
                    {
                        _logger.LogWarning("⚠️ Nenhum dispositivo TiePie detectado via USB");
                        return new HardwareStatus
                        {
                            IsConnected = false,
                            ErrorMessage = "Nenhum dispositivo TiePie encontrado. Verifique conexão USB."
                        };
                    }

                    // Abrir primeiro dispositivo
                    _deviceHandle = LstOpenDevice(IDKIND_INDEX, 0, DEVICETYPE_GENERATOR);

                    if (_deviceHandle == IntPtr.Zero)
                    {
                        _logger.LogError("❌ Falha ao abrir dispositivo TiePie (handle nulo)");
                        return new HardwareStatus
                        {
                            IsConnected = false,
                            ErrorMessage = "Falha ao abrir dispositivo. Verifique drivers."
                        };
                    }

                    // Obter informações do dispositivo
                    var serialNumber = LstDevGetSerialNumber(IDKIND_INDEX, 0);

                    var nameBuffer = Marshal.AllocHGlobal(256);
                    LstDevGetNameShort(IDKIND_INDEX, 0, nameBuffer, 256);
                    var deviceName = Marshal.PtrToStringAnsi(nameBuffer) ?? "TiePie Handyscope HS5";
                    Marshal.FreeHGlobal(nameBuffer);

                    _logger.LogInformation("✅ Dispositivo conectado: {DeviceName} (S/N: {SerialNumber})",
                        deviceName, serialNumber);

                    return new HardwareStatus
                    {
                        IsConnected = true,
                        DeviceName = deviceName,
                        SerialNumber = serialNumber.ToString(),
                        ChannelCount = 2, // HS5 tem 2 canais
                        MaxFrequencyHz = 5_000_000, // 5 MHz
                        MaxVoltageV = 8.0
                    };
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "❌ Erro ao obter status do hardware");
                    return new HardwareStatus
                    {
                        IsConnected = false,
                        ErrorMessage = $"Erro: {ex.Message}"
                    };
                }
            }
        });
    }

    public async Task<bool> SendSignalAsync(SignalConfiguration config)
    {
        if (config == null)
            throw new ArgumentNullException(nameof(config));

        if (!config.IsValid())
        {
            _logger.LogError("❌ Configuração inválida: {Config}", config);
            return false;
        }

        return await Task.Run(() =>
        {
            lock (_lockObject)
            {
                try
                {
                    if (_deviceHandle == IntPtr.Zero)
                    {
                        _logger.LogError("❌ Dispositivo não conectado. Execute GetStatusAsync() primeiro.");
                        return false;
                    }

                    _logger.LogInformation("🔊 Enviando sinal: {Config}", config);

                    // 1. Parar geração anterior
                    GenStop(_deviceHandle);

                    // 2. Configurar forma de onda
                    uint signalType = config.Waveform switch
                    {
                        SignalWaveform.Sine => ST_SINE,
                        SignalWaveform.Square => ST_SQUARE,
                        SignalWaveform.Triangle => ST_TRIANGLE,
                        SignalWaveform.Sawtooth => ST_SAWTOOTH,
                        _ => ST_SINE
                    };

                    if (!GenSetSignalType(_deviceHandle, signalType))
                    {
                        _logger.LogError("❌ Falha ao configurar forma de onda");
                        return false;
                    }

                    // 3. Configurar frequência (Hz)
                    if (!GenSetFrequency(_deviceHandle, config.FrequencyHz))
                    {
                        _logger.LogError("❌ Falha ao configurar frequência {Freq} Hz", config.FrequencyHz);
                        return false;
                    }

                    // 4. Configurar amplitude (Volts pico-a-pico → dividir por 2 para amplitude)
                    var amplitude = config.VoltageV / 2.0;
                    if (!GenSetAmplitude(_deviceHandle, amplitude))
                    {
                        _logger.LogError("❌ Falha ao configurar voltagem {Voltage} V", config.VoltageV);
                        return false;
                    }

                    // 5. Ativar saída
                    if (!GenSetOutputOn(_deviceHandle, true))
                    {
                        _logger.LogError("❌ Falha ao ativar saída");
                        return false;
                    }

                    // 6. Iniciar geração
                    if (!GenStart(_deviceHandle))
                    {
                        _logger.LogError("❌ Falha ao iniciar geração de sinal");
                        return false;
                    }

                    _logger.LogInformation("✅ Sinal iniciado com sucesso");

                    // 7. Aguardar duração especificada
                    Task.Delay(TimeSpan.FromSeconds(config.DurationSeconds)).Wait();

                    // 8. Parar geração
                    GenStop(_deviceHandle);
                    GenSetOutputOn(_deviceHandle, false);

                    _logger.LogInformation("✅ Sinal completado ({Duration}s)", config.DurationSeconds);
                    return true;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "❌ Erro ao enviar sinal");
                    return false;
                }
            }
        });
    }

    public async Task StopAllChannelsAsync()
    {
        await Task.Run(() =>
        {
            lock (_lockObject)
            {
                try
                {
                    _logger.LogInformation("🛑 Parando todos os canais...");

                    if (_deviceHandle != IntPtr.Zero)
                    {
                        GenStop(_deviceHandle);
                        GenSetOutputOn(_deviceHandle, false);
                        _logger.LogInformation("✅ Todos os canais parados");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "❌ Erro ao parar canais");
                }
            }
        });
    }

    public async Task<bool> SendMultipleFrequenciesAsync(
        double[] frequencies,
        SignalChannel channel = SignalChannel.Channel1,
        double voltageV = 1.0,
        SignalWaveform waveform = SignalWaveform.Sine,
        double durationPerFreqSeconds = 60.0)
    {
        if (frequencies == null || frequencies.Length == 0)
            throw new ArgumentException("Array de frequências vazio", nameof(frequencies));

        _logger.LogInformation(
            "🎵 Enviando {Count} frequências no Ch{Channel}: [{Freqs}]",
            frequencies.Length,
            (int)channel,
            string.Join(", ", frequencies.Take(5).Select(f => $"{f:F2} Hz")) + (frequencies.Length > 5 ? "..." : ""));

        foreach (var freq in frequencies)
        {
            var config = new SignalConfiguration
            {
                Channel = channel,
                FrequencyHz = freq,
                VoltageV = voltageV,
                Waveform = waveform,
                DurationSeconds = durationPerFreqSeconds
            };

            var success = await SendSignalAsync(config);
            if (!success)
            {
                _logger.LogError("❌ Falha ao enviar frequência {Freq} Hz", freq);
                return false;
            }
        }

        _logger.LogInformation("✅ Todas as {Count} frequências foram enviadas com sucesso", frequencies.Length);
        return true;
    }

    public async Task<bool> TestHardwareAsync()
    {
        _logger.LogInformation("🧪 Teste de hardware: 1 kHz, 1V, Sine, 2s");

        var testConfig = new SignalConfiguration
        {
            Channel = SignalChannel.Channel1,
            FrequencyHz = 1000.0, // 1 kHz
            VoltageV = 1.0,
            Waveform = SignalWaveform.Sine,
            DurationSeconds = 2.0
        };

        var result = await SendSignalAsync(testConfig);

        if (result)
            _logger.LogInformation("✅ Teste de hardware: PASSOU");
        else
            _logger.LogError("❌ Teste de hardware: FALHOU");

        return result;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                lock (_lockObject)
                {
                    try
                    {
                        if (_deviceHandle != IntPtr.Zero)
                        {
                            _logger.LogInformation("🔌 Fechando dispositivo TiePie...");
                            GenStop(_deviceHandle);
                            GenSetOutputOn(_deviceHandle, false);
                            ObjClose(_deviceHandle);
                            _deviceHandle = IntPtr.Zero;
                        }

                        LibExit();
                        _logger.LogInformation("✅ LibTiePie SDK finalizado");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "❌ Erro ao finalizar LibTiePie SDK");
                    }
                }
            }

            _disposed = true;
        }
    }

    ~RealTiePieHardwareService()
    {
        Dispose(false);
    }
}
