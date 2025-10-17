using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Hardware.TiePie;

/// <summary>
/// Serviço para controlo direto do TiePie Handyscope HS3
/// Usa hs3.dll nativa via P/Invoke (mesma DLL que Inergetix CoRe)
/// </summary>
public interface ITiePieHS3Service : IDisposable
{
    /// <summary>
    /// Indica se o HS3 está conectado e inicializado
    /// </summary>
    bool IsConnected { get; }

    /// <summary>
    /// Número de série do HS3 conectado (0 se não conectado)
    /// </summary>
    uint SerialNumber { get; }

    /// <summary>
    /// Inicializa a biblioteca e conecta ao HS3
    /// </summary>
    /// <returns>true se sucesso</returns>
    Task<bool> InitializeAsync();

    /// <summary>
    /// Emite uma frequência específica com amplitude definida
    /// </summary>
    /// <param name="frequencyHz">Frequência em Hz (0.1 - 10000)</param>
    /// <param name="amplitudeVolts">Amplitude em Volts (0 - 10V)</param>
    /// <param name="waveform">Tipo de onda (Sine, Square, Triangle)</param>
    /// <returns>true se iniciou emissão</returns>
    Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine");

    /// <summary>
    /// Para a emissão atual
    /// </summary>
    Task StopEmissionAsync();

    /// <summary>
    /// Obtém informações do dispositivo
    /// </summary>
    Task<string> GetDeviceInfoAsync();
}

/// <summary>
/// Implementação do serviço TiePie HS3 usando hs3.dll nativa
/// </summary>
public class TiePieHS3Service : ITiePieHS3Service
{
    private readonly ILogger<TiePieHS3Service> _logger;
    private nint _deviceHandle = nint.Zero;
    private bool _isLibraryInitialized = false;
    private bool _disposed = false;

    public bool IsConnected => _deviceHandle != nint.Zero;
    public uint SerialNumber { get; private set; }

    public TiePieHS3Service(ILogger<TiePieHS3Service> logger)
    {
        _logger = logger;
    }

    public async Task<bool> InitializeAsync()
    {
        return await Task.Run(() =>
        {
            try
            {
                _logger.LogInformation("🔌 Inicializando TiePie HS3...");

                // Inicializar biblioteca
                if (!HS3Native.LibInit())
                {
                    _logger.LogError("❌ Falha ao inicializar hs3.dll");
                    return false;
                }
                _isLibraryInitialized = true;
                _logger.LogInformation("✅ hs3.dll inicializada");

                // Atualizar lista de dispositivos
                int deviceCount = HS3Native.LstUpdate();
                _logger.LogInformation($"🔍 Dispositivos encontrados: {deviceCount}");

                if (deviceCount == 0)
                {
                    _logger.LogWarning("⚠️ Nenhum HS3 conectado");
                    return false;
                }

                // Abrir primeiro dispositivo disponível (dwDeviceType=0, dwSerialNumber=0)
                _deviceHandle = HS3Native.LstOpenDevice(0, 0);
                if (_deviceHandle == nint.Zero)
                {
                    _logger.LogError("❌ Falha ao abrir dispositivo HS3");
                    return false;
                }

                // Obter número de série
                SerialNumber = HS3Native.DevGetSerialNumber(_deviceHandle);
                uint firmwareVersion = HS3Native.DevGetFirmwareVersion(_deviceHandle);

                _logger.LogInformation($"✅ HS3 conectado!");
                _logger.LogInformation($"   Número de Série: {SerialNumber}");
                _logger.LogInformation($"   Firmware: {firmwareVersion:X}");

                // Configurar gerador para modo de frequência de sinal
                HS3Native.GenSetFrequencyMode(_deviceHandle, (uint)HS3Native.FrequencyMode.SignalFrequency);

                return true;
            }
            catch (DllNotFoundException ex)
            {
                _logger.LogError(ex, "❌ hs3.dll não encontrada! Certifique-se que está na pasta do executável.");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao inicializar HS3");
                return false;
            }
        });
    }

    public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine")
    {
        return await Task.Run(() =>
        {
            if (!IsConnected)
            {
                _logger.LogWarning("⚠️ HS3 não conectado");
                return false;
            }

            try
            {
                _logger.LogInformation($"🎵 Configurando emissão: {frequencyHz} Hz @ {amplitudeVolts}V ({waveform})");

                // Mapear waveform string para enum
                var signalType = waveform.ToLower() switch
                {
                    "sine" => HS3Native.SignalType.Sine,
                    "square" => HS3Native.SignalType.Square,
                    "triangle" => HS3Native.SignalType.Triangle,
                    "dc" => HS3Native.SignalType.DC,
                    "noise" => HS3Native.SignalType.Noise,
                    _ => HS3Native.SignalType.Sine
                };

                // 1. Parar emissão anterior (se existir)
                HS3Native.GenStop(_deviceHandle);
                HS3Native.GenSetOutputOn(_deviceHandle, false);

                // 2. Configurar tipo de sinal
                uint actualType = HS3Native.GenSetSignalType(_deviceHandle, (uint)signalType);
                _logger.LogDebug($"   Tipo de sinal: {(HS3Native.SignalType)actualType}");

                // 3. Configurar frequência
                double actualFreq = HS3Native.GenSetFrequency(_deviceHandle, frequencyHz);
                _logger.LogDebug($"   Frequência configurada: {actualFreq:F2} Hz");

                // 4. Configurar amplitude
                double actualAmp = HS3Native.GenSetAmplitude(_deviceHandle, amplitudeVolts);
                _logger.LogDebug($"   Amplitude configurada: {actualAmp:F2} V");

                // 5. Ativar saída
                if (!HS3Native.GenSetOutputOn(_deviceHandle, true))
                {
                    _logger.LogError("❌ Falha ao ativar saída");
                    return false;
                }

                // 6. Iniciar geração
                if (!HS3Native.GenStart(_deviceHandle))
                {
                    _logger.LogError("❌ Falha ao iniciar geração");
                    return false;
                }

                _logger.LogInformation($"✅ Emissão iniciada: {actualFreq:F2} Hz @ {actualAmp:F2}V");
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao emitir frequência");
                return false;
            }
        });
    }

    public async Task StopEmissionAsync()
    {
        await Task.Run(() =>
        {
            if (!IsConnected)
            {
                return;
            }

            try
            {
                _logger.LogInformation("⏹️ Parando emissão...");

                // Parar geração
                HS3Native.GenStop(_deviceHandle);

                // Desativar saída
                HS3Native.GenSetOutputOn(_deviceHandle, false);

                _logger.LogInformation("✅ Emissão parada");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao parar emissão");
            }
        });
    }

    public async Task<string> GetDeviceInfoAsync()
    {
        return await Task.Run(() =>
        {
            if (!IsConnected)
            {
                return "❌ HS3 não conectado";
            }

            try
            {
                uint serial = HS3Native.DevGetSerialNumber(_deviceHandle);
                uint firmware = HS3Native.DevGetFirmwareVersion(_deviceHandle);
                double freq = HS3Native.GenGetFrequency(_deviceHandle);
                double amp = HS3Native.GenGetAmplitude(_deviceHandle);
                uint signalType = HS3Native.GenGetSignalType(_deviceHandle);
                bool outputOn = HS3Native.GenGetOutputOn(_deviceHandle);

                return $"""
                    📟 TiePie Handyscope HS3
                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    Número de Série: {serial}
                    Firmware: v{firmware:X}

                    ⚙️ Configuração Atual:
                    Frequência: {freq:F2} Hz
                    Amplitude: {amp:F2} V
                    Tipo de Sinal: {(HS3Native.SignalType)signalType}
                    Saída Ativa: {(outputOn ? "✅ SIM" : "❌ NÃO")}
                    """;
            }
            catch (Exception ex)
            {
                return $"❌ Erro ao obter informações: {ex.Message}";
            }
        });
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            try
            {
                // Parar emissão se estiver ativa
                if (IsConnected)
                {
                    HS3Native.GenStop(_deviceHandle);
                    HS3Native.GenSetOutputOn(_deviceHandle, false);
                    HS3Native.DevClose(_deviceHandle);
                    _deviceHandle = nint.Zero;
                    _logger.LogInformation("🔌 HS3 desconectado");
                }

                // Finalizar biblioteca
                if (_isLibraryInitialized)
                {
                    HS3Native.LibExit();
                    _isLibraryInitialized = false;
                    _logger.LogInformation("✅ hs3.dll finalizada");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao fazer dispose do HS3Service");
            }
        }

        _disposed = true;
    }
}
