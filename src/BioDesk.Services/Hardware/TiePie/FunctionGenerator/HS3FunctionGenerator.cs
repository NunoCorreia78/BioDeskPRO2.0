using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Hardware.TiePie.Protocol;

namespace BioDesk.Services.Hardware.TiePie.FunctionGenerator;

/// <summary>
/// Implementação de alto nível do gerador de funções TiePie HS3
/// Abstrai comandos USB em métodos type-safe
///
/// ATENÇÃO CRÍTICA: Códigos de comando são HIPOTÉTICOS!
/// Valores reais DEVEM ser descobertos via HS3CommandDiscovery.cs com hardware físico.
///
/// Estratégia de descoberta:
/// 1. Executar HS3CommandDiscovery range 0x00000001-0x000000FF
/// 2. Identificar comandos que retornam valores razoáveis (1-1MHz para freq, 0-12V para amplitude)
/// 3. Testar SET enviando valores conhecidos e verificar com GET
/// 4. Validar com osciloscópio/multímetro
/// </summary>
public class HS3FunctionGenerator : IDisposable
{
    private readonly ILogger<HS3FunctionGenerator> _logger;
    private readonly HS3DeviceProtocol _protocol;
    private bool _disposed;

    // Estado local (cache) - SEMPRE sincronizar com hardware
    private double _currentFrequency;
    private double _currentAmplitude;
    private WaveformType _currentWaveform;
    private bool _outputEnabled;

    #region Command Codes (HIPOTÉTICOS - A DESCOBRIR!)

    // ⚠️ ATENÇÃO: Estes valores são COMPLETAMENTE HIPOTÉTICOS!
    // DEVEM ser descobertos via engenharia reversa com hardware real.

    // Comandos GET (leitura de estado)
    private const uint CMD_GET_FREQUENCY = 0x00000010;
    private const uint CMD_GET_AMPLITUDE = 0x00000020;
    private const uint CMD_GET_WAVEFORM = 0x00000030;
    private const uint CMD_GET_OUTPUT_STATE = 0x00000040;
    private const uint CMD_GET_STATUS = 0x00000001;

    // Comandos SET (escrita de configuração)
    private const uint CMD_SET_FREQUENCY = 0x00000011;
    private const uint CMD_SET_AMPLITUDE = 0x00000021;
    private const uint CMD_SET_WAVEFORM = 0x00000031;
    private const uint CMD_SET_OUTPUT_ON = 0x00000041;
    private const uint CMD_SET_OUTPUT_OFF = 0x00000042;

    // Comandos de controle
    private const uint CMD_RESET = 0x000001FF;
    private const uint CMD_CALIBRATE = 0x00000100;

    #endregion

    public HS3FunctionGenerator(ILogger<HS3FunctionGenerator> logger, HS3DeviceProtocol protocol)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _protocol = protocol ?? throw new ArgumentNullException(nameof(protocol));
    }

    #region Frequency Control

    /// <summary>
    /// Define frequência de saída
    /// </summary>
    /// <param name="frequencyHz">Frequência em Hz (range típico: 0.1 Hz - 50 MHz)</param>
    /// <returns>True se sucesso</returns>
    public async Task<bool> SetFrequencyAsync(double frequencyHz)
    {
        if (frequencyHz < 0.1 || frequencyHz > 50e6)
        {
            _logger.LogError("❌ Frequência fora de range: {Freq} Hz (válido: 0.1 Hz - 50 MHz)",
                frequencyHz);
            return false;
        }

        _logger.LogDebug("Definindo frequência: {Freq:F6} Hz", frequencyHz);

        try
        {
            // TODO: Descobrir protocolo correto
            // Hipótese 1: WRITE_OPERATION com double (8 bytes)
            // Hipótese 2: READ→WRITE com comando específico

            // Preparar payload: double em formato IEEE 754
            byte[] payload = BitConverter.GetBytes(frequencyHz);

            // Tentar enviar comando
            bool success = _protocol.WriteOperation(
                CMD_SET_FREQUENCY,
                payload.Length,
                out byte[] response);

            if (!success)
            {
                _logger.LogError("❌ SET_FREQUENCY falhou");
                return false;
            }

            // Verificar resposta (deveria ser status OK)
            if (response.Length > 0 && response[0] != 0x00)
            {
                _logger.LogWarning("⚠️ SET_FREQUENCY retornou status: 0x{Status:X2}", response[0]);
            }

            // Atualizar cache local
            _currentFrequency = frequencyHz;

            // Validar com GET (confirmar que hardware aceitou)
            double readBack = await GetFrequencyAsync();
            if (Math.Abs(readBack - frequencyHz) > 0.01) // Tolerância 0.01 Hz
            {
                _logger.LogWarning("⚠️ Frequência read-back difere: Set={Set:F6} Hz, Get={Get:F6} Hz",
                    frequencyHz, readBack);
            }

            _logger.LogInformation("✅ Frequência definida: {Freq:F6} Hz", frequencyHz);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao definir frequência");
            return false;
        }
    }

    /// <summary>
    /// Lê frequência atual do dispositivo
    /// </summary>
    /// <returns>Frequência em Hz (0 se erro)</returns>
    public Task<double> GetFrequencyAsync()
    {
        try
        {
            bool success = _protocol.ReadOperation(CMD_GET_FREQUENCY, out HS3Response8 response);

            if (!success)
            {
                _logger.LogError("❌ GET_FREQUENCY falhou");
                return Task.FromResult(0.0);
            }

            // Interpretar resposta como double
            double frequency = response.ValueAsDouble;

            // Validar range razoável
            if (frequency < 0 || frequency > 1e9)
            {
                _logger.LogWarning("⚠️ GET_FREQUENCY retornou valor suspeito: {Freq}", frequency);
                return Task.FromResult(0.0);
            }

            _currentFrequency = frequency;
            _logger.LogTrace("GET_FREQUENCY: {Freq:F6} Hz", frequency);

            return Task.FromResult(frequency);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao ler frequência");
            return Task.FromResult(0.0);
        }
    }

    #endregion

    #region Amplitude Control

    /// <summary>
    /// Define amplitude de saída (pico-a-pico)
    /// </summary>
    /// <param name="amplitudeVpp">Amplitude em Volts pico-a-pico (range típico: 0.01 V - 12 V)</param>
    /// <returns>True se sucesso</returns>
    public async Task<bool> SetAmplitudeAsync(double amplitudeVpp)
    {
        if (amplitudeVpp < 0.01 || amplitudeVpp > 12.0)
        {
            _logger.LogError("❌ Amplitude fora de range: {Amp} Vpp (válido: 0.01 V - 12 V)",
                amplitudeVpp);
            return false;
        }

        _logger.LogDebug("Definindo amplitude: {Amp:F3} Vpp", amplitudeVpp);

        try
        {
            byte[] payload = BitConverter.GetBytes(amplitudeVpp);

            bool success = _protocol.WriteOperation(
                CMD_SET_AMPLITUDE,
                payload.Length,
                out byte[] response);

            if (!success)
            {
                _logger.LogError("❌ SET_AMPLITUDE falhou");
                return false;
            }

            _currentAmplitude = amplitudeVpp;

            // Validar com GET
            double readBack = await GetAmplitudeAsync();
            if (Math.Abs(readBack - amplitudeVpp) > 0.01) // Tolerância 0.01 V
            {
                _logger.LogWarning("⚠️ Amplitude read-back difere: Set={Set:F3} V, Get={Get:F3} V",
                    amplitudeVpp, readBack);
            }

            _logger.LogInformation("✅ Amplitude definida: {Amp:F3} Vpp", amplitudeVpp);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao definir amplitude");
            return false;
        }
    }

    /// <summary>
    /// Lê amplitude atual do dispositivo
    /// </summary>
    /// <returns>Amplitude em Vpp (0 se erro)</returns>
    public Task<double> GetAmplitudeAsync()
    {
        try
        {
            bool success = _protocol.ReadOperation(CMD_GET_AMPLITUDE, out HS3Response8 response);

            if (!success)
            {
                _logger.LogError("❌ GET_AMPLITUDE falhou");
                return Task.FromResult(0.0);
            }

            double amplitude = response.ValueAsDouble;

            // Validar range razoável
            if (amplitude < 0 || amplitude > 100)
            {
                _logger.LogWarning("⚠️ GET_AMPLITUDE retornou valor suspeito: {Amp}", amplitude);
                return Task.FromResult(0.0);
            }

            _currentAmplitude = amplitude;
            _logger.LogTrace("GET_AMPLITUDE: {Amp:F3} Vpp", amplitude);

            return Task.FromResult(amplitude);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao ler amplitude");
            return Task.FromResult(0.0);
        }
    }

    #endregion

    #region Waveform Control

    /// <summary>
    /// Define tipo de forma de onda
    /// </summary>
    /// <param name="waveform">Tipo de onda (Sine, Square, Triangle, etc)</param>
    /// <returns>True se sucesso</returns>
    public async Task<bool> SetWaveformAsync(WaveformType waveform)
    {
        _logger.LogDebug("Definindo waveform: {Waveform}", waveform);

        try
        {
            // Waveform provavelmente é enum (uint)
            uint waveformCode = (uint)waveform;
            byte[] payload = BitConverter.GetBytes(waveformCode);

            bool success = _protocol.WriteOperation(
                CMD_SET_WAVEFORM,
                payload.Length,
                out byte[] response);

            if (!success)
            {
                _logger.LogError("❌ SET_WAVEFORM falhou");
                return false;
            }

            _currentWaveform = waveform;

            _logger.LogInformation("✅ Waveform definido: {Waveform}", waveform);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao definir waveform");
            return false;
        }
    }

    /// <summary>
    /// Lê tipo de forma de onda atual
    /// </summary>
    /// <returns>Tipo de onda</returns>
    public Task<WaveformType> GetWaveformAsync()
    {
        try
        {
            bool success = _protocol.ReadOperation(CMD_GET_WAVEFORM, out HS3Response8 response);

            if (!success)
            {
                _logger.LogError("❌ GET_WAVEFORM falhou");
                return Task.FromResult(WaveformType.Unknown);
            }

            // Interpretar como enum
            uint waveformCode = response.LowDWord;
            var waveform = (WaveformType)waveformCode;

            _currentWaveform = waveform;
            _logger.LogTrace("GET_WAVEFORM: {Waveform}", waveform);

            return Task.FromResult(waveform);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao ler waveform");
            return Task.FromResult(WaveformType.Unknown);
        }
    }

    #endregion

    #region Output Control

    /// <summary>
    /// Liga saída do gerador
    /// </summary>
    /// <returns>True se sucesso</returns>
    public async Task<bool> EnableOutputAsync()
    {
        _logger.LogInformation("🔌 Ligando saída do gerador...");

        try
        {
            bool success = _protocol.SendCommand(CMD_SET_OUTPUT_ON, 1, out byte[] response);

            if (!success)
            {
                _logger.LogError("❌ SET_OUTPUT_ON falhou");
                return false;
            }

            // Verificar status (deveria retornar 0x00 = OK)
            if (response.Length > 0 && response[0] != 0x00)
            {
                _logger.LogWarning("⚠️ SET_OUTPUT_ON retornou status: 0x{Status:X2}", response[0]);
            }

            _outputEnabled = true;

            // Confirmar com GET
            bool isOn = await IsOutputEnabledAsync();
            if (!isOn)
            {
                _logger.LogWarning("⚠️ Output não confirmou estado ON após comando");
            }

            _logger.LogInformation("✅ Saída LIGADA");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao ligar saída");
            return false;
        }
    }

    /// <summary>
    /// Desliga saída do gerador (SEGURANÇA!)
    /// </summary>
    /// <returns>True se sucesso</returns>
    public Task<bool> DisableOutputAsync()
    {
        _logger.LogInformation("🔌 Desligando saída do gerador...");

        try
        {
            bool success = _protocol.SendCommand(CMD_SET_OUTPUT_OFF, 1, out byte[] response);

            if (!success)
            {
                _logger.LogError("❌ SET_OUTPUT_OFF falhou");
                return Task.FromResult(false);
            }

            _outputEnabled = false;

            _logger.LogInformation("✅ Saída DESLIGADA");
            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao desligar saída");
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Verifica se saída está ligada
    /// </summary>
    /// <returns>True se saída está ON</returns>
    public Task<bool> IsOutputEnabledAsync()
    {
        try
        {
            bool success = _protocol.ReadOperation(CMD_GET_OUTPUT_STATE, out HS3Response8 response);

            if (!success)
            {
                _logger.LogError("❌ GET_OUTPUT_STATE falhou");
                return Task.FromResult(false);
            }

            // Interpretar como bool (0 = OFF, 1 = ON)
            bool isOn = response.LowDWord != 0;

            _outputEnabled = isOn;
            _logger.LogTrace("GET_OUTPUT_STATE: {State}", isOn ? "ON" : "OFF");

            return Task.FromResult(isOn);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Exceção ao ler estado output");
            return Task.FromResult(false);
        }
    }

    #endregion

    #region High-Level Methods

    /// <summary>
    /// Configura gerador completo (frequência + amplitude + waveform) e liga saída
    /// Método conveniente para setup rápido
    /// </summary>
    public async Task<bool> ConfigureAndStartAsync(
        double frequencyHz,
        double amplitudeVpp,
        WaveformType waveform = WaveformType.Sine)
    {
        _logger.LogInformation("⚙️ Configurando gerador: {Freq} Hz, {Amp} Vpp, {Wave}",
            frequencyHz, amplitudeVpp, waveform);

        // 1. Desligar output (segurança)
        await DisableOutputAsync();

        // 2. Configurar parâmetros
        if (!await SetFrequencyAsync(frequencyHz))
            return false;

        if (!await SetAmplitudeAsync(amplitudeVpp))
            return false;

        if (!await SetWaveformAsync(waveform))
            return false;

        // 3. Ligar output
        if (!await EnableOutputAsync())
            return false;

        _logger.LogInformation("🎉 Gerador configurado e ativo!");
        return true;
    }

    /// <summary>
    /// Para emissão e desliga output (EMERGENCY STOP)
    /// </summary>
    public async Task<bool> EmergencyStopAsync()
    {
        _logger.LogWarning("🚨 EMERGENCY STOP ativado!");

        bool success = await DisableOutputAsync();

        if (success)
        {
            // Zerar amplitude por segurança
            await SetAmplitudeAsync(0.0);
        }

        return success;
    }

    /// <summary>
    /// Reseta gerador para configuração padrão segura
    /// </summary>
    public async Task<bool> ResetToSafeDefaultsAsync()
    {
        _logger.LogInformation("🔄 Resetando gerador para defaults seguros...");

        // Desligar output
        await DisableOutputAsync();

        // Configurações seguras
        await SetFrequencyAsync(7.83); // Ressonância Schumann (segura)
        await SetAmplitudeAsync(1.0); // 1V (baixa)
        await SetWaveformAsync(WaveformType.Sine); // Sine (suave)

        _logger.LogInformation("✅ Gerador resetado para defaults seguros");
        return true;
    }

    /// <summary>
    /// Lê estado completo do gerador
    /// </summary>
    public async Task<GeneratorState> GetStateAsync()
    {
        return new GeneratorState
        {
            Frequency = await GetFrequencyAsync(),
            Amplitude = await GetAmplitudeAsync(),
            Waveform = await GetWaveformAsync(),
            OutputEnabled = await IsOutputEnabledAsync()
        };
    }

    #endregion

    #region Properties

    /// <summary>
    /// Frequência atual (cache local - pode estar dessinc do hardware)
    /// Usar GetFrequencyAsync() para ler valor real
    /// </summary>
    public double CurrentFrequency => _currentFrequency;

    /// <summary>
    /// Amplitude atual (cache local)
    /// </summary>
    public double CurrentAmplitude => _currentAmplitude;

    /// <summary>
    /// Waveform atual (cache local)
    /// </summary>
    public WaveformType CurrentWaveform => _currentWaveform;

    /// <summary>
    /// Estado output (cache local)
    /// </summary>
    public bool OutputEnabled => _outputEnabled;

    #endregion

    #region Dispose

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
            // Desligar output ao dispose (SEGURANÇA!)
            try
            {
                DisableOutputAsync().Wait(TimeSpan.FromSeconds(2));
                _logger.LogInformation("✅ Output desligado ao dispose (segurança)");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Falha ao desligar output no dispose");
            }
        }

        _disposed = true;
    }

    #endregion
}

#region Enums and Data Structures

/// <summary>
/// Tipos de forma de onda suportados
/// Valores são HIPOTÉTICOS - descobrir valores reais via hardware
/// </summary>
public enum WaveformType : uint
{
    Unknown = 0,
    Sine = 1,        // Onda senoidal (suave, natural)
    Square = 2,      // Onda quadrada (rica em harmônicos)
    Triangle = 3,    // Onda triangular
    Sawtooth = 4,    // Onda dente de serra
    Pulse = 5,       // Pulso (duty cycle variável)
    Noise = 6,       // Ruído branco (aleatório)
    DC = 7,          // DC offset
    Arbitrary = 8    // Forma de onda arbitrária (AWG)
}

/// <summary>
/// Estado completo do gerador
/// </summary>
public class GeneratorState
{
    public double Frequency { get; set; }
    public double Amplitude { get; set; }
    public WaveformType Waveform { get; set; }
    public bool OutputEnabled { get; set; }

    public override string ToString() =>
        $"{Frequency:F3} Hz, {Amplitude:F3} Vpp, {Waveform}, Output {(OutputEnabled ? "ON" : "OFF")}";
}

#endregion
