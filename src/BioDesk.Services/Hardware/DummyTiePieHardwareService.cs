using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Hardware;

/// <summary>
/// Implementação dummy para testes SEM hardware físico
/// Simula comportamento do TiePie Handyscope HS5
/// </summary>
public class DummyTiePieHardwareService : ITiePieHardwareService
{
    private readonly ILogger<DummyTiePieHardwareService> _logger;
    private bool _isSimulatingSignal = false;

    public DummyTiePieHardwareService(ILogger<DummyTiePieHardwareService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _logger.LogWarning("🔶 DummyTiePieHardwareService inicializado - MODO SIMULAÇÃO (sem hardware real)");
    }

    public Task<HardwareStatus> GetStatusAsync()
    {
        _logger.LogInformation("📡 GetStatus: Simulando hardware conectado");

        var status = new HardwareStatus
        {
            IsConnected = true,
            DeviceName = "TiePie Handyscope HS5 (DUMMY)",
            SerialNumber = "DUMMY-12345",
            ChannelCount = 2,
            MaxFrequencyHz = 5_000_000, // 5 MHz
            MaxVoltageV = 8.0,
            ErrorMessage = null
        };

        return Task.FromResult(status);
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

        _logger.LogInformation(
            "🔊 SIMULANDO envio de sinal: {Config}",
            config);

        _isSimulatingSignal = true;

        // Simular duração do sinal
        await Task.Delay(TimeSpan.FromSeconds(Math.Min(config.DurationSeconds, 5.0))); // Máx 5s em dummy mode

        _isSimulatingSignal = false;

        _logger.LogInformation("✅ Sinal simulado com sucesso");
        return true;
    }

    public Task StopAllChannelsAsync()
    {
        _logger.LogInformation("🛑 SIMULANDO paragem de todos os canais");
        _isSimulatingSignal = false;
        return Task.CompletedTask;
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
            "🎵 SIMULANDO envio de {Count} frequências no Ch{Channel}: [{Freqs}]",
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

        _logger.LogInformation("✅ Todas as {Count} frequências foram simuladas com sucesso", frequencies.Length);
        return true;
    }

    public async Task<bool> TestHardwareAsync()
    {
        _logger.LogInformation("🧪 SIMULANDO teste de hardware: 1 kHz, 1V, Sine, 2s");

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
            _logger.LogInformation("✅ Teste de hardware simulado: PASSOU");
        else
            _logger.LogError("❌ Teste de hardware simulado: FALHOU");

        return result;
    }
}
