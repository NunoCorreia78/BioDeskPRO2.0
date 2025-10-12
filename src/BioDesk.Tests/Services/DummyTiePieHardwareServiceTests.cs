using System;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Services.Hardware;
using Microsoft.Extensions.Logging;
using Xunit;

namespace BioDesk.Tests.Services;

public class DummyTiePieHardwareServiceTests
{
    private readonly DummyTiePieHardwareService _service;

    public DummyTiePieHardwareServiceTests()
    {
        var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
        var logger = loggerFactory.CreateLogger<DummyTiePieHardwareService>();
        _service = new DummyTiePieHardwareService(logger);
    }

    [Fact]
    public async Task GetStatus_RetornaHardwareConectadoSimulado()
    {
        // Act
        var status = await _service.GetStatusAsync();

        // Assert
        Assert.NotNull(status);
        Assert.True(status.IsConnected);
        Assert.Equal("TiePie Handyscope HS5 (DUMMY)", status.DeviceName);
        Assert.Equal("DUMMY-12345", status.SerialNumber);
        Assert.Equal(2, status.ChannelCount);
        Assert.Equal(5_000_000, status.MaxFrequencyHz); // 5 MHz
        Assert.Equal(8.0, status.MaxVoltageV);
        Assert.Null(status.ErrorMessage);
    }

    [Fact]
    public async Task SendSignal_ConfiguracaoValida_RetornaTrue()
    {
        // Arrange
        var config = new SignalConfiguration
        {
            Channel = SignalChannel.Channel1,
            FrequencyHz = 2720.0,
            VoltageV = 2.5,
            Waveform = SignalWaveform.Sine,
            DurationSeconds = 1.0 // Reduzido para teste rápido
        };

        // Act
        var result = await _service.SendSignalAsync(config);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task SendSignal_ConfiguracaoInvalida_RetornaFalse()
    {
        // Arrange - Frequência fora do range
        var config = new SignalConfiguration
        {
            Channel = SignalChannel.Channel1,
            FrequencyHz = 10_000_000, // 10 MHz - acima do máximo (5 MHz)
            VoltageV = 2.5,
            Waveform = SignalWaveform.Sine,
            DurationSeconds = 1.0
        };

        // Act
        var result = await _service.SendSignalAsync(config);

        // Assert
        Assert.False(result);
    }

    [Fact]
    public async Task SendSignal_ConfiguracaoNull_ThrowsArgumentNullException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ArgumentNullException>(() => 
            _service.SendSignalAsync(null!));
    }

    [Fact]
    public async Task StopAllChannels_ExecutaSemErros()
    {
        // Act
        await _service.StopAllChannelsAsync();

        // Assert - Não deve lançar exceção
        Assert.True(true);
    }

    [Fact]
    public async Task SendMultipleFrequencies_ArrayValido_RetornaTrue()
    {
        // Arrange
        var frequencies = new double[] { 2720.0, 1600.0, 987.6 };

        // Act
        var result = await _service.SendMultipleFrequenciesAsync(
            frequencies,
            SignalChannel.Channel1,
            voltageV: 1.5,
            waveform: SignalWaveform.Sine,
            durationPerFreqSeconds: 0.5 // Reduzido para teste rápido
        );

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task SendMultipleFrequencies_ArrayVazio_ThrowsArgumentException()
    {
        // Arrange
        var frequencies = Array.Empty<double>();

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.SendMultipleFrequenciesAsync(frequencies));
    }

    [Fact]
    public async Task SendMultipleFrequencies_ArrayNull_ThrowsArgumentException()
    {
        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _service.SendMultipleFrequenciesAsync(null!));
    }

    [Fact]
    public async Task TestHardware_ExecutaComSucesso()
    {
        // Act
        var result = await _service.TestHardwareAsync();

        // Assert
        Assert.True(result);
    }

    [Theory]
    [InlineData(SignalChannel.Channel1, 2720.0, 1.0, SignalWaveform.Sine)]
    [InlineData(SignalChannel.Channel2, 1600.0, 2.5, SignalWaveform.Square)]
    [InlineData(SignalChannel.Channel1, 987.6, 1.5, SignalWaveform.Triangle)]
    [InlineData(SignalChannel.Channel2, 5000.0, 3.0, SignalWaveform.Sawtooth)]
    public async Task SendSignal_DiferentesConfiguracoes_RetornaTrue(
        SignalChannel channel,
        double frequencyHz,
        double voltageV,
        SignalWaveform waveform)
    {
        // Arrange
        var config = new SignalConfiguration
        {
            Channel = channel,
            FrequencyHz = frequencyHz,
            VoltageV = voltageV,
            Waveform = waveform,
            DurationSeconds = 0.5 // Reduzido para teste rápido
        };

        // Act
        var result = await _service.SendSignalAsync(config);

        // Assert
        Assert.True(result);
    }

    [Fact]
    public void SignalConfiguration_IsValid_ValidaCorretamente()
    {
        // Arrange & Act & Assert

        // ✅ Configuração válida
        var validConfig = new SignalConfiguration
        {
            FrequencyHz = 2720.0,
            VoltageV = 2.5,
            DurationSeconds = 60.0
        };
        Assert.True(validConfig.IsValid());

        // ❌ Frequência muito baixa
        var lowFreq = new SignalConfiguration
        {
            FrequencyHz = 0.05, // < 0.1 Hz
            VoltageV = 2.5,
            DurationSeconds = 60.0
        };
        Assert.False(lowFreq.IsValid());

        // ❌ Frequência muito alta
        var highFreq = new SignalConfiguration
        {
            FrequencyHz = 10_000_000, // > 5 MHz
            VoltageV = 2.5,
            DurationSeconds = 60.0
        };
        Assert.False(highFreq.IsValid());

        // ❌ Voltagem muito baixa
        var lowVoltage = new SignalConfiguration
        {
            FrequencyHz = 2720.0,
            VoltageV = 0.1, // < 0.2V
            DurationSeconds = 60.0
        };
        Assert.False(lowVoltage.IsValid());

        // ❌ Voltagem muito alta
        var highVoltage = new SignalConfiguration
        {
            FrequencyHz = 2720.0,
            VoltageV = 10.0, // > 8V
            DurationSeconds = 60.0
        };
        Assert.False(highVoltage.IsValid());

        // ❌ Duração zero
        var zeroDuration = new SignalConfiguration
        {
            FrequencyHz = 2720.0,
            VoltageV = 2.5,
            DurationSeconds = 0.0
        };
        Assert.False(zeroDuration.IsValid());
    }
}
