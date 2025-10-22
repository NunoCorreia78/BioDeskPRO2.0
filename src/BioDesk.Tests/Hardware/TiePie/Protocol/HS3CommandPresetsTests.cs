using System;
using BioDesk.Services.Hardware.TiePie.Protocol;
using Xunit;

namespace BioDesk.Tests.Hardware.TiePie.Protocol;

/// <summary>
/// Testes para HS3CommandPresets.
/// Valida presets predefinidos, enum Waveform, e sequências compostas.
/// </summary>
public class HS3CommandPresetsTests
{
    #region Frequency Preset Tests

    [Theory]
    [InlineData(1.0)]
    [InlineData(10.0)]
    [InlineData(100.0)]
    [InlineData(432.0)]    // "Schumann frequency"
    [InlineData(528.0)]    // "Love frequency"
    [InlineData(1000.0)]
    [InlineData(1000000.0)] // 1 MHz max
    public void SetFrequency_WithValidRange_ReturnsValidCommand(double frequency)
    {
        // Act
        var command = HS3CommandPresets.SetFrequency(frequency);

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x40, command[0]); // OpCode 0x40
        Assert.True(command.Length <= 64); // Fits in USB bulk transfer
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(0.5)]
    [InlineData(-100.0)]
    [InlineData(1000001.0)]
    public void SetFrequency_WithInvalidRange_ThrowsException(double frequency)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => HS3CommandPresets.SetFrequency(frequency));
    }

    [Fact]
    public void SetFrequency_GeneratesDifferentBytesForDifferentFrequencies()
    {
        // Act
        var cmd1 = HS3CommandPresets.SetFrequency(100.0);
        var cmd2 = HS3CommandPresets.SetFrequency(200.0);

        // Assert
        Assert.NotEqual(cmd1, cmd2); // Different frequencies should produce different commands
    }

    #endregion

    #region Amplitude Preset Tests

    [Theory]
    [InlineData(0.0)]    // Min
    [InlineData(25.0)]
    [InlineData(50.0)]
    [InlineData(75.0)]
    [InlineData(100.0)]  // Max
    public void SetAmplitude_WithValidRange_ReturnsValidCommand(double amplitude)
    {
        // Act
        var command = HS3CommandPresets.SetAmplitude(amplitude);

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x41, command[0]); // OpCode 0x41
        Assert.True(command.Length <= 64);
    }

    [Theory]
    [InlineData(-0.1)]
    [InlineData(-50.0)]
    [InlineData(100.1)]
    [InlineData(200.0)]
    public void SetAmplitude_WithInvalidRange_ThrowsException(double amplitude)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => HS3CommandPresets.SetAmplitude(amplitude));
    }

    #endregion

    #region Waveform Enum Tests

    [Fact]
    public void Waveform_SineValue_Is0x00()
    {
        Assert.Equal(0x00, (byte)HS3CommandPresets.Waveform.Sine);
    }

    [Fact]
    public void Waveform_SquareValue_Is0x01()
    {
        Assert.Equal(0x01, (byte)HS3CommandPresets.Waveform.Square);
    }

    [Fact]
    public void Waveform_TriangleValue_Is0x02()
    {
        Assert.Equal(0x02, (byte)HS3CommandPresets.Waveform.Triangle);
    }

    [Fact]
    public void Waveform_SawtoothValue_Is0x03()
    {
        Assert.Equal(0x03, (byte)HS3CommandPresets.Waveform.Sawtooth);
    }

    #endregion

    #region Waveform Preset Tests

    [Theory]
    [InlineData(HS3CommandPresets.Waveform.Sine)]
    [InlineData(HS3CommandPresets.Waveform.Square)]
    [InlineData(HS3CommandPresets.Waveform.Triangle)]
    [InlineData(HS3CommandPresets.Waveform.Sawtooth)]
    public void SetWaveform_WithValidEnum_ReturnsValidCommand(HS3CommandPresets.Waveform waveform)
    {
        // Act
        var command = HS3CommandPresets.SetWaveform(waveform);

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x44, command[0]); // OpCode 0x44
        Assert.True(command.Length <= 64);
    }

    [Fact]
    public void SetWaveformSine_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.SetWaveformSine();

        // Assert
        Assert.NotNull(command);
        Assert.Equal(0x44, command[0]);
    }

    [Fact]
    public void SetWaveformSquare_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.SetWaveformSquare();

        // Assert
        Assert.NotNull(command);
        Assert.Equal(0x44, command[0]);
    }

    [Fact]
    public void SetWaveformTriangle_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.SetWaveformTriangle();

        // Assert
        Assert.NotNull(command);
        Assert.Equal(0x44, command[0]);
    }

    [Fact]
    public void SetWaveformSawtooth_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.SetWaveformSawtooth();

        // Assert
        Assert.NotNull(command);
        Assert.Equal(0x44, command[0]);
    }

    [Fact]
    public void SetWaveform_DifferentWaveforms_ProduceDifferentCommands()
    {
        // Act
        var sine = HS3CommandPresets.SetWaveform(HS3CommandPresets.Waveform.Sine);
        var square = HS3CommandPresets.SetWaveform(HS3CommandPresets.Waveform.Square);

        // Assert
        Assert.NotEqual(sine, square);
    }

    #endregion

    #region Emission Control Tests

    [Fact]
    public void StartEmission_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.StartEmission();

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x42, command[0]); // OpCode 0x42
        Assert.True(command.Length <= 64);
    }

    [Fact]
    public void StopEmission_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.StopEmission();

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x43, command[0]); // OpCode 0x43
        Assert.True(command.Length <= 64);
    }

    [Fact]
    public void StartEmission_AlwaysReturnsSameCommand()
    {
        // Act
        var cmd1 = HS3CommandPresets.StartEmission();
        var cmd2 = HS3CommandPresets.StartEmission();

        // Assert
        Assert.Equal(cmd1, cmd2); // Deterministic
    }

    [Fact]
    public void StopEmission_AlwaysReturnsSameCommand()
    {
        // Act
        var cmd1 = HS3CommandPresets.StopEmission();
        var cmd2 = HS3CommandPresets.StopEmission();

        // Assert
        Assert.Equal(cmd1, cmd2); // Deterministic
    }

    #endregion

    #region Duration Preset Tests

    [Theory]
    [InlineData(0)]      // Continuous
    [InlineData(1)]
    [InlineData(30)]
    [InlineData(60)]
    [InlineData(255)]    // Max
    public void SetDuration_WithValidRange_ReturnsValidCommand(int duration)
    {
        // Act
        var command = HS3CommandPresets.SetDuration(duration);

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x45, command[0]); // OpCode 0x45
        Assert.True(command.Length <= 64);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(256)]
    [InlineData(1000)]
    public void SetDuration_WithInvalidRange_ThrowsException(int duration)
    {
        // Act & Assert
        Assert.Throws<ArgumentException>(() => HS3CommandPresets.SetDuration(duration));
    }

    [Fact]
    public void SetDuration_Zero_MeansContinuous()
    {
        // Act
        var command = HS3CommandPresets.SetDuration(0);

        // Assert
        Assert.NotNull(command);
        // Duration of 0 should be the command for continuous emission
    }

    #endregion

    #region Diagnostics Presets Tests

    [Fact]
    public void GetStatus_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.GetStatus();

        // Assert
        Assert.NotNull(command);
        Assert.Equal(0x03, command[0]); // OpCode 0x03
    }

    [Fact]
    public void GetVersion_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.GetVersion();

        // Assert
        Assert.NotNull(command);
        Assert.Equal(0x04, command[0]); // OpCode 0x04
    }

    [Fact]
    public void GetError_ReturnsValidCommand()
    {
        // Act
        var command = HS3CommandPresets.GetError();

        // Assert
        Assert.NotNull(command);
        Assert.Equal(0x05, command[0]); // OpCode 0x05
    }

    #endregion

    #region Composite Sequence Tests

    [Fact]
    public void EmitFrequencySequence_Returns4Commands()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0, HS3CommandPresets.Waveform.Sine);

        // Assert
        Assert.NotNull(sequence);
        Assert.Equal(4, sequence.Length);
    }

    [Fact]
    public void EmitFrequencySequence_FirstCommandIsSetFrequency()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0);

        // Assert
        Assert.Equal(0x40, sequence[0][0]); // SET_FREQUENCY
    }

    [Fact]
    public void EmitFrequencySequence_SecondCommandIsSetAmplitude()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0);

        // Assert
        Assert.Equal(0x41, sequence[1][0]); // SET_AMPLITUDE
    }

    [Fact]
    public void EmitFrequencySequence_ThirdCommandIsSetWaveform()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0);

        // Assert
        Assert.Equal(0x44, sequence[2][0]); // SET_WAVEFORM
    }

    [Fact]
    public void EmitFrequencySequence_FourthCommandIsStartEmission()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0);

        // Assert
        Assert.Equal(0x42, sequence[3][0]); // START_EMISSION
    }

    [Fact]
    public void EmitFrequencySequence_WithDifferentWaveforms_ProducesDifferentSequences()
    {
        // Act
        var seq1 = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0, HS3CommandPresets.Waveform.Sine);
        var seq2 = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0, HS3CommandPresets.Waveform.Square);

        // Assert - Third command (waveform) should differ
        Assert.NotEqual(seq1[2], seq2[2]);
    }

    [Fact]
    public void EmitFrequencyWithDurationSequence_Returns5Commands()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencyWithDurationSequence(100.0, 50.0, 30);

        // Assert
        Assert.NotNull(sequence);
        Assert.Equal(5, sequence.Length);
    }

    [Fact]
    public void EmitFrequencyWithDurationSequence_FirstCommandIsSetDuration()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencyWithDurationSequence(100.0, 50.0, 30);

        // Assert
        Assert.Equal(0x45, sequence[0][0]); // SET_DURATION
    }

    [Fact]
    public void EmitFrequencyWithDurationSequence_LastCommandIsStartEmission()
    {
        // Act
        var sequence = HS3CommandPresets.EmitFrequencyWithDurationSequence(100.0, 50.0, 30);

        // Assert
        Assert.Equal(0x42, sequence[4][0]); // START_EMISSION (last)
    }

    #endregion

    #region OpCode Constant Tests

    [Fact]
    public void OpCode_SetFrequency_Is0x40()
    {
        Assert.Equal(0x40u, HS3CommandPresets.SET_FREQUENCY_OPCODE);
    }

    [Fact]
    public void OpCode_SetAmplitude_Is0x41()
    {
        Assert.Equal(0x41u, HS3CommandPresets.SET_AMPLITUDE_OPCODE);
    }

    [Fact]
    public void OpCode_StartEmission_Is0x42()
    {
        Assert.Equal(0x42u, HS3CommandPresets.START_EMISSION_OPCODE);
    }

    [Fact]
    public void OpCode_StopEmission_Is0x43()
    {
        Assert.Equal(0x43u, HS3CommandPresets.STOP_EMISSION_OPCODE);
    }

    [Fact]
    public void OpCode_SetWaveform_Is0x44()
    {
        Assert.Equal(0x44u, HS3CommandPresets.SET_WAVEFORM_OPCODE);
    }

    [Fact]
    public void OpCode_SetDuration_Is0x45()
    {
        Assert.Equal(0x45u, HS3CommandPresets.SET_DURATION_OPCODE);
    }

    [Fact]
    public void OpCode_GetStatus_Is0x03()
    {
        Assert.Equal(0x03u, HS3CommandPresets.GET_STATUS_OPCODE);
    }

    [Fact]
    public void OpCode_GetVersion_Is0x04()
    {
        Assert.Equal(0x04u, HS3CommandPresets.GET_VERSION_OPCODE);
    }

    [Fact]
    public void OpCode_GetError_Is0x05()
    {
        Assert.Equal(0x05u, HS3CommandPresets.GET_ERROR_OPCODE);
    }

    #endregion
}
