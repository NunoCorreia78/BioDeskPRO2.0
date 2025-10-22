using System;
using BioDesk.Services.Hardware.TiePie.Protocol;
using Xunit;

namespace BioDesk.Tests.Hardware.TiePie.Protocol;

/// <summary>
/// Testes de unidade para HS3CommandBuilder.
/// Valida construção de comandos, ranges, CRC8, e presets.
/// Não requer hardware - usa valores determinísticos.
/// </summary>
public class HS3CommandBuilderTests
{
    #region Basic Construction Tests

    [Fact]
    public void Build_WithValidOpCode_ReturnsValidCommand()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act
        var command = builder
            .OpCode(0x40)
            .Build();

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x40, command[0]);
    }

    [Fact]
    public void Build_WithMultipleParameters_ChainsProperly()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act
        var command = builder
            .OpCode(0x40)
            .Frequency(100.5)
            .Amplitude(50.0)
            .Build();

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x40, command[0]); // OpCode preserved
        Assert.True(command.Length >= 1); // At least opcode
    }

    [Fact]
    public void OpCode_WithValidValue_Stores()
    {
        // Arrange & Act
        var builder = new HS3CommandBuilder();
        builder.OpCode(0x42);
        var command = builder.Build();

        // Assert
        Assert.Equal(0x42, command[0]);
    }

    #endregion

    #region Validation Tests - Frequency Range

    [Theory]
    [InlineData(1.0)]      // Min valid
    [InlineData(100.5)]    // Middle value
    [InlineData(1000000.0)] // Max valid (1MHz)
    public void Frequency_WithValidRange_Accepts(double frequency)
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert - should not throw
        var command = builder
            .OpCode(0x40)
            .Frequency(frequency)
            .Build();

        Assert.NotNull(command);
    }

    [Theory]
    [InlineData(0.5)]    // Below min
    [InlineData(0.0)]    // Zero
    [InlineData(1000001.0)]  // Above max
    [InlineData(-100.0)]     // Negative
    public void Frequency_WithInvalidRange_ThrowsArgumentException(double frequency)
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            builder.OpCode(0x40).Frequency(frequency).Build()
        );

        Assert.Contains("hz", ex.ParamName?.ToLower() ?? ex.Message.ToLower());
    }

    #endregion

    #region Validation Tests - Amplitude Range

    [Theory]
    [InlineData(0.0)]    // Min valid
    [InlineData(50.0)]   // Middle value
    [InlineData(100.0)]  // Max valid
    public void Amplitude_WithValidRange_Accepts(double amplitude)
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert - should not throw
        var command = builder
            .OpCode(0x41)
            .Amplitude(amplitude)
            .Build();

        Assert.NotNull(command);
    }

    [Theory]
    [InlineData(-0.1)]   // Below min
    [InlineData(-50.0)]  // Below min
    [InlineData(100.1)]  // Above max
    [InlineData(200.0)]  // Above max
    public void Amplitude_WithInvalidRange_ThrowsArgumentException(double amplitude)
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            builder.OpCode(0x41).Amplitude(amplitude).Build()
        );

        Assert.Contains("percentage", ex.ParamName?.ToLower() ?? ex.Message.ToLower());
    }

    #endregion

    #region Validation Tests - Duration Range

    [Theory]
    [InlineData(0)]       // Min valid
    [InlineData(128)]     // Middle value
    [InlineData(255)]     // Max valid
    public void Duration_WithValidRange_Accepts(int duration)
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert - should not throw
        var command = builder
            .OpCode(0x43)
            .Duration(duration)
            .Build();

        Assert.NotNull(command);
    }

    [Theory]
    [InlineData(-1)]      // Below min
    [InlineData(256)]     // Above max
    [InlineData(1000)]    // Way above max
    public void Duration_WithInvalidRange_ThrowsArgumentException(int duration)
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() =>
            builder.OpCode(0x43).Duration(duration).Build()
        );

        Assert.Contains("seconds", ex.ParamName?.ToLower() ?? ex.Message.ToLower());
    }

    #endregion

    #region Size Validation Tests

    [Fact]
    public void ValidateMaxSize_WithValidSize_DoesNotThrow()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert - should not throw
        var command = builder
            .OpCode(0x40)
            .Frequency(100.0)
            .ValidateMaxSize(64) // Valid for USB bulk transfer
            .Build();

        Assert.NotNull(command);
        Assert.True(command.Length <= 64);
    }

    [Fact]
    public void ValidateMaxSize_WithSmallLimit_ThrowsIfExceeded()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            builder
                .OpCode(0x40)
                .Frequency(100.0)
                .Amplitude(50.0)
                .Duration(255)
                .ValidateMaxSize(2) // Too small
                .Build()
        );

        Assert.Contains("exceed", ex.Message.ToLower());
    }

    #endregion

    #region Preset Tests

    [Fact]
    public void SetFrequency_CreatesValidCommand()
    {
        // Arrange
        var frequency = 50.0;

        // Act
        var command = HS3CommandPresets.SetFrequency(frequency);

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x40, command[0]); // SetFrequency uses OpCode 0x40
    }

    [Fact]
    public void SetAmplitude_CreatesValidCommand()
    {
        // Arrange
        var amplitude = 75.0;

        // Act
        var command = HS3CommandPresets.SetAmplitude(amplitude);

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x41, command[0]); // SetAmplitude uses OpCode 0x41
    }

    [Fact]
    public void StartEmission_CreatesValidCommand()
    {
        // Arrange & Act
        var command = HS3CommandPresets.StartEmission();

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x42, command[0]); // StartEmission uses OpCode 0x42
    }

    [Fact]
    public void StopEmission_CreatesValidCommand()
    {
        // Arrange & Act
        var command = HS3CommandPresets.StopEmission();

        // Assert
        Assert.NotNull(command);
        Assert.NotEmpty(command);
        Assert.Equal(0x43, command[0]); // StopEmission uses OpCode 0x43
    }

    #endregion

    #region CRC8 Tests

    [Fact]
    public void AddCRC8_AddsChecksum()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act
        var command = builder
            .OpCode(0x40)
            .AddCRC8()
            .Build();

        // Assert
        Assert.NotNull(command);
        Assert.True(command.Length >= 2); // At least OpCode + CRC8
        // CRC8 should be last byte
        byte lastByte = command[command.Length - 1];
        Assert.NotEqual(0, lastByte); // CRC8 unlikely to be 0 for OpCode 0x40
    }

    [Fact]
    public void AddCRC8_DifferentOpcodes_ProduceDifferentChecksums()
    {
        // Arrange
        var builder1 = new HS3CommandBuilder();
        var builder2 = new HS3CommandBuilder();

        // Act
        var command1 = builder1.OpCode(0x40).AddCRC8().Build();
        var command2 = builder2.OpCode(0x41).AddCRC8().Build();

        // Assert
        Assert.NotEqual(command1[command1.Length - 1], command2[command2.Length - 1]);
    }

    #endregion

    #region Empty/Invalid Command Tests

    [Fact]
    public void Build_WithoutOpCode_ThrowsInvalidOperationException()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var ex = Assert.Throws<InvalidOperationException>(() =>
            builder.Build() // No OpCode set
        );

        Assert.Contains("opcode", ex.Message.ToLower());
    }

    [Fact]
    public void OpCode_WithZero_ThrowsException()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert - OpCode 0x00 is now reserved and should throw
        Assert.Throws<ArgumentException>(() => builder.OpCode(0x00));
    }

    [Fact]
    public void OpCode_WithMaxByte_IsValid()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert - OpCode 0xFF should be valid
        var command = builder.OpCode(0xFF).Build();
        Assert.Equal(0xFF, command[0]);
    }

    #endregion

    #region Complex Command Tests

    [Fact]
    public void CompleteFrequencyEmitCommand_BuildsSuccessfully()
    {
        // This simulates the real use case: Set frequency → Set amplitude → Start emission

        // Act
        var freqCommand = new HS3CommandBuilder()
            .OpCode(0x40)
            .Frequency(100.5)
            .ValidateMaxSize(64)
            .Build();

        var ampCommand = new HS3CommandBuilder()
            .OpCode(0x41)
            .Amplitude(50.0)
            .ValidateMaxSize(64)
            .Build();

        var startCommand = new HS3CommandBuilder()
            .OpCode(0x42)
            .ValidateMaxSize(64)
            .Build();

        // Assert
        Assert.NotNull(freqCommand);
        Assert.NotNull(ampCommand);
        Assert.NotNull(startCommand);

        Assert.All(new[] { freqCommand, ampCommand, startCommand },
            cmd => Assert.True(cmd.Length <= 64));
    }

    [Fact]
    public void Builder_CanBeReused()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act
        var cmd1 = builder.OpCode(0x40).Build();
        var cmd2 = builder.OpCode(0x41).Build();
        var cmd3 = builder.OpCode(0x42).Build();

        // Assert
        Assert.Equal(0x40, cmd1[0]);
        Assert.Equal(0x41, cmd2[0]);
        Assert.Equal(0x42, cmd3[0]);
    }

    #endregion

    #region Boundary Tests

    [Fact]
    public void Frequency_AtMinBoundary_IsValid()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var command = builder.OpCode(0x40).Frequency(1.0).Build();
        Assert.NotNull(command);
    }

    [Fact]
    public void Frequency_JustBelowMinBoundary_ThrowsException()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            builder.OpCode(0x40).Frequency(0.99999).Build()
        );
    }

    [Fact]
    public void Frequency_AtMaxBoundary_IsValid()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var command = builder.OpCode(0x40).Frequency(1000000.0).Build();
        Assert.NotNull(command);
    }

    [Fact]
    public void Frequency_JustAboveMaxBoundary_ThrowsException()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            builder.OpCode(0x40).Frequency(1000000.1).Build()
        );
    }

    [Fact]
    public void Duration_AtMinBoundary_IsValid()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var command = builder.OpCode(0x43).Duration(0).Build();
        Assert.NotNull(command);
    }

    [Fact]
    public void Duration_AtMaxBoundary_IsValid()
    {
        // Arrange
        var builder = new HS3CommandBuilder();

        // Act & Assert
        var command = builder.OpCode(0x43).Duration(255).Build();
        Assert.NotNull(command);
    }

    #endregion
}
