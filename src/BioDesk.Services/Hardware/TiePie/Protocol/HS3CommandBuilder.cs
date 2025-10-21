using System;
using System.Collections.Generic;
using System.Linq;

namespace BioDesk.Services.Hardware.TiePie.Protocol;

/// <summary>
/// Fluent builder for constructing HS3 commands with validation.
///
/// Example:
///     var command = new HS3CommandBuilder()
///         .OpCode(0x01)
///         .Frequency(100.5)
///         .Duration(30)
///         .Build();
/// </summary>
public class HS3CommandBuilder
{
    private readonly List<byte> _bytes = new();
    private byte? _opCode;

    /// <summary>
    /// Sets the operation code (first byte of command).
    /// </summary>
    public HS3CommandBuilder OpCode(byte code)
    {
        if (code == 0x00)
            throw new ArgumentException("OpCode cannot be 0x00", nameof(code));

        _opCode = code;
        _bytes.Clear();
        _bytes.Add(code);
        return this;
    }

    /// <summary>
    /// Adds a frequency parameter (2 bytes, little-endian).
    /// Range: 1 Hz to 1 MHz
    /// </summary>
    public HS3CommandBuilder Frequency(double hz)
    {
        ValidateFrequency(hz);

        uint freqInt = (uint)hz;
        _bytes.Add((byte)(freqInt & 0xFF));
        _bytes.Add((byte)((freqInt >> 8) & 0xFF));
        return this;
    }

    /// <summary>
    /// Adds a frequency parameter as uint16 (for higher precision).
    /// </summary>
    public HS3CommandBuilder FrequencyRaw(ushort rawFreq)
    {
        _bytes.Add((byte)(rawFreq & 0xFF));
        _bytes.Add((byte)((rawFreq >> 8) & 0xFF));
        return this;
    }

    /// <summary>
    /// Adds an amplitude parameter (1 byte, 0-100%).
    /// </summary>
    public HS3CommandBuilder Amplitude(double percentage)
    {
        if (percentage < 0 || percentage > 100)
            throw new ArgumentOutOfRangeException(nameof(percentage), "Amplitude must be between 0 and 100%");

        byte ampByte = (byte)Math.Round(percentage * 2.55); // 0-100% → 0-255
        _bytes.Add(ampByte);
        return this;
    }

    /// <summary>
    /// Adds a duration parameter (1 byte, 0-255 seconds).
    /// </summary>
    public HS3CommandBuilder Duration(int seconds)
    {
        if (seconds < 0 || seconds > 255)
            throw new ArgumentOutOfRangeException(nameof(seconds), "Duration must be between 0 and 255 seconds");

        _bytes.Add((byte)seconds);
        return this;
    }

    /// <summary>
    /// Adds a duration parameter in milliseconds (2 bytes, little-endian).
    /// </summary>
    public HS3CommandBuilder DurationMs(ushort milliseconds)
    {
        _bytes.Add((byte)(milliseconds & 0xFF));
        _bytes.Add((byte)((milliseconds >> 8) & 0xFF));
        return this;
    }

    /// <summary>
    /// Adds a waveform selector (1 byte).
    /// Common values: 0=Sine, 1=Square, 2=Triangle, 3=Sawtooth
    /// </summary>
    public HS3CommandBuilder Waveform(byte waveformCode)
    {
        _bytes.Add(waveformCode);
        return this;
    }

    /// <summary>
    /// Adds a waveform by name (Sine, Square, Triangle, Sawtooth).
    /// </summary>
    public HS3CommandBuilder Waveform(string waveformName)
    {
        byte waveformCode = waveformName?.ToLowerInvariant() switch
        {
            "sine" or "sin" => 0x00,
            "square" or "sqr" => 0x01,
            "triangle" or "tri" => 0x02,
            "sawtooth" or "saw" => 0x03,
            _ => throw new ArgumentException($"Unknown waveform: {waveformName}", nameof(waveformName))
        };

        _bytes.Add(waveformCode);
        return this;
    }

    /// <summary>
    /// Adds a raw byte to the command.
    /// </summary>
    public HS3CommandBuilder RawByte(byte value)
    {
        _bytes.Add(value);
        return this;
    }

    /// <summary>
    /// Adds multiple raw bytes to the command.
    /// </summary>
    public HS3CommandBuilder RawBytes(params byte[] values)
    {
        if (values != null)
            _bytes.AddRange(values);
        return this;
    }

    /// <summary>
    /// Adds a CRC8 checksum byte (simple XOR of all previous bytes).
    /// </summary>
    public HS3CommandBuilder AddCRC8()
    {
        byte crc = 0;
        foreach (byte b in _bytes)
            crc ^= b;

        _bytes.Add(crc);
        return this;
    }

    /// <summary>
    /// Gets the current command size (useful for validation).
    /// </summary>
    public int GetSize() => _bytes.Count;

    /// <summary>
    /// Validates that the command doesn't exceed max size.
    /// </summary>
    public HS3CommandBuilder ValidateMaxSize(int maxSize)
    {
        if (_bytes.Count > maxSize)
            throw new InvalidOperationException($"Command size {_bytes.Count} exceeds max {maxSize} bytes");

        return this;
    }

    /// <summary>
    /// Clears all bytes except the OpCode and rebuilds from scratch.
    /// </summary>
    public HS3CommandBuilder Reset()
    {
        _bytes.Clear();
        if (_opCode.HasValue)
            _bytes.Add(_opCode.Value);
        return this;
    }

    /// <summary>
    /// Builds the final command as byte array.
    /// </summary>
    public byte[] Build()
    {
        if (_bytes.Count == 0)
            throw new InvalidOperationException("Cannot build empty command - set OpCode first");

        return _bytes.ToArray();
    }

    /// <summary>
    /// Builds and returns hex representation for debugging.
    /// </summary>
    public string BuildHex()
    {
        var cmd = Build();
        return string.Join(" ", cmd.Select(b => $"0x{b:X2}"));
    }

    /// <summary>
    /// Validates frequency is in acceptable range.
    /// </summary>
    private static void ValidateFrequency(double hz)
    {
        if (hz < 1 || hz > 1_000_000)
            throw new ArgumentOutOfRangeException(nameof(hz), "Frequency must be between 1 Hz and 1 MHz");
    }
}
