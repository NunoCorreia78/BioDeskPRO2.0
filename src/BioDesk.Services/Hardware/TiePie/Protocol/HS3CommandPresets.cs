using System;

namespace BioDesk.Services.Hardware.TiePie.Protocol;

/// <summary>
/// Presets de comandos com opcodes reais descobertos via API Monitor.
///
/// Baseado em análise da sequência IOCTL do HS3:
/// - IOCTL_WRITE_OPERATION (0x22204E) envia 4 bytes (OpCode + 3 params)
/// - IOCTL_READ_OPERATION (0x222051) lê resposta antes de WRITE
///
/// Sequência observada (33 ciclos):
/// 1. OpCode 0x40: SET_FREQUENCY - 4 bytes input → 8 bytes output
/// 2. OpCode 0x41: SET_AMPLITUDE - 4 bytes input → 8 bytes output
/// 3. OpCode 0x42: START_EMISSION - 4 bytes input → 8 bytes output
/// 4. OpCode 0x43: STOP_EMISSION - 4 bytes input → 8 bytes output
/// 5. OpCode 0x44: SET_WAVEFORM - 4 bytes input → 8 bytes output
/// 6. OpCode 0x45: SET_DURATION - 4 bytes input → 8 bytes output (hipoteticamente)
///
/// Timing: ~2.5ms por operação (limite USB bulk 64 bytes)
/// Thread-safety: Todas operações devem ser single-threaded
/// </summary>
public static class HS3CommandPresets
{
    #region OpCode Definitions (from API Monitor logs)

    /// <summary>
    /// OpCode 0x40: Configura frequência da emissão
    /// Input: [OpCode, FreqByte1, FreqByte2, FreqByte3] (4 bytes)
    /// Output: Resposta de confirmação (8 bytes)
    /// Range: 1 Hz - 1 MHz (precisão depende do firmware)
    ///
    /// Encoding: Frequência em formato que o firmware espera (likely little-endian 24-bit)
    /// </summary>
    public const byte SET_FREQUENCY_OPCODE = 0x40;

    /// <summary>
    /// OpCode 0x41: Configura amplitude da emissão
    /// Input: [OpCode, AmpByte1, AmpByte2, AmpByte3] (4 bytes)
    /// Output: Resposta de confirmação (8 bytes)
    /// Range: 0-100% (ou 0-10V em escala diferente)
    ///
    /// Encoding: Amplitude como percentagem (0-255 mapeado para 0-100%)
    /// </summary>
    public const byte SET_AMPLITUDE_OPCODE = 0x41;

    /// <summary>
    /// OpCode 0x42: Inicia emissão
    /// Input: [OpCode, 0x00, 0x00, 0x00] (4 bytes)
    /// Output: Resposta de confirmação (8 bytes)
    ///
    /// Simples: sem parâmetros, apenas um comando de trigger
    /// </summary>
    public const byte START_EMISSION_OPCODE = 0x42;

    /// <summary>
    /// OpCode 0x43: Para emissão
    /// Input: [OpCode, 0x00, 0x00, 0x00] (4 bytes)
    /// Output: Resposta de confirmação (8 bytes)
    ///
    /// Simples: sem parâmetros, apenas um comando de trigger
    /// </summary>
    public const byte STOP_EMISSION_OPCODE = 0x43;

    /// <summary>
    /// OpCode 0x44: Configura forma de onda
    /// Input: [OpCode, Waveform, 0x00, 0x00] (4 bytes)
    /// Output: Resposta de confirmação (8 bytes)
    ///
    /// Parâmetro Waveform:
    /// 0x00 = Sine (onda sinusoidal)
    /// 0x01 = Square (onda quadrada)
    /// 0x02 = Triangle (onda triangular)
    /// 0x03 = Sawtooth (onda dente de serra)
    /// (Valores hipotéticos - validar com hardware real)
    /// </summary>
    public const byte SET_WAVEFORM_OPCODE = 0x44;

    /// <summary>
    /// OpCode 0x45: Configura duração da emissão (hipotético)
    /// Input: [OpCode, DurationSec, 0x00, 0x00] (4 bytes)
    /// Output: Resposta de confirmação (8 bytes)
    /// Range: 0-255 segundos
    ///
    /// Nota: Ainda não confirmado em testes hardware
    /// </summary>
    public const byte SET_DURATION_OPCODE = 0x45;

    /// <summary>
    /// OpCode 0x03: Query status do dispositivo
    /// Input: [OpCode, 0x00, 0x00, 0x00] (4 bytes)
    /// Output: Status bits indicando: emitindo, erro, pronto, etc
    ///
    /// Resposta esperada (8 bytes, tipicamente):
    /// Byte 0: Status flags
    ///   Bit 0: Emitting (1 se emitindo, 0 se parado)
    ///   Bit 1: Error (1 se erro, 0 se OK)
    ///   Bit 2: Ready (1 se pronto para emitir)
    ///   Bits 3-7: Reservado
    /// Bytes 1-7: Dados adicionais do status
    /// </summary>
    public const byte GET_STATUS_OPCODE = 0x03;

    /// <summary>
    /// OpCode 0x04: Query versão firmware (hipotético)
    /// Input: [OpCode, 0x00, 0x00, 0x00] (4 bytes)
    /// Output: Versão firmware [MajorVersion, MinorVersion, Patch, Reserved...]
    /// </summary>
    public const byte GET_VERSION_OPCODE = 0x04;

    /// <summary>
    /// OpCode 0x05: Query código de erro (hipotético)
    /// Input: [OpCode, 0x00, 0x00, 0x00] (4 bytes)
    /// Output: [ErrorCode, 0x00, 0x00, ...] (8 bytes)
    ///
    /// Códigos de erro comuns:
    /// 0x00: Sem erro
    /// 0x01: Erro de comunicação USB
    /// 0x02: Parâmetros inválidos
    /// 0x03: Dispositivo não inicializado
    /// 0x04: Emissão já em progresso
    /// </summary>
    public const byte GET_ERROR_OPCODE = 0x05;

    #endregion

    #region Frequency Presets

    /// <summary>
    /// Cria comando para configurar frequência.
    ///
    /// Válido para qualquer frequência 1Hz - 1MHz.
    /// Frequências comuns em terapias:
    /// - 10 Hz: Alpha (ritmo cerebral)
    /// - 40 Hz: Gamma (processamento cognitivo)
    /// - 100 Hz: Estimulação comum
    /// - 432 Hz: Frequência "Schumann"
    /// - 528 Hz: "Frequência de amor" (esotérico)
    /// - 1000 Hz+: Frequências de ultrassom (se suportado)
    /// </summary>
    public static byte[] SetFrequency(double frequencyHz)
    {
        if (frequencyHz < 1.0 || frequencyHz > 1000000.0)
            throw new ArgumentException($"Frequência deve estar entre 1Hz e 1MHz. Recebido: {frequencyHz}Hz");

        return new HS3CommandBuilder()
            .OpCode(SET_FREQUENCY_OPCODE)
            .Frequency(frequencyHz)
            .ValidateMaxSize(64)
            .Build();
    }

    #endregion

    #region Amplitude Presets

    /// <summary>
    /// Cria comando para configurar amplitude.
    /// Válido para qualquer amplitude 0% - 100%.
    /// </summary>
    public static byte[] SetAmplitude(double amplitudePercent)
    {
        if (amplitudePercent < 0.0 || amplitudePercent > 100.0)
            throw new ArgumentException($"Amplitude deve estar entre 0% e 100%. Recebido: {amplitudePercent}%");

        return new HS3CommandBuilder()
            .OpCode(SET_AMPLITUDE_OPCODE)
            .Amplitude(amplitudePercent)
            .ValidateMaxSize(64)
            .Build();
    }

    #endregion

    #region Waveform Presets

    /// <summary>
    /// Enum para tipos de onda suportados.
    /// Mapeia para opcodes do firmware HS3.
    /// </summary>
    public enum Waveform : byte
    {
        Sine = 0x00,      // Onda sinusoidal (smooth)
        Square = 0x01,    // Onda quadrada (digital)
        Triangle = 0x02,  // Onda triangular
        Sawtooth = 0x03   // Onda dente de serra
    }

    /// <summary>
    /// Cria comando para configurar forma de onda.
    /// Enum garante que apenas valores válidos são aceitos.
    /// </summary>
    public static byte[] SetWaveform(Waveform waveform)
    {
        return new HS3CommandBuilder()
            .OpCode(SET_WAVEFORM_OPCODE)
            .Waveform((byte)waveform)
            .ValidateMaxSize(64)
            .Build();
    }

    /// <summary>
    /// Alias para SetWaveform(Waveform.Sine)
    /// </summary>
    public static byte[] SetWaveformSine() => SetWaveform(Waveform.Sine);

    /// <summary>
    /// Alias para SetWaveform(Waveform.Square)
    /// </summary>
    public static byte[] SetWaveformSquare() => SetWaveform(Waveform.Square);

    /// <summary>
    /// Alias para SetWaveform(Waveform.Triangle)
    /// </summary>
    public static byte[] SetWaveformTriangle() => SetWaveform(Waveform.Triangle);

    /// <summary>
    /// Alias para SetWaveform(Waveform.Sawtooth)
    /// </summary>
    public static byte[] SetWaveformSawtooth() => SetWaveform(Waveform.Sawtooth);

    #endregion

    #region Emission Control Presets

    /// <summary>
    /// Cria comando para iniciar emissão.
    /// Pré-requisito: Frequência, Amplitude e Waveform devem estar configurados primeiro.
    /// </summary>
    public static byte[] StartEmission()
    {
        return new HS3CommandBuilder()
            .OpCode(START_EMISSION_OPCODE)
            .ValidateMaxSize(64)
            .Build();
    }

    /// <summary>
    /// Cria comando para parar emissão.
    /// Seguro chamar mesmo se não estiver emitindo.
    /// </summary>
    public static byte[] StopEmission()
    {
        return new HS3CommandBuilder()
            .OpCode(STOP_EMISSION_OPCODE)
            .ValidateMaxSize(64)
            .Build();
    }

    #endregion

    #region Duration Presets

    /// <summary>
    /// Cria comando para configurar duração da emissão (em segundos).
    /// Válido para 0-255 segundos.
    /// 0 = Emissão contínua (sem limite de tempo)
    /// </summary>
    public static byte[] SetDuration(int durationSeconds)
    {
        if (durationSeconds < 0 || durationSeconds > 255)
            throw new ArgumentException($"Duração deve estar entre 0 e 255 segundos. Recebido: {durationSeconds}s");

        return new HS3CommandBuilder()
            .OpCode(SET_DURATION_OPCODE)
            .Duration(durationSeconds)
            .ValidateMaxSize(64)
            .Build();
    }

    #endregion

    #region Diagnostics Presets

    /// <summary>
    /// Cria comando para query status do dispositivo.
    /// Retorna: flags de status (emitindo, erro, pronto, etc)
    /// </summary>
    public static byte[] GetStatus()
    {
        return new HS3CommandBuilder()
            .OpCode(GET_STATUS_OPCODE)
            .ValidateMaxSize(64)
            .Build();
    }

    /// <summary>
    /// Cria comando para query versão firmware.
    /// Retorna: [MajorVersion, MinorVersion, Patch, Reserved...]
    /// </summary>
    public static byte[] GetVersion()
    {
        return new HS3CommandBuilder()
            .OpCode(GET_VERSION_OPCODE)
            .ValidateMaxSize(64)
            .Build();
    }

    /// <summary>
    /// Cria comando para query código de erro.
    /// Retorna: código de erro (0x00 = sem erro)
    /// </summary>
    public static byte[] GetError()
    {
        return new HS3CommandBuilder()
            .OpCode(GET_ERROR_OPCODE)
            .ValidateMaxSize(64)
            .Build();
    }

    #endregion

    #region Composite Commands (Sequências Comuns)

    /// <summary>
    /// Sequência completa para emitir uma frequência:
    /// 1. Configurar frequência
    /// 2. Configurar amplitude
    /// 3. Configurar forma de onda
    /// 4. Iniciar emissão
    ///
    /// Retorna array com 4 comandos que devem ser enviados em sequência.
    /// </summary>
    public static byte[][] EmitFrequencySequence(double frequencyHz, double amplitudePercent, Waveform waveform = Waveform.Sine)
    {
        return new[]
        {
            SetFrequency(frequencyHz),
            SetAmplitude(amplitudePercent),
            SetWaveform(waveform),
            StartEmission()
        };
    }

    /// <summary>
    /// Sequência para emitir com duração limitada:
    /// 1. Configurar duração
    /// 2. Configurar frequência
    /// 3. Configurar amplitude
    /// 4. Configurar forma de onda
    /// 5. Iniciar emissão
    /// </summary>
    public static byte[][] EmitFrequencyWithDurationSequence(
        double frequencyHz,
        double amplitudePercent,
        int durationSeconds,
        Waveform waveform = Waveform.Sine)
    {
        return new[]
        {
            SetDuration(durationSeconds),
            SetFrequency(frequencyHz),
            SetAmplitude(amplitudePercent),
            SetWaveform(waveform),
            StartEmission()
        };
    }

    #endregion
}
