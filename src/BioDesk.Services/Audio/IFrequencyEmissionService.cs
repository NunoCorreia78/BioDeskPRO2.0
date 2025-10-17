using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace BioDesk.Services.Audio;

/// <summary>
/// Dispositivo de áudio disponível para emissão de frequências.
/// </summary>
public record AudioDevice(string Id, string Name, bool IsDefault);

/// <summary>
/// Forma de onda para geração de sinal.
/// </summary>
public enum WaveForm
{
    Sine,       // Onda senoidal (mais suave, padrão para terapias)
    Square,     // Onda quadrada (mais incisiva)
    Triangle,   // Onda triangular (híbrido)
    Sawtooth    // Onda dente de serra
}

/// <summary>
/// Resultado de emissão de frequência.
/// </summary>
public record EmissionResult(
    bool Success,
    string Message,
    double ActualFrequency,
    TimeSpan Duration
);

/// <summary>
/// Serviço de emissão de frequências via áudio (TiePie HS3 ou dispositivo padrão).
///
/// ARQUITETURA DESCOBERTA:
/// - CoRe System usa TiePie Handyscope HS3 como interface USB de áudio
/// - HS3 funciona como placa de som dedicada (44100 Hz, 16-bit, Mono)
/// - Método: Geração de tons → WASAPI → HS3 → Emissão física
///
/// PARÂMETROS TÉCNICOS:
/// - Sample Rate: 44100 Hz (CD quality)
/// - Channels: 1 (Mono)
/// - Bit Depth: 16-bit
/// - Volume Padrão: 70% (~7V no HS3, testado)
/// - Duração Padrão: 5 segundos/frequência
/// </summary>
public interface IFrequencyEmissionService : IDisposable
{
    /// <summary>
    /// Obtém lista de dispositivos de áudio disponíveis (output).
    /// Prioriza TiePie Handyscope HS3 se detectado.
    /// </summary>
    Task<List<AudioDevice>> GetAvailableDevicesAsync();

    /// <summary>
    /// Seleciona dispositivo de áudio para emissão.
    /// </summary>
    /// <param name="deviceId">ID do dispositivo (null = dispositivo padrão)</param>
    Task<bool> SelectDeviceAsync(string? deviceId = null);

    /// <summary>
    /// Obtém dispositivo atualmente selecionado.
    /// </summary>
    AudioDevice? CurrentDevice { get; }

    /// <summary>
    /// Emite frequência única com parâmetros especificados.
    /// </summary>
    /// <param name="frequencyHz">Frequência em Hertz (10 - 20000 Hz)</param>
    /// <param name="durationSeconds">Duração em segundos</param>
    /// <param name="volumePercent">Volume (0-100%)</param>
    /// <param name="waveForm">Forma de onda</param>
    /// <param name="cancellationToken">Token de cancelamento</param>
    Task<EmissionResult> EmitFrequencyAsync(
        double frequencyHz,
        int durationSeconds,
        int volumePercent = 70,
        WaveForm waveForm = WaveForm.Sine,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Emite lista de frequências sequencialmente (para programas/ressonantes).
    /// </summary>
    /// <param name="frequencies">Lista de frequências em Hz</param>
    /// <param name="durationPerFrequencySeconds">Tempo por frequência</param>
    /// <param name="volumePercent">Volume (0-100%)</param>
    /// <param name="waveForm">Forma de onda</param>
    /// <param name="progressCallback">Callback para progresso (index, total, frequênciaAtual)</param>
    /// <param name="cancellationToken">Token de cancelamento</param>
    Task<EmissionResult> EmitFrequencyListAsync(
        IEnumerable<double> frequencies,
        int durationPerFrequencySeconds,
        int volumePercent = 70,
        WaveForm waveForm = WaveForm.Sine,
        Action<int, int, double>? progressCallback = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Testa emissão com tom de 440 Hz (Lá musical) por 2 segundos.
    /// </summary>
    Task<EmissionResult> TestEmissionAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Para emissão atual (se houver).
    /// </summary>
    Task StopAsync();

    /// <summary>
    /// Indica se está emitindo frequência no momento.
    /// </summary>
    bool IsEmitting { get; }
}
