namespace BioDesk.Services.Hardware;

/// <summary>
/// Configuração de sinal para geração
/// </summary>
public class SignalConfiguration
{
    /// <summary>
    /// Canal de saída (1 ou 2)
    /// </summary>
    public SignalChannel Channel { get; set; } = SignalChannel.Channel1;

    /// <summary>
    /// Frequência em Hz (0.1 Hz a 5 MHz)
    /// </summary>
    public double FrequencyHz { get; set; }

    /// <summary>
    /// Voltagem pico-a-pico em Volts (±0.2V a ±8V)
    /// </summary>
    public double VoltageV { get; set; } = 1.0;

    /// <summary>
    /// Forma de onda
    /// </summary>
    public SignalWaveform Waveform { get; set; } = SignalWaveform.Sine;

    /// <summary>
    /// Duração do sinal em segundos (padrão: 60s)
    /// </summary>
    public double DurationSeconds { get; set; } = 60.0;

    /// <summary>
    /// Validar configuração
    /// </summary>
    public bool IsValid()
    {
        return FrequencyHz >= 0.1 
            && FrequencyHz <= 5_000_000 
            && VoltageV >= 0.2 
            && VoltageV <= 8.0
            && DurationSeconds > 0;
    }

    public override string ToString()
    {
        return $"Ch{(int)Channel}: {FrequencyHz:F2} Hz, {VoltageV:F2}V, {Waveform}, {DurationSeconds:F1}s";
    }
}
