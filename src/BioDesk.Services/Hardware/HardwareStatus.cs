namespace BioDesk.Services.Hardware;

/// <summary>
/// Status do hardware TiePie
/// </summary>
public class HardwareStatus
{
    /// <summary>
    /// Hardware está conectado
    /// </summary>
    public bool IsConnected { get; set; }

    /// <summary>
    /// Nome do dispositivo (ex: "TiePie Handyscope HS5")
    /// </summary>
    public string DeviceName { get; set; } = string.Empty;

    /// <summary>
    /// Número de série
    /// </summary>
    public string SerialNumber { get; set; } = string.Empty;

    /// <summary>
    /// Número de canais disponíveis
    /// </summary>
    public int ChannelCount { get; set; }

    /// <summary>
    /// Frequência máxima suportada (Hz)
    /// </summary>
    public double MaxFrequencyHz { get; set; }

    /// <summary>
    /// Voltagem máxima suportada (V)
    /// </summary>
    public double MaxVoltageV { get; set; }

    /// <summary>
    /// Mensagem de erro (se houver)
    /// </summary>
    public string? ErrorMessage { get; set; }

    public override string ToString()
    {
        if (!IsConnected)
            return $"❌ Desconectado{(string.IsNullOrEmpty(ErrorMessage) ? "" : $": {ErrorMessage}")}";

        return $"✅ {DeviceName} (S/N: {SerialNumber}) - {ChannelCount} canais, Max: {MaxFrequencyHz / 1_000_000:F2} MHz";
    }
}
