using System.Threading.Tasks;

namespace BioDesk.Services.Hardware;

/// <summary>
/// Interface para comunicação com TiePie Handyscope HS5
/// </summary>
public interface ITiePieHardwareService
{
    /// <summary>
    /// Verifica se o hardware está conectado e operacional
    /// </summary>
    Task<HardwareStatus> GetStatusAsync();

    /// <summary>
    /// Envia sinal para o gerador
    /// </summary>
    /// <param name="config">Configuração do sinal</param>
    /// <returns>True se enviado com sucesso</returns>
    Task<bool> SendSignalAsync(SignalConfiguration config);

    /// <summary>
    /// Para a geração de sinal em todos os canais
    /// </summary>
    Task StopAllChannelsAsync();

    /// <summary>
    /// Envia múltiplas frequências sequencialmente
    /// </summary>
    /// <param name="frequencies">Array de frequências em Hz</param>
    /// <param name="channel">Canal de saída</param>
    /// <param name="voltageV">Voltagem</param>
    /// <param name="waveform">Forma de onda</param>
    /// <param name="durationPerFreqSeconds">Duração por frequência</param>
    Task<bool> SendMultipleFrequenciesAsync(
        double[] frequencies, 
        SignalChannel channel = SignalChannel.Channel1,
        double voltageV = 1.0,
        SignalWaveform waveform = SignalWaveform.Sine,
        double durationPerFreqSeconds = 60.0);

    /// <summary>
    /// Testa o hardware enviando sinal de teste (1 kHz, 1V, Sine, 2s)
    /// </summary>
    Task<bool> TestHardwareAsync();
}
