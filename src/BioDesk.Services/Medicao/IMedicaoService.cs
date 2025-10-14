using System;
using System.Threading.Tasks;

namespace BioDesk.Services.Medicao;

/// <summary>
/// Serviço de medição bioenergética via TiePie Oscilloscope (INPUT)
/// Captura leituras biofeedback durante aplicação de terapias
/// Baseado em CoRe 5.0 biofeedback system
/// </summary>
public interface IMedicaoService
{
    /// <summary>
    /// Captura uma leitura baseline (pré-terapia) para estabelecer referência
    /// </summary>
    /// <param name="duracaoSegundos">Duração da captura em segundos (padrão: 5s)</param>
    /// <returns>LeituraBiofeedback com RMS, pico e frequência dominante</returns>
    Task<LeituraBiofeedback> CapturarBaselineAsync(int duracaoSegundos = 5);

    /// <summary>
    /// Captura leitura durante aplicação de terapia (monitorização contínua)
    /// </summary>
    /// <returns>LeituraBiofeedback instantânea</returns>
    Task<LeituraBiofeedback> CapturarLeituraAsync();

    /// <summary>
    /// Calcula Improvement % comparando leitura atual com baseline
    /// Fórmula CoRe: (current - baseline) / baseline * 100
    /// </summary>
    /// <param name="baseline">Leitura de referência (pré-terapia)</param>
    /// <param name="current">Leitura atual</param>
    /// <returns>Percentagem de melhoria (-100% a +∞)</returns>
    double CalcularImprovementPercent(LeituraBiofeedback baseline, LeituraBiofeedback current);

    /// <summary>
    /// Inicia captura contínua de leituras (para gráficos em tempo real)
    /// </summary>
    /// <param name="intervalMs">Intervalo entre leituras em ms (padrão: 1000ms = 1s)</param>
    Task IniciarCapturaContinuaAsync(int intervalMs = 1000);

    /// <summary>
    /// Para captura contínua
    /// </summary>
    Task PararCapturaContinuaAsync();

    /// <summary>
    /// Testa disponibilidade do hardware TiePie para INPUT (oscilloscope)
    /// </summary>
    /// <returns>True se hardware disponível e funcional</returns>
    Task<bool> TestarHardwareAsync();
}

/// <summary>
/// DTO para leitura biofeedback capturada via TiePie oscilloscope
/// </summary>
public class LeituraBiofeedback
{
    /// <summary>
    /// RMS (Root Mean Square) - valor eficaz do sinal em mV
    /// Representa energia/amplitude média do sinal biológico
    /// </summary>
    public double Rms { get; set; }

    /// <summary>
    /// Pico máximo do sinal em mV
    /// </summary>
    public double Pico { get; set; }

    /// <summary>
    /// Frequência dominante calculada via FFT em Hz
    /// Ex: 10.5 Hz (Alpha brainwave), 40 Hz (Gamma), etc.
    /// </summary>
    public double FrequenciaDominante { get; set; }

    /// <summary>
    /// Potência espectral na frequência dominante (dB)
    /// Intensidade da componente de frequência principal
    /// </summary>
    public double PotenciaEspectral { get; set; }

    /// <summary>
    /// Timestamp da captura
    /// </summary>
    public DateTime Timestamp { get; set; }

    /// <summary>
    /// Dados brutos do buffer (opcional - para análise avançada)
    /// Array de amostras em mV
    /// </summary>
    public double[]? DadosBrutos { get; set; }

    public LeituraBiofeedback()
    {
        Timestamp = DateTime.Now;
    }

    /// <summary>
    /// Retorna representação legível da leitura
    /// </summary>
    public override string ToString()
    {
        return $"RMS: {Rms:F2}mV | Pico: {Pico:F2}mV | Freq: {FrequenciaDominante:F1}Hz | Pot: {PotenciaEspectral:F1}dB";
    }
}
