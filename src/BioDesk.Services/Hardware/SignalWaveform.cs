namespace BioDesk.Services.Hardware;

/// <summary>
/// Forma de onda do sinal gerado
/// </summary>
public enum SignalWaveform
{
    /// <summary>
    /// Onda senoidal (padrão terapias bioenergéticas)
    /// </summary>
    Sine = 0,

    /// <summary>
    /// Onda quadrada
    /// </summary>
    Square = 1,

    /// <summary>
    /// Onda triangular
    /// </summary>
    Triangle = 2,

    /// <summary>
    /// Onda dente de serra
    /// </summary>
    Sawtooth = 3
}
