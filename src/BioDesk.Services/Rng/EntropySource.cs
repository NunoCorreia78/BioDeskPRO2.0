namespace BioDesk.Services.Rng;

/// <summary>
/// Fonte de entropia para geração de números aleatórios verdadeiros
/// </summary>
public enum EntropySource
{
    /// <summary>
    /// Pseudo-aleatório (System.Random) - Apenas para testes
    /// </summary>
    PseudoRandom = 0,

    /// <summary>
    /// Hardware entropy (RNGCryptoServiceProvider) - Baseado em ruído térmico
    /// </summary>
    HardwareCrypto = 1,

    /// <summary>
    /// Atmospheric noise via Random.org API - Entropia verdadeira de fenómenos atmosféricos
    /// </summary>
    AtmosphericNoise = 2,

    /// <summary>
    /// Quantum random (futuro) - Eventos quânticos
    /// </summary>
    Quantum = 3
}
