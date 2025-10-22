namespace BioDesk.Domain.Enums;

/// <summary>
/// Forma de onda do sinal elétrico para emissão de frequências terapêuticas.
/// </summary>
public enum FormaOnda
{
    /// <summary>
    /// Onda sinusoidal suave (padrão) - Ideal para terapias prolongadas e ressonâncias.
    /// </summary>
    Seno = 0,

    /// <summary>
    /// Onda quadrada com transições abruptas - Máxima penetração, ideal para parasitas e bactérias.
    /// </summary>
    Quadrada = 1,

    /// <summary>
    /// Onda triangular com rampa linear - Equilíbrio entre suavidade e eficácia.
    /// </summary>
    Triangular = 2,

    /// <summary>
    /// Pulsos curtos de alta intensidade - Ideal para casos agudos e estímulo intenso.
    /// </summary>
    Pulso = 3
}
