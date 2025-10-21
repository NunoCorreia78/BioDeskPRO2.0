namespace BioDesk.Domain.Enums;

/// <summary>
/// Tipo de terapia bioenergética (cada tipo pode ter configurações diferentes).
/// </summary>
public enum TipoTerapia
{
    /// <summary>
    /// Programas terapêuticos pré-definidos (ex: Detox, Candida, Parasitas).
    /// </summary>
    Programas = 0,

    /// <summary>
    /// Frequências ressonantes específicas (ex: vírus, bactérias, fungos).
    /// </summary>
    Ressonantes = 1,

    /// <summary>
    /// Biofeedback em tempo real com ajuste automático de frequências.
    /// </summary>
    Biofeedback = 2
}
