namespace BioDesk.Domain.Enums;

/// <summary>
/// Categorias do sistema Core Informacional inspirado no Inergetix CoRe 5.0
/// Cada categoria representa um domínio terapêutico com itens específicos
/// </summary>
public enum CategoriaCore
{
    /// <summary>
    /// Frequências terapêuticas (5.869 itens já importados)
    /// </summary>
    Frequencia = 1,

    /// <summary>
    /// Remédios homeopáticos (Materia Medica, Kent's Repertory)
    /// ~3.000 itens planejados
    /// </summary>
    Homeopatia = 2,

    /// <summary>
    /// Sistema Florais de Bach original (Dr. Edward Bach)
    /// 38 essências + Rescue Remedy = 39 itens
    /// </summary>
    FloraisBach = 3,

    /// <summary>
    /// Florais Californianos (Flower Essence Society - FES)
    /// 103 essências completas
    /// </summary>
    FloraisCalifornianos = 4,

    /// <summary>
    /// Emoções catalogadas (Medo, Raiva, Tristeza, Alegria, etc.)
    /// ~500 itens com relações MTC e Chakras
    /// </summary>
    Emocao = 5,

    /// <summary>
    /// Órgãos e sistemas anatómicos
    /// ~150 itens com validação de género obrigatória
    /// </summary>
    Orgao = 6,

    /// <summary>
    /// Chakras védicos (7 principais + 21 secundários)
    /// 28 itens completos
    /// </summary>
    Chakra = 7,

    /// <summary>
    /// Meridianos da Medicina Tradicional Chinesa
    /// 12 principais + 8 extraordinários = 20 itens
    /// </summary>
    Meridiano = 8,

    /// <summary>
    /// Vitaminas (A, complexo B, C, D, E, K)
    /// ~50 itens com formas ativas e inativas
    /// </summary>
    Vitamina = 10,

    /// <summary>
    /// Minerais (macro, micro e oligoelementos)
    /// ~80 itens
    /// </summary>
    Mineral = 11,

    /// <summary>
    /// Suplementos nutricionais (probióticos, enzimas, adaptógenos)
    /// ~300 itens
    /// </summary>
    Suplemento = 13,

    /// <summary>
    /// Alimentos terapêuticos (frutas, vegetais, ervas, superalimentos)
    /// ~1.000 itens
    /// </summary>
    Alimento = 14
}
