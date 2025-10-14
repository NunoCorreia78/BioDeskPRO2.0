namespace BioDesk.Domain.Entities;

/// <summary>
/// Categorias do sistema Core Informacional
/// Baseado no modelo Inergetix CoRe 5.0
/// </summary>
public enum CategoriaCore
{
    /// <summary>
    /// Frequências Rife/Clark (5.869 itens já existentes em ProtocoloTerapeutico)
    /// </summary>
    Frequencia = 1,

    /// <summary>
    /// Homeopatia (~3.000 itens)
    /// Remédios homeopáticos clássicos com potências diversas
    /// </summary>
    Homeopatia = 2,

    /// <summary>
    /// Florais de Bach (38 itens - sistema completo original)
    /// Dr. Edward Bach - 38 Essências Florais
    /// </summary>
    FloraisBach = 3,

    /// <summary>
    /// Florais Californianos (103 itens - sistema FES completo)
    /// Flower Essence Society
    /// </summary>
    FloraisCalifornianos = 4,

    /// <summary>
    /// Emoções (~500 itens)
    /// Categorização de estados emocionais
    /// </summary>
    Emocao = 5,

    /// <summary>
    /// Órgãos e sistemas corporais (~150 itens)
    /// ATENÇÃO: Género específico para órgãos reprodutores
    /// </summary>
    Orgao = 6,

    /// <summary>
    /// Chakras (28 itens - 7 principais + 21 secundários)
    /// Sistema energético védico
    /// </summary>
    Chakra = 7,

    /// <summary>
    /// Meridianos (20 itens - 12 principais + 8 extraordinários)
    /// Medicina Tradicional Chinesa
    /// </summary>
    Meridiano = 8,

    /// <summary>
    /// Patógenos e micro-organismos
    /// (Reservado para futura implementação)
    /// </summary>
    Patogeno = 9,

    /// <summary>
    /// Vitaminas (~50 itens)
    /// Lipossolúveis, hidrossolúveis e suas formas ativas
    /// </summary>
    Vitamina = 10,

    /// <summary>
    /// Minerais (~80 itens)
    /// Macrominerais, microminerais e oligoelementos
    /// </summary>
    Mineral = 11,

    /// <summary>
    /// Afirmações positivas e reprogramação mental
    /// (Reservado para futura implementação)
    /// </summary>
    Afirmacao = 12,

    /// <summary>
    /// Suplementos nutricionais (~300 itens)
    /// Probióticos, ácidos gordos, aminoácidos, enzimas, antioxidantes, adaptógenos
    /// </summary>
    Suplemento = 13,

    /// <summary>
    /// Alimentos terapêuticos (~1.000 itens)
    /// Frutas, vegetais, ervas, especiarias, superalimentos
    /// </summary>
    Alimento = 14
}
