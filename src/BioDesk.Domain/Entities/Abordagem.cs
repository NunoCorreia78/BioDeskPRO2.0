namespace BioDesk.Domain.Entities;

/// <summary>
/// Tipos de abordagens terapêuticas disponíveis
/// Uma sessão pode ter múltiplas abordagens
/// </summary>
public enum TipoAbordagem
{
    /// <summary>
    /// Naturopatia (fitoterapia, suplementação, dietas)
    /// </summary>
    Naturopatia = 1,

    /// <summary>
    /// Mesoterapia (injeções localizadas)
    /// </summary>
    Mesoterapia = 2,

    /// <summary>
    /// Osteopatia (manipulações articulares, técnicas manuais)
    /// </summary>
    Osteopatia = 3,

    /// <summary>
    /// Iridologia (diagnóstico pela íris)
    /// </summary>
    Iridologia = 4,

    /// <summary>
    /// Medicina Bioenergética (terapias energéticas)
    /// </summary>
    MedicinaBioenergetica = 5
}

/// <summary>
/// Tabela de relação Many-to-Many entre Sessao e Abordagens
/// Permite que uma sessão tenha múltiplas abordagens terapêuticas
/// </summary>
public class AbordagemSessao
{
    public int Id { get; set; }

    /// <summary>
    /// ID da sessão
    /// </summary>
    public int SessaoId { get; set; }
    public Sessao Sessao { get; set; } = null!;

    /// <summary>
    /// Tipo de abordagem aplicada
    /// </summary>
    public TipoAbordagem TipoAbordagem { get; set; }

    /// <summary>
    /// Observações específicas sobre esta abordagem nesta sessão (opcional)
    /// Exemplo: "Protocolo específico para lombalgia"
    /// </summary>
    public string? Observacoes { get; set; }
}
