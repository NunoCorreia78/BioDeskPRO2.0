using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class KnowledgeLink : BaseEntity
{
    [Required]
    [ForeignKey(nameof(KnowledgeEntry))]
    public int KnowledgeEntryId { get; set; }
    
    [Required]
    [MaxLength(500)]
    public string Url { get; set; } = string.Empty;
    
    [MaxLength(200)]
    public string? TituloLink { get; set; }
    
    [MaxLength(500)]
    public string? Descricao { get; set; }
    
    [MaxLength(50)]
    public string? TipoLink { get; set; } // Interno, Externo, Referencia, etc.
    
    public int? Ordem { get; set; }
    
    public bool Ativo { get; set; } = true;
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    // Navigation properties
    public virtual KnowledgeEntry KnowledgeEntry { get; set; } = null!;
}