using System.ComponentModel.DataAnnotations;

namespace BioDeskPro.Core.Entities;

public class KnowledgeEntry : BaseEntity
{
    [Required]
    [MaxLength(300)]
    public string Titulo { get; set; } = string.Empty;
    
    [MaxLength(300)]
    public string? TituloNormalizado { get; set; }
    
    [Required]
    public string Conteudo { get; set; } = string.Empty;
    
    [MaxLength(50)]
    public string? Categoria { get; set; }
    
    [MaxLength(50)]
    public string? TipoConteudo { get; set; } // Artigo, Video, PDF, etc.
    
    [MaxLength(500)]
    public string? Tags { get; set; }
    
    [MaxLength(200)]
    public string? Autor { get; set; }
    
    [MaxLength(500)]
    public string? FonteOriginal { get; set; }
    
    public DateTime? DataPublicacao { get; set; }
    
    [MaxLength(1000)]
    public string? Resumo { get; set; }
    
    public int? NivelImportancia { get; set; } // 1-5
    
    public int Visualizacoes { get; set; } = 0;
    
    public bool Publico { get; set; } = true;
    
    public bool Ativo { get; set; } = true;
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    // Navigation properties
    public virtual ICollection<KnowledgeLink> Links { get; set; } = new List<KnowledgeLink>();
}