using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class IrisReport : BaseEntity
{
    [Required]
    [ForeignKey(nameof(IrisImage))]
    public int IrisImageId { get; set; }
    
    [Required]
    [MaxLength(200)]
    public string Titulo { get; set; } = string.Empty;
    
    [Required]
    public string ConteudoRelatorio { get; set; } = string.Empty;
    
    [MaxLength(50)]
    public string? TipoRelatorio { get; set; }
    
    public DateTime DataGeracao { get; set; } = DateTime.Now;
    
    [MaxLength(100)]
    public string? GeradoPor { get; set; }
    
    public bool Finalizado { get; set; } = false;
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    // Navigation properties
    public virtual IrisImage IrisImage { get; set; } = null!;
}