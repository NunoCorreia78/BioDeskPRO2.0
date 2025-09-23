using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class IrisFinding : BaseEntity
{
    [Required]
    [ForeignKey(nameof(IrisImage))]
    public int IrisImageId { get; set; }
    
    [Required]
    [MaxLength(100)]
    public string TipoAchado { get; set; } = string.Empty;
    
    [MaxLength(200)]
    public string? Descricao { get; set; }
    
    [MaxLength(100)]
    public string? Localizacao { get; set; }
    
    [MaxLength(50)]
    public string? Severidade { get; set; }
    
    // Coordenadas da região na imagem
    public int? PosicaoX { get; set; }
    public int? PosicaoY { get; set; }
    public int? Largura { get; set; }
    public int? Altura { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public bool Validado { get; set; } = false;
    
    // Navigation properties
    public virtual IrisImage IrisImage { get; set; } = null!;
}