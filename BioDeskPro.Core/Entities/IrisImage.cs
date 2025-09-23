using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class IrisImage : BaseEntity
{
    [Required]
    [ForeignKey(nameof(Encontro))]
    public int EncontroId { get; set; }
    
    [Required]
    [MaxLength(10)]
    public string Olho { get; set; } = string.Empty; // "Direito" ou "Esquerdo"
    
    [Required]
    [MaxLength(500)]
    public string CaminhoArquivo { get; set; } = string.Empty;
    
    [MaxLength(100)]
    public string? NomeArquivo { get; set; }
    
    public long TamanhoArquivo { get; set; }
    
    [MaxLength(50)]
    public string? TipoMime { get; set; }
    
    public int? Largura { get; set; }
    
    public int? Altura { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public DateTime DataCaptura { get; set; } = DateTime.Now;
    
    // Navigation properties
    public virtual Encontro Encontro { get; set; } = null!;
    public virtual ICollection<IrisFinding> Findings { get; set; } = new List<IrisFinding>();
    public virtual ICollection<IrisReport> Reports { get; set; } = new List<IrisReport>();
}