using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class Documento : BaseEntity
{
    [Required]
    [ForeignKey(nameof(Paciente))]
    public int PacienteId { get; set; }
    
    [Required]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;
    
    [MaxLength(50)]
    public string? TipoDocumento { get; set; }
    
    [Required]
    [MaxLength(500)]
    public string CaminhoArquivo { get; set; } = string.Empty;
    
    [MaxLength(100)]
    public string? NomeArquivo { get; set; }
    
    public long TamanhoArquivo { get; set; }
    
    [MaxLength(50)]
    public string? TipoMime { get; set; }
    
    [MaxLength(1000)]
    public string? Descricao { get; set; }
    
    [MaxLength(500)]
    public string? Tags { get; set; }
    
    public DateTime DataDocumento { get; set; } = DateTime.Now;
    
    [MaxLength(100)]
    public string? Autor { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public bool Publico { get; set; } = false;
    
    // Navigation properties
    public virtual Paciente Paciente { get; set; } = null!;
}