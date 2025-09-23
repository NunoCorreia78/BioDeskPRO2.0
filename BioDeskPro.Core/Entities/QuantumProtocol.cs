using System.ComponentModel.DataAnnotations;

namespace BioDeskPro.Core.Entities;

public class QuantumProtocol : BaseEntity
{
    [Required]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;
    
    [MaxLength(200)]
    public string? NomeNormalizado { get; set; }
    
    [MaxLength(1000)]
    public string? Descricao { get; set; }
    
    [MaxLength(50)]
    public string? Categoria { get; set; }
    
    [MaxLength(50)]
    public string? TipoProtocolo { get; set; }
    
    public int? DuracaoMinutos { get; set; }
    
    [MaxLength(500)]
    public string? Parametros { get; set; } // JSON com parâmetros específicos
    
    [MaxLength(1000)]
    public string? Indicacoes { get; set; }
    
    [MaxLength(1000)]
    public string? Contraindicacoes { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public bool Ativo { get; set; } = true;
    
    // Navigation properties
    public virtual ICollection<QuantumSession> Sessions { get; set; } = new List<QuantumSession>();
}