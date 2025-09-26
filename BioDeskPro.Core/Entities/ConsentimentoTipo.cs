using System.ComponentModel.DataAnnotations;

namespace BioDeskPro.Core.Entities;

public class ConsentimentoTipo : BaseEntity
{
    [Required]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;
    
    [MaxLength(200)]
    public string? NomeNormalizado { get; set; }
    
    [Required]
    public string ConteudoTemplate { get; set; } = string.Empty;
    
    [MaxLength(1000)]
    public string? Descricao { get; set; }
    
    [MaxLength(50)]
    public string? Categoria { get; set; }
    
    public bool Obrigatorio { get; set; } = false;
    
    public bool Ativo { get; set; } = true;
    
    [MaxLength(20)]
    public string? Versao { get; set; }
    
    // Navigation properties
    public virtual ICollection<ConsentimentoPaciente> ConsentimentosPaciente { get; set; } = new List<ConsentimentoPaciente>();
}