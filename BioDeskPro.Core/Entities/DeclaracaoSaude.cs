using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class DeclaracaoSaude : BaseEntity
{
    [Required]
    [ForeignKey(nameof(Paciente))]
    public int PacienteId { get; set; }
    
    public DateTime DataDeclaracao { get; set; } = DateTime.Now;
    
    [MaxLength(50)]
    public string? TipoDeclaracao { get; set; }
    
    [Required]
    public string ConteudoDeclaracao { get; set; } = string.Empty;
    
    [MaxLength(1000)]
    public string? CondicoesPreexistentes { get; set; }
    
    [MaxLength(500)]
    public string? MedicacaoAtual { get; set; }
    
    [MaxLength(500)]
    public string? Alergias { get; set; }
    
    [MaxLength(500)]
    public string? CirurgiasAnteriores { get; set; }
    
    [MaxLength(500)]
    public string? HistoriaFamiliar { get; set; }
    
    [MaxLength(500)]
    public string? EstiloVida { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public bool Validada { get; set; } = false;
    
    [MaxLength(100)]
    public string? ValidadaPor { get; set; }
    
    public DateTime? DataValidacao { get; set; }
    
    // Navigation properties
    public virtual Paciente Paciente { get; set; } = null!;
}