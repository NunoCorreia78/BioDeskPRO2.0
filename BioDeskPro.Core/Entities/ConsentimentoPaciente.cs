using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class ConsentimentoPaciente : BaseEntity
{
    [Required]
    [ForeignKey(nameof(Paciente))]
    public int PacienteId { get; set; }
    
    [Required]
    [ForeignKey(nameof(ConsentimentoTipo))]
    public int ConsentimentoTipoId { get; set; }
    
    public DateTime DataConsentimento { get; set; } = DateTime.Now;
    
    public bool Aceito { get; set; } = false;
    
    [MaxLength(200)]
    public string? AssinaturaDigital { get; set; }
    
    [MaxLength(100)]
    public string? EnderecoIP { get; set; }
    
    [MaxLength(200)]
    public string? UserAgent { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public DateTime? DataRevogacao { get; set; }
    
    [MaxLength(500)]
    public string? MotivoRevogacao { get; set; }
    
    // Navigation properties
    public virtual Paciente Paciente { get; set; } = null!;
    public virtual ConsentimentoTipo ConsentimentoTipo { get; set; } = null!;
}