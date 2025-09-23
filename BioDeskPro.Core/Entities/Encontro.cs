using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class Encontro : BaseEntity
{
    [Required]
    [ForeignKey(nameof(Paciente))]
    public int PacienteId { get; set; }
    
    public DateTime DataEncontro { get; set; } = DateTime.Now;
    
    [MaxLength(50)]
    public string? TipoEncontro { get; set; } // Consulta, Exame, etc.
    
    [MaxLength(100)]
    public string? Profissional { get; set; }
    
    [MaxLength(1000)]
    public string? MotivoPrincipal { get; set; }
    
    [MaxLength(2000)]
    public string? HistoriaClinica { get; set; }
    
    [MaxLength(1000)]
    public string? ExameFisico { get; set; }
    
    [MaxLength(1000)]
    public string? Diagnostico { get; set; }
    
    [MaxLength(1000)]
    public string? PlanoTratamento { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public bool Concluido { get; set; } = false;
    
    // Navigation properties
    public virtual Paciente Paciente { get; set; } = null!;
    public virtual ICollection<Consulta> Consultas { get; set; } = new List<Consulta>();
    public virtual ICollection<IrisImage> IrisImages { get; set; } = new List<IrisImage>();
    public virtual ICollection<QuantumSession> QuantumSessions { get; set; } = new List<QuantumSession>();
}