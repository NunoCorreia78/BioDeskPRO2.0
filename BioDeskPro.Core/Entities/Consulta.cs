using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class Consulta : BaseEntity
{
    [Required]
    [ForeignKey(nameof(Encontro))]
    public int EncontroId { get; set; }
    
    public DateTime DataConsulta { get; set; } = DateTime.Now;
    
    [MaxLength(50)]
    public string? TipoConsulta { get; set; }
    
    [MaxLength(1000)]
    public string? QueixaPrincipal { get; set; }
    
    [MaxLength(2000)]
    public string? HistoriaDoencaAtual { get; set; }
    
    [MaxLength(1000)]
    public string? AntecedentesPessoais { get; set; }
    
    [MaxLength(1000)]
    public string? AntecedentesFamiliares { get; set; }
    
    [MaxLength(500)]
    public string? MedicacaoAtual { get; set; }
    
    [MaxLength(500)]
    public string? Alergias { get; set; }
    
    [MaxLength(1000)]
    public string? ExameObjetivo { get; set; }
    
    [MaxLength(1000)]
    public string? DiagnosticoDiferencial { get; set; }
    
    [MaxLength(1000)]
    public string? PlanoTerapeutico { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    // Navigation properties
    public virtual Encontro Encontro { get; set; } = null!;
}