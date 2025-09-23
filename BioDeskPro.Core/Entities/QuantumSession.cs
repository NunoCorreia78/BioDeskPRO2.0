using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class QuantumSession : BaseEntity
{
    [Required]
    [ForeignKey(nameof(Encontro))]
    public int EncontroId { get; set; }
    
    [Required]
    [ForeignKey(nameof(QuantumProtocol))]
    public int QuantumProtocolId { get; set; }
    
    public DateTime DataInicio { get; set; } = DateTime.Now;
    
    public DateTime? DataFim { get; set; }
    
    public int? DuracaoMinutos { get; set; }
    
    [MaxLength(50)]
    public string? StatusSessao { get; set; } // Agendada, EmAndamento, Concluida, Cancelada
    
    [MaxLength(1000)]
    public string? ParametrosUtilizados { get; set; } // JSON
    
    [MaxLength(1000)]
    public string? ResultadosObtidos { get; set; }
    
    [MaxLength(1000)]
    public string? ReacoesPaciente { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    [MaxLength(100)]
    public string? Profissional { get; set; }
    
    public decimal? Intensidade { get; set; }
    
    public int? FrequenciaHz { get; set; }
    
    // Navigation properties
    public virtual Encontro Encontro { get; set; } = null!;
    public virtual QuantumProtocol QuantumProtocol { get; set; } = null!;
}