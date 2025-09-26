using System.ComponentModel.DataAnnotations;

namespace BioDeskPro.Core.Entities;

public class OutboxEmail : BaseEntity
{
    [Required]
    [MaxLength(200)]
    public string Para { get; set; } = string.Empty;
    
    [MaxLength(200)]
    public string? Cc { get; set; }
    
    [MaxLength(200)]
    public string? Bcc { get; set; }
    
    [Required]
    [MaxLength(300)]
    public string Assunto { get; set; } = string.Empty;
    
    [Required]
    public string CorpoEmail { get; set; } = string.Empty;
    
    [MaxLength(50)]
    public string? TipoEmail { get; set; }
    
    [MaxLength(50)]
    public string Status { get; set; } = "Pendente"; // Pendente, Enviado, Erro
    
    public DateTime DataCriacao { get; set; } = DateTime.Now;
    
    public DateTime? DataEnvio { get; set; }
    
    public int TentativasEnvio { get; set; } = 0;
    
    [MaxLength(1000)]
    public string? MensagemErro { get; set; }
    
    [MaxLength(100)]
    public string? Prioridade { get; set; } = "Normal";
    
    [MaxLength(500)]
    public string? Anexos { get; set; } // JSON com lista de caminhos
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
}