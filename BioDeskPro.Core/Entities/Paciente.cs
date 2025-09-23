using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDeskPro.Core.Entities;

public class Paciente : BaseEntity
{
    [Required]
    [MaxLength(100)]
    public string Nome { get; set; } = string.Empty;
    
    [MaxLength(100)]
    public string? NomeNormalizado { get; set; }
    
    [MaxLength(20)]
    public string? NumeroUtente { get; set; }
    
    [MaxLength(20)]
    public string? DocumentoIdentidade { get; set; }
    
    public DateTime? DataNascimento { get; set; }
    
    [MaxLength(10)]
    public string? Sexo { get; set; }
    
    [MaxLength(200)]
    public string? Morada { get; set; }
    
    [MaxLength(20)]
    public string? Telemovel { get; set; }
    
    [MaxLength(100)]
    public string? Email { get; set; }
    
    [MaxLength(100)]
    public string? ComoConheceu { get; set; }
    
    [MaxLength(500)]
    public string? Observacoes { get; set; }
    
    public bool Ativo { get; set; } = true;

    // Propriedades computadas (não mapeadas para BD)
    [NotMapped]
    public string NomeCompleto => Nome;
    
    [NotMapped]
    public int Idade => DataNascimento.HasValue 
        ? CalculateAge(DataNascimento.Value) 
        : 0;

    [NotMapped]
    public string IdadeText => DataNascimento.HasValue 
        ? $"{Idade} anos" 
        : "N/A";

    // Navigation properties
    public virtual ICollection<Encontro> Encontros { get; set; } = new List<Encontro>();
    public virtual ICollection<ConsentimentoPaciente> Consentimentos { get; set; } = new List<ConsentimentoPaciente>();
    public virtual ICollection<DeclaracaoSaude> DeclaracoesSaude { get; set; } = new List<DeclaracaoSaude>();
    public virtual ICollection<Documento> Documentos { get; set; } = new List<Documento>();

    private static int CalculateAge(DateTime dateOfBirth)
    {
        var today = DateTime.Today;
        var age = today.Year - dateOfBirth.Year;
        
        if (dateOfBirth.Date > today.AddYears(-age))
            age--;
            
        return age;
    }
}