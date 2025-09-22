using System.ComponentModel.DataAnnotations;

namespace BioDeskPRO.Models;

/// <summary>
/// Patient entity representing biographical data
/// </summary>
public class Patient
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string FullName { get; set; } = string.Empty;

    [Required]
    public DateTime DateOfBirth { get; set; }

    [MaxLength(50)]
    public string CivilStatus { get; set; } = string.Empty;

    [MaxLength(20)]
    public string Phone { get; set; } = string.Empty;

    [MaxLength(20)]
    public string Mobile { get; set; } = string.Empty;

    [MaxLength(200)]
    public string Email { get; set; } = string.Empty;

    [MaxLength(100)]
    public string HowFoundClinic { get; set; } = string.Empty;

    public string GeneralObservations { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Calculated property for age based on date of birth
    /// </summary>
    public int Age
    {
        get
        {
            var today = DateTime.Today;
            var age = today.Year - DateOfBirth.Year;
            if (DateOfBirth.Date > today.AddYears(-age))
                age--;
            return age;
        }
    }

    /// <summary>
    /// Navigation properties for future modules
    /// </summary>
    public virtual ICollection<Consultation> Consultations { get; set; } = new List<Consultation>();
    public virtual ICollection<ConsentSignature> ConsentSignatures { get; set; } = new List<ConsentSignature>();
}

/// <summary>
/// Consultation entity for future medical appointments
/// </summary>
public class Consultation
{
    [Key]
    public int Id { get; set; }

    [Required]
    public int PatientId { get; set; }

    [Required]
    public DateTime ConsultationDate { get; set; }

    public string Notes { get; set; } = string.Empty;

    public string Treatment { get; set; } = string.Empty;

    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    public virtual Patient Patient { get; set; } = null!;
}

/// <summary>
/// Consent type for LGPD/GDPR compliance
/// </summary>
public class ConsentType
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [Required]
    public string Description { get; set; } = string.Empty;

    public bool IsRequired { get; set; }

    public bool IsActive { get; set; } = true;

    public virtual ICollection<ConsentSignature> ConsentSignatures { get; set; } = new List<ConsentSignature>();
}

/// <summary>
/// Consent signature tracking
/// </summary>
public class ConsentSignature
{
    [Key]
    public int Id { get; set; }

    [Required]
    public int PatientId { get; set; }

    [Required]
    public int ConsentTypeId { get; set; }

    [Required]
    public DateTime SignedAt { get; set; }

    public bool IsActive { get; set; } = true;

    public virtual Patient Patient { get; set; } = null!;
    public virtual ConsentType ConsentType { get; set; } = null!;
}