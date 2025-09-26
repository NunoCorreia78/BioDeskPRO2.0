using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa alterações na medicação numa sessão específica
/// Rastreamento de mudanças para o sistema de deltas
/// </summary>
public class AlteracaoMedicacao
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Referência à sessão clínica
    /// </summary>
    [Required]
    public int SessaoClinicaId { get; set; }
    
    [ForeignKey(nameof(SessaoClinicaId))]
    public virtual SessaoClinica SessaoClinica { get; set; } = null!;

    /// <summary>
    /// Nome da medicação
    /// </summary>
    [Required]
    [MaxLength(200)]
    public string NomeMedicacao { get; set; } = string.Empty;

    /// <summary>
    /// Tipo de alteração realizada
    /// </summary>
    public TipoAlteracaoMedicacao TipoAlteracao { get; set; }

    /// <summary>
    /// Dose anterior (para ajustes)
    /// </summary>
    [MaxLength(100)]
    public string DoseAnterior { get; set; } = string.Empty;

    /// <summary>
    /// Nova dose
    /// </summary>
    [MaxLength(100)]
    public string NovaDosse { get; set; } = string.Empty;

    /// <summary>
    /// Via de administração
    /// </summary>
    [MaxLength(50)]
    public string Via { get; set; } = string.Empty;

    /// <summary>
    /// Frequência
    /// </summary>
    [MaxLength(100)]
    public string Frequencia { get; set; } = string.Empty;

    /// <summary>
    /// Indicação/motivo
    /// </summary>
    [MaxLength(300)]
    public string Indicacao { get; set; } = string.Empty;

    /// <summary>
    /// Motivo da alteração
    /// </summary>
    [MaxLength(500)]
    public string MotivoAlteracao { get; set; } = string.Empty;

    /// <summary>
    /// Data da alteração
    /// </summary>
    public DateTime DataAlteracao { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Indica se deve [Atualizar permanente]
    /// </summary>
    public bool AtualizarPermanente { get; set; } = false;

    /// <summary>
    /// Observações sobre a alteração
    /// </summary>
    [MaxLength(500)]
    public string Observacoes { get; set; } = string.Empty;
}

public enum TipoAlteracaoMedicacao
{
    Nova = 0,
    AjusteDose = 1,
    Suspensao = 2,
    Substituicao = 3,
    AlteracaoFrequencia = 4
}