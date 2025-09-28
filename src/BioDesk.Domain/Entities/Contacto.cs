using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade para dados de contacto do paciente
/// Separada para normalização e flexibilidade futura
/// </summary>
public class Contacto
{
    public int Id { get; set; }

    /// <summary>
    /// FK para o paciente proprietário
    /// </summary>
    [Required]
    public int PacienteId { get; set; }

    // === MORADA PRINCIPAL ===
    [StringLength(300)]
    public string? RuaAvenida { get; set; }

    [StringLength(10)]
    public string? Numero { get; set; }

    [StringLength(50)]
    public string? AndarFraccao { get; set; }

    [StringLength(8)] // XXXX-XXX formato português
    public string? CodigoPostal { get; set; }

    [StringLength(100)]
    public string? Localidade { get; set; }

    [StringLength(100)]
    public string? Distrito { get; set; }

    // === CONTACTOS DIRETOS ===
    [StringLength(20)]
    public string? TelefonePrincipal { get; set; }

    [StringLength(20)]
    public string? TelefoneAlternativo { get; set; }

    [StringLength(200)]
    [EmailAddress]
    public string? EmailPrincipal { get; set; }

    [StringLength(200)]
    [EmailAddress]
    public string? EmailAlternativo { get; set; }

    // === NAVEGAÇÃO ===
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Morada completa formatada para exibição
    /// </summary>
    public string MoradaCompleta =>
        $"{RuaAvenida} {Numero}, {AndarFraccao}\n{CodigoPostal} {Localidade}\n{Distrito}".Trim();

    /// <summary>
    /// Contacto principal para exibição rápida
    /// </summary>
    public string ContactoPrincipal =>
        !string.IsNullOrEmpty(TelefonePrincipal) ? TelefonePrincipal :
        !string.IsNullOrEmpty(EmailPrincipal) ? EmailPrincipal : "N/A";
}
