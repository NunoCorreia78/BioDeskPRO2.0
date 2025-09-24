using System;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade que representa um paciente no sistema BioDeskPro2
/// Caminho de ouro: Criação → Validação → Gravação → SetPacienteAtivo → NavigateTo("FichaPaciente")
/// </summary>
public class Paciente
{
    public int Id { get; set; }

    [Required(ErrorMessage = "Nome é obrigatório")]
    [MaxLength(200)]
    public string Nome { get; set; } = string.Empty;

    [Required(ErrorMessage = "Data de nascimento é obrigatória")]
    public DateTime DataNascimento { get; set; }

    [Required(ErrorMessage = "Email é obrigatório")]
    [EmailAddress(ErrorMessage = "Email inválido")]
    [MaxLength(255)]
    public string Email { get; set; } = string.Empty;

    [MaxLength(20)]
    public string? Telefone { get; set; }

    // Timestamps
    public DateTime CriadoEm { get; set; } = DateTime.Now;
    public DateTime AtualizadoEm { get; set; } = DateTime.Now;

    /// <summary>
    /// Atualiza a data de última atualização
    /// </summary>
    public void AtualizarTimestamp()
    {
        AtualizadoEm = DateTime.Now;
    }
}