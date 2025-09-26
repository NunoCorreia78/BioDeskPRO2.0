using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade que representa uma consulta no sistema BioDeskPro2
/// Caminho de ouro: CriarConsulta → Validação → Gravação → AtualizarEstatisticas
/// </summary>
public class Consulta
{
    public int Id { get; set; }

    #region Relacionamento com Paciente
    [Required]
    public int PacienteId { get; set; }
    
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;
    #endregion

    #region Dados da Consulta
    [Required(ErrorMessage = "Data da consulta é obrigatória")]
    public DateTime DataConsulta { get; set; } = DateTime.Now;

    [Required(ErrorMessage = "Tipo de consulta é obrigatório")]
    [MaxLength(50)]
    public string TipoConsulta { get; set; } = string.Empty; // "Primeira" ou "Seguimento"

    [MaxLength(2000)]
    public string? Notas { get; set; }

    [MaxLength(5000)]
    public string? Prescricao { get; set; }

    [Column(TypeName = "decimal(10,2)")]
    public decimal? Valor { get; set; }

    [Required]
    [MaxLength(20)]
    public string Status { get; set; } = "Agendada"; // "Agendada", "Realizada", "Cancelada", "Faltou"
    #endregion

    #region Metadados
    public DateTime DataCriacao { get; set; } = DateTime.Now;
    public DateTime? DataUltimaEdicao { get; set; }
    #endregion

    #region Métodos de Conveniência
    public bool IsPrimeiraConsulta => TipoConsulta.Equals("Primeira", StringComparison.OrdinalIgnoreCase);
    
    public bool IsConsultaRealizada => Status.Equals("Realizada", StringComparison.OrdinalIgnoreCase);
    
    public string GetDescricaoCompleta()
    {
        return $"{TipoConsulta} - {DataConsulta:dd/MM/yyyy HH:mm} ({Status})";
    }
    #endregion
}