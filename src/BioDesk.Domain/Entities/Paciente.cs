using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade principal do paciente com dados biográficos completos
/// Aba 1: Dados Biográficos - Identificação e contactos
/// </summary>
public class Paciente
{
    public int Id { get; set; }

    /// <summary>
    /// Número de processo único (gerado automaticamente)
    /// </summary>
    public string NumeroProcesso { get; set; } = string.Empty;

    // === IDENTIFICAÇÃO PESSOAL (Obrigatórios) ===
    [Required]
    [StringLength(200)]
    public string NomeCompleto { get; set; } = string.Empty;

    // ⭐ NULLABLE - Pode ficar vazio até utilizador preencher
    public DateTime? DataNascimento { get; set; }

    [Required]
    [StringLength(20)]
    public string Genero { get; set; } = string.Empty; // Masculino/Feminino/Outro/Não especifica

    // === IDENTIFICAÇÃO PESSOAL (Opcionais) ===
    [StringLength(100)]
    public string? NomePreferido { get; set; }

    [StringLength(9)] // NIF português tem 9 dígitos
    public string? NIF { get; set; }

    [StringLength(100)]
    public string? Nacionalidade { get; set; }

    [StringLength(50)]
    public string? EstadoCivil { get; set; }

    [StringLength(200)]
    public string? Profissao { get; set; }

    [StringLength(100)]
    public string? Proveniencia { get; set; } // Como conheceu a clínica

    [StringLength(200)]
    public string? ProvenienciaOutro { get; set; } // Detalhes quando seleciona "Outro"

    // === DADOS SISTEMA ===
    public DateTime DataCriacao { get; set; } = DateTime.UtcNow;
    public DateTime? DataUltimaAtualizacao { get; set; }

    /// <summary>
    /// Estado do registo: Incompleto/Em Progresso/Completo
    /// </summary>
    [StringLength(20)]
    public string EstadoRegisto { get; set; } = "Incompleto";

    /// <summary>
    /// Progresso das abas: bitfield ou JSON com estado de cada aba
    /// </summary>
    public string? ProgressoAbas { get; set; }

    // === PROPRIEDADES CALCULADAS ===
    /// <summary>
    /// Idade calculada automaticamente (null se DataNascimento não preenchida)
    /// </summary>
    public int? Idade => DataNascimento.HasValue
        ? DateTime.Now.Year - DataNascimento.Value.Year - (DateTime.Now.DayOfYear < DataNascimento.Value.DayOfYear ? 1 : 0)
        : null;

    // === NAVEGAÇÃO PARA OUTRAS ENTIDADES ===
    public virtual Contacto? Contacto { get; set; }
    public virtual DeclaracaoSaude? DeclaracaoSaude { get; set; } // ⭐ Aba 2 - Declaração de Saúde
    public virtual ICollection<HistoricoMedico> HistoricoMedico { get; set; } = [];
    public virtual ICollection<Consulta> Consultas { get; set; } = [];
    public virtual ICollection<Consentimento> Consentimentos { get; set; } = [];
    public virtual ICollection<IrisAnalise> IrisAnalises { get; set; } = [];

    public override string ToString() =>
        $"{NomeCompleto} ({NumeroProcesso}) - {Idade} anos";
}
