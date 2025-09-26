using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma sessão clínica individual com um paciente
/// Cada sessão é uma entrada na timeline do Tab 3
/// </summary>
public class SessaoClinica
{
    [Key]
    public int Id { get; set; }

    /// <summary>
    /// Referência ao paciente
    /// </summary>
    [Required]
    public int PacienteId { get; set; }
    
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Data e hora da sessão
    /// </summary>
    [Required]
    public DateTime DataSessao { get; set; }

    /// <summary>
    /// Motivo principal da consulta
    /// </summary>
    [Required]
    [MaxLength(500)]
    public string Motivo { get; set; } = string.Empty;

    /// <summary>
    /// História da queixa atual - narrativa detalhada
    /// </summary>
    [MaxLength(2000)]
    public string HistoriaQueixaAtual { get; set; } = string.Empty;

    /// <summary>
    /// Observações da sessão (Tab 1)
    /// </summary>
    [MaxLength(1000)]
    public string ObservacoesSessao { get; set; } = string.Empty;

    /// <summary>
    /// Plano terapêutico definido nesta sessão
    /// </summary>
    [MaxLength(1000)]
    public string PlanoTerapeutico { get; set; } = string.Empty;

    /// <summary>
    /// Profissional que conduziu a sessão
    /// </summary>
    [MaxLength(200)]
    public string Profissional { get; set; } = string.Empty;

    /// <summary>
    /// Estado da sessão
    /// </summary>
    public StatusSessao Status { get; set; } = StatusSessao.Rascunho;

    /// <summary>
    /// Indica se houve alterações na medicação nesta sessão
    /// </summary>
    public bool HouveAlteracoesMedicacao { get; set; }

    /// <summary>
    /// Indica se houve alterações nas alergias nesta sessão
    /// </summary>
    public bool HouveAlteracoesAlergias { get; set; }

    /// <summary>
    /// Indica se houve alterações nas condições crónicas
    /// </summary>
    public bool HouveAlteracoesCronicas { get; set; }

    /// <summary>
    /// Sintomas trabalhados nesta sessão
    /// </summary>
    public virtual ICollection<SintomaSessao> SintomasTrabalhados { get; set; } = new List<SintomaSessao>();

    /// <summary>
    /// Alterações de medicação aplicadas nesta sessão
    /// </summary>
    public virtual ICollection<AlteracaoMedicacao> AlteracoesMedicacao { get; set; } = new List<AlteracaoMedicacao>();

    /// <summary>
    /// Red flags identificados nesta sessão
    /// </summary>
    public virtual ICollection<RedFlag> RedFlags { get; set; } = new List<RedFlag>();

    /// <summary>
    /// Declaração legal gerada para esta sessão (Tab 2)
    /// </summary>
    public virtual DeclaracaoLegal? Declaracao { get; set; }

    /// <summary>
    /// Timestamps de auditoria
    /// </summary>
    public DateTime CriadoEm { get; set; } = DateTime.UtcNow;
    public DateTime AtualizadoEm { get; set; } = DateTime.UtcNow;
}

public enum StatusSessao
{
    Rascunho = 0,
    EmAndamento = 1,
    Finalizada = 2,
    Assinada = 3
}