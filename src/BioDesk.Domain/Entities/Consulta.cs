using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Entidade para registo de consultas
/// Aba 4: Registo de Consultas - Metodologia SOAP
/// </summary>
public class Consulta
{
    public int Id { get; set; }

    [Required]
    public int PacienteId { get; set; }

    // === INFORMAÇÕES BÁSICAS ===
    /// <summary>
    /// Data e hora da consulta
    /// </summary>
    [Required]
    public DateTime DataHoraConsulta { get; set; }

    /// <summary>
    /// Tipo: "Primeira Consulta"|"Seguimento"|"Urgência"|"Reavaliação"
    /// </summary>
    [Required]
    [StringLength(50)]
    public string TipoConsulta { get; set; } = string.Empty;

    /// <summary>
    /// Duração em minutos: 30|45|60|90
    /// </summary>
    public int DuracaoPrevista { get; set; }

    /// <summary>
    /// Duração real da consulta (preenchida após)
    /// </summary>
    public int? DuracaoReal { get; set; }

    // === METODOLOGIA SOAP ===

    #region S - SUBJETIVO (Queixas do Paciente)

    /// <summary>
    /// Queixa principal - motivo da consulta
    /// </summary>
    [Required]
    public string QueixaPrincipal { get; set; } = string.Empty;

    /// <summary>
    /// História da doença atual - evolução dos sintomas
    /// </summary>
    public string? HistoriaDoencaAtual { get; set; }

    /// <summary>
    /// Revisão de sistemas (JSON com checkboxes por sistema)
    /// Ex: {"Cardiovascular":["Palpitações","Dor torácica"],"Digestivo":["Náuseas"]}
    /// </summary>
    public string? RevisaoSistemas { get; set; }

    #endregion

    #region O - OBJETIVO (Observações Clínicas)

    /// <summary>
    /// Pressão arterial (ex: "120/80")
    /// </summary>
    [StringLength(20)]
    public string? PressaoArterial { get; set; }

    /// <summary>
    /// Peso em kg
    /// </summary>
    [Column(TypeName = "decimal(5,2)")]
    public decimal? Peso { get; set; }

    /// <summary>
    /// Altura em cm
    /// </summary>
    [Column(TypeName = "decimal(5,1)")]
    public decimal? Altura { get; set; }

    /// <summary>
    /// Temperatura em Celsius
    /// </summary>
    [Column(TypeName = "decimal(4,1)")]
    public decimal? Temperatura { get; set; }

    /// <summary>
    /// Frequência cardíaca (bpm)
    /// </summary>
    public int? FrequenciaCardiaca { get; set; }

    /// <summary>
    /// Exame físico detalhado
    /// </summary>
    public string? ExameFisico { get; set; }

    /// <summary>
    /// Testes e avaliações realizadas (JSON array)
    /// </summary>
    public string? TestesAvaliacoes { get; set; }

    #endregion

    #region A - AVALIAÇÃO (Análise Clínica)

    /// <summary>
    /// Diagnóstico principal (naturopático)
    /// </summary>
    [Required]
    public string DiagnosticoPrincipal { get; set; } = string.Empty;

    /// <summary>
    /// Diagnósticos secundários (JSON array)
    /// </summary>
    public string? DiagnosticosSecundarios { get; set; }

    /// <summary>
    /// Prognóstico - expectativas de evolução
    /// </summary>
    public string? Prognostico { get; set; }

    #endregion

    #region P - PLANO (Tratamento)

    /// <summary>
    /// Tratamentos prescritos (JSON array)
    /// Ex: [{"Tratamento":"Extrato de Valeriana","Dosagem":"300mg","Duracao":"30 dias","Instrucoes":"1x ao deitar"}]
    /// </summary>
    public string? TratamentosPrescritos { get; set; }

    /// <summary>
    /// Recomendações gerais - mudanças de estilo de vida
    /// </summary>
    public string? RecomendacoesGerais { get; set; }

    /// <summary>
    /// Data sugerida para próximo seguimento
    /// </summary>
    public DateTime? ProximoSeguimento { get; set; }

    #endregion

    // === ASPETOS FINANCEIROS ===
    /// <summary>
    /// Valor da consulta
    /// </summary>
    [Column(TypeName = "decimal(10,2)")]
    public decimal? Valor { get; set; }

    /// <summary>
    /// Estado de pagamento
    /// </summary>
    [StringLength(20)]
    public string EstadoPagamento { get; set; } = "Pendente";

    /// <summary>
    /// Data do pagamento
    /// </summary>
    public DateTime? DataPagamento { get; set; }

    /// <summary>
    /// Método de pagamento: "Dinheiro"|"MB Way"|"Cartão"|"Transferência"
    /// </summary>
    [StringLength(20)]
    public string? MetodoPagamento { get; set; }

    // === ESTADO DA CONSULTA ===
    /// <summary>
    /// Estado: "Agendada"|"Realizada"|"Falta"|"Cancelada"
    /// </summary>
    [Required]
    [StringLength(20)]
    public string Estado { get; set; } = "Agendada";

    /// <summary>
    /// Observações internas (não visíveis ao paciente)
    /// </summary>
    public string? ObservacoesInternas { get; set; }

    // === METADADOS ===
    public DateTime DataCriacao { get; set; } = DateTime.UtcNow;
    public DateTime? DataAtualizacao { get; set; }

    // === NAVEGAÇÃO ===
    [ForeignKey(nameof(PacienteId))]
    public virtual Paciente Paciente { get; set; } = null!;

    // === PROPRIEDADES CALCULADAS ===
    /// <summary>
    /// IMC calculado automaticamente
    /// </summary>
    public decimal? IMC =>
        Peso.HasValue && Altura.HasValue && Altura.Value > 0
            ? Math.Round(Peso.Value / (Altura.Value / 100 * Altura.Value / 100), 2)
            : null;

    /// <summary>
    /// Descrição resumida da consulta
    /// </summary>
    public string ResumoConsulta =>
        $"{DataHoraConsulta:dd/MM/yyyy HH:mm} - {TipoConsulta}: {QueixaPrincipal}";
}
