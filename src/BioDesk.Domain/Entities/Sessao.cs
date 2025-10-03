using System;
using System.Collections.Generic;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma sessão clínica com o paciente
/// Pode incluir múltiplas abordagens terapêuticas numa única sessão
/// </summary>
public class Sessao
{
    public int Id { get; set; }

    /// <summary>
    /// Paciente da sessão
    /// </summary>
    public int PacienteId { get; set; }
    public Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Data e hora da sessão
    /// </summary>
    public DateTime DataHora { get; set; }

    /// <summary>
    /// Duração em minutos (padrão: 60 min)
    /// </summary>
    public int DuracaoMinutos { get; set; } = 60;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // ABORDAGENS TERAPÊUTICAS (Multi-seleção)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Abordagens terapêuticas aplicadas nesta sessão (pode ser mais que uma)
    /// </summary>
    public List<AbordagemSessao> Abordagens { get; set; } = new();

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // BALÃO 1: MOTIVO & CONTEXTO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Motivo principal da consulta (obrigatório)
    /// Exemplo: "Dor lombar aguda", "Avaliação inicial"
    /// </summary>
    public string Motivo { get; set; } = string.Empty;

    /// <summary>
    /// Contexto adicional (opcional)
    /// Exemplo: "Após esforço no trabalho", "Stress elevado no trabalho"
    /// </summary>
    public string? Contexto { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // BALÃO 2: ACHADOS & MEDIÇÕES
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Achados do exame físico (opcional)
    /// Exemplo: "Tensão L4-L5, trigger points bilateral"
    /// </summary>
    public string? Achados { get; set; }

    /// <summary>
    /// Pressão arterial (formato: "120/80")
    /// </summary>
    public string? PressaoArterial { get; set; }

    /// <summary>
    /// Peso em kg
    /// </summary>
    public decimal? Peso { get; set; }

    /// <summary>
    /// Temperatura em °C
    /// </summary>
    public decimal? Temperatura { get; set; }

    /// <summary>
    /// Outras medições em texto livre
    /// Exemplo: "Frequência cardíaca: 72 bpm"
    /// </summary>
    public string? OutrasMedicoes { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // BALÃO 3: AVALIAÇÃO & PLANO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Avaliação clínica (opcional)
    /// Exemplo: "Lombalgia mecânica aguda"
    /// </summary>
    public string? Avaliacao { get; set; }

    /// <summary>
    /// Plano terapêutico (opcional)
    /// Exemplo: "HVLA L4-L5 + Protocolo anti-inflamatório + Reavaliação em 1 semana"
    /// </summary>
    public string? Plano { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // METADATA
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Data de criação do registo
    /// </summary>
    public DateTime CriadoEm { get; set; } = DateTime.Now;

    /// <summary>
    /// Data da última modificação
    /// </summary>
    public DateTime? ModificadoEm { get; set; }

    /// <summary>
    /// Se true, sessão foi apagada (soft delete)
    /// </summary>
    public bool IsDeleted { get; set; } = false;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // PROPRIEDADES COMPUTED (Para UI)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Resumo da avaliação (primeiros 60 caracteres) para exibir na tabela
    /// </summary>
    public string AvaliacaoResumo
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Avaliacao))
                return "(Sem avaliação)";

            return Avaliacao.Length > 60
                ? Avaliacao.Substring(0, 60) + "..."
                : Avaliacao;
        }
    }

    /// <summary>
    /// Resumo do plano (primeiros 60 caracteres) para exibir na tabela
    /// </summary>
    public string PlanoResumo
    {
        get
        {
            if (string.IsNullOrWhiteSpace(Plano))
                return "(Sem plano)";

            return Plano.Length > 60
                ? Plano.Substring(0, 60) + "..."
                : Plano;
        }
    }
}
