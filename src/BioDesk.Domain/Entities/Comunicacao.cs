using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma comunicação com o paciente (email, SMS, chamada)
/// Suporta fila offline com tentativas automáticas de reenvio
/// </summary>
public class Comunicacao
{
    public int Id { get; set; }

    /// <summary>
    /// Paciente destinatário
    /// </summary>
    public int PacienteId { get; set; }
    public Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Tipo de comunicação
    /// </summary>
    [Required]
    public TipoComunicacao Tipo { get; set; }

    /// <summary>
    /// Destinatário (email ou telefone)
    /// </summary>
    [Required]
    [StringLength(200)]
    public string Destinatario { get; set; } = string.Empty;

    /// <summary>
    /// Assunto (para emails)
    /// </summary>
    [StringLength(500)]
    public string? Assunto { get; set; }

    /// <summary>
    /// Corpo da mensagem
    /// </summary>
    public string Corpo { get; set; } = string.Empty;

    /// <summary>
    /// Anexos (PDFs, imagens, etc.)
    /// </summary>
    public List<AnexoComunicacao> Anexos { get; set; } = new();

    /// <summary>
    /// Template utilizado (se aplicável)
    /// </summary>
    [StringLength(100)]
    public string? TemplateUtilizado { get; set; }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // STATUS E TRACKING
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Status atual da comunicação
    /// </summary>
    [Required]
    public StatusComunicacao Status { get; set; } = StatusComunicacao.Rascunho;

    /// <summary>
    /// Data de criação
    /// </summary>
    public DateTime DataCriacao { get; set; } = DateTime.Now;

    /// <summary>
    /// Data de envio efetivo
    /// </summary>
    public DateTime? DataEnvio { get; set; }

    /// <summary>
    /// Data em que o email foi aberto (tracking)
    /// </summary>
    public DateTime? DataAbertura { get; set; }

    /// <summary>
    /// Se o email foi aberto pelo destinatário
    /// </summary>
    public bool FoiAberto { get; set; } = false;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // FILA OFFLINE E AUTO-RETRY
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Se a mensagem foi enviada com sucesso
    /// </summary>
    public bool IsEnviado { get; set; } = false;

    /// <summary>
    /// Número de tentativas de envio já realizadas
    /// </summary>
    public int TentativasEnvio { get; set; } = 0;

    /// <summary>
    /// Data/hora da próxima tentativa de envio (para retry automático)
    /// </summary>
    public DateTime? ProximaTentativa { get; set; }

    /// <summary>
    /// Última mensagem de erro (se falhou)
    /// </summary>
    [StringLength(1000)]
    public string? UltimoErro { get; set; }

    /// <summary>
    /// Mensagem está na fila aguardando conexão
    /// </summary>
    public bool NaFila => !IsEnviado && Status == StatusComunicacao.Agendado;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // FOLLOW-UP AUTOMÁTICO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Data agendada para follow-up automático
    /// </summary>
    public DateTime? DataFollowUp { get; set; }

    /// <summary>
    /// Mensagem do follow-up
    /// </summary>
    public string? MensagemFollowUp { get; set; }

    /// <summary>
    /// Se o follow-up já foi enviado
    /// </summary>
    public bool FollowUpEnviado { get; set; } = false;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // METADATA
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /// <summary>
    /// Observações adicionais
    /// </summary>
    public string? Observacoes { get; set; }

    /// <summary>
    /// Soft delete
    /// </summary>
    public bool IsDeleted { get; set; } = false;
}

/// <summary>
/// Tipos de comunicação suportados
/// </summary>
public enum TipoComunicacao
{
    Email = 1,
    SMS = 2,
    Chamada = 3,
    WhatsApp = 4,
    Presencial = 5
}

/// <summary>
/// Status da comunicação
/// </summary>
public enum StatusComunicacao
{
    Rascunho = 1,      // Ainda não enviado
    Agendado = 2,      // Na fila para envio
    Enviado = 3,       // Enviado com sucesso
    Entregue = 4,      // Confirmado entrega (tracking)
    Aberto = 5,        // Email foi aberto
    Respondido = 6,    // Paciente respondeu
    Falhado = 7        // Falhou após várias tentativas
}
