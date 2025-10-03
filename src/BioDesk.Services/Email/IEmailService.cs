using System.Threading.Tasks;
using System.Collections.Generic;

namespace BioDesk.Services.Email;

/// <summary>
/// Serviço de envio de emails com suporte offline e retry automático
/// </summary>
public interface IEmailService
{
    /// <summary>
    /// Envia um email. Se offline, adiciona à fila para envio posterior.
    /// </summary>
    Task<EmailResult> EnviarAsync(EmailMessage message);

    /// <summary>
    /// Verifica se há conexão com internet
    /// </summary>
    bool TemConexao { get; }

    /// <summary>
    /// Processa fila de mensagens pendentes (chamado automaticamente em background)
    /// </summary>
    Task ProcessarFilaAsync();

    /// <summary>
    /// Retorna número de mensagens na fila aguardando envio
    /// </summary>
    Task<int> ContarMensagensNaFilaAsync();

    /// <summary>
    /// Testa conexão SMTP com credenciais fornecidas (usado em ConfiguracoesView)
    /// </summary>
    Task<EmailResult> TestarConexaoAsync(string smtpUsername, string smtpPassword, string fromEmail, string fromName);
}

/// <summary>
/// Mensagem de email a ser enviada
/// </summary>
public class EmailMessage
{
    public string To { get; set; } = string.Empty;
    public string? ToName { get; set; }
    public string Subject { get; set; } = string.Empty;
    public string Body { get; set; } = string.Empty;
    public bool IsHtml { get; set; } = true;
    public List<string> Attachments { get; set; } = new();
}

/// <summary>
/// Resultado do envio de email
/// </summary>
public class EmailResult
{
    public bool Sucesso { get; set; }
    public string? Mensagem { get; set; }
    public bool AdicionadoNaFila { get; set; }
}
