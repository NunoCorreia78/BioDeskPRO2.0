using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Mail;
using System.Threading.Tasks;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.Services.Email;

/// <summary>
/// Implementação do serviço de email com suporte offline e retry automático
/// SINGLETON - Usa IServiceProvider para resolver BioDeskDbContext (scoped)
/// </summary>
public class EmailService : IEmailService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<EmailService> _logger;

    // Configurações SMTP (podem ser movidas para appsettings.json)
    private const string SmtpHost = "smtp.gmail.com"; // Alterar conforme necessário
    private const int SmtpPort = 587;
    private const string SmtpUsername = "seu-email@gmail.com"; // ⚠️ CONFIGURAR
    private const string SmtpPassword = "sua-senha-app"; // ⚠️ CONFIGURAR
    private const string FromEmail = "seu-email@gmail.com"; // ⚠️ CONFIGURAR
    private const string FromName = "BioDeskPro - Clínica"; // ⚠️ CONFIGURAR

    public EmailService(IServiceProvider serviceProvider, ILogger<EmailService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    /// <summary>
    /// Verifica se tem conexão com internet
    /// </summary>
    public bool TemConexao
    {
        get
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
                var response = client.GetAsync("https://www.google.com").Result;
                return response.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }
    }

    /// <summary>
    /// Envia um email. Se offline, adiciona à fila.
    /// </summary>
    public async Task<EmailResult> EnviarAsync(EmailMessage message)
    {
        _logger.LogInformation("📧 Tentando enviar email para {To}: {Subject}", message.To, message.Subject);

        // Verificar conexão
        if (!TemConexao)
        {
            _logger.LogWarning("⚠️ Sem conexão com internet. Email adicionado à fila.");
            return new EmailResult
            {
                Sucesso = false,
                AdicionadoNaFila = true,
                Mensagem = "Sem conexão. Email será enviado automaticamente quando a conexão retornar."
            };
        }

        // Tentar enviar
        try
        {
            await EnviarViaSMTPAsync(message);

            _logger.LogInformation("✅ Email enviado com sucesso para {To}", message.To);

            return new EmailResult
            {
                Sucesso = true,
                Mensagem = "Email enviado com sucesso!"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao enviar email para {To}", message.To);

            return new EmailResult
            {
                Sucesso = false,
                AdicionadoNaFila = true,
                Mensagem = $"Erro: {ex.Message}. Email adicionado à fila para retry."
            };
        }
    }

    /// <summary>
    /// Processa fila de mensagens pendentes
    /// </summary>
    public async Task ProcessarFilaAsync()
    {
        if (!TemConexao)
        {
            _logger.LogDebug("⚠️ Sem conexão. Fila não processada.");
            return;
        }

        _logger.LogInformation("🔄 Processando fila de emails...");

        // ✅ Criar scope para resolver DbContext
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

        // Buscar mensagens na fila (não enviadas, com tentativas < 3, e próxima tentativa <= agora)
        var mensagensNaFila = await dbContext.Comunicacoes
            .Where(c => !c.IsEnviado
                && c.Status == StatusComunicacao.Agendado
                && c.TentativasEnvio < 3
                && (!c.ProximaTentativa.HasValue || c.ProximaTentativa.Value <= DateTime.Now))
            .Include(c => c.Anexos)
            .ToListAsync();

        _logger.LogInformation("📬 {Count} mensagens na fila para processar", mensagensNaFila.Count);

        foreach (var comunicacao in mensagensNaFila)
        {
            try
            {
                // Criar EmailMessage
                var emailMessage = new EmailMessage
                {
                    To = comunicacao.Destinatario,
                    Subject = comunicacao.Assunto ?? "Mensagem da Clínica",
                    Body = comunicacao.Corpo,
                    IsHtml = true,
                    Attachments = comunicacao.Anexos.Select(a => a.CaminhoArquivo).ToList()
                };

                // Tentar enviar
                await EnviarViaSMTPAsync(emailMessage);

                // Sucesso → Atualizar status
                comunicacao.IsEnviado = true;
                comunicacao.Status = StatusComunicacao.Enviado;
                comunicacao.DataEnvio = DateTime.Now;
                comunicacao.UltimoErro = null;

                _logger.LogInformation("✅ Email da fila enviado com sucesso (ID: {Id})", comunicacao.Id);
            }
            catch (Exception ex)
            {
                // Falhou → Incrementar tentativas e agendar próxima tentativa
                comunicacao.TentativasEnvio++;
                comunicacao.UltimoErro = ex.Message;
                comunicacao.ProximaTentativa = DateTime.Now.AddMinutes(5 * comunicacao.TentativasEnvio); // Backoff exponencial

                if (comunicacao.TentativasEnvio >= 3)
                {
                    comunicacao.Status = StatusComunicacao.Falhado;
                    _logger.LogError("❌ Email falhou após 3 tentativas (ID: {Id}): {Error}", comunicacao.Id, ex.Message);
                }
                else
                {
                    _logger.LogWarning("⚠️ Tentativa {Tentativa}/3 falhou para email ID {Id}. Próxima tentativa: {ProximaTentativa}",
                        comunicacao.TentativasEnvio, comunicacao.Id, comunicacao.ProximaTentativa);
                }
            }

            await dbContext.SaveChangesAsync();
        }

        _logger.LogInformation("✅ Processamento de fila concluído");
    }

    /// <summary>
    /// Retorna número de mensagens na fila
    /// </summary>
    public async Task<int> ContarMensagensNaFilaAsync()
    {
        // ✅ Criar scope para resolver DbContext
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

        return await dbContext.Comunicacoes
            .CountAsync(c => !c.IsEnviado && c.Status == StatusComunicacao.Agendado);
    }

    /// <summary>
    /// Envia email via SMTP
    /// </summary>
    private async Task EnviarViaSMTPAsync(EmailMessage message)
    {
        using var smtpClient = new SmtpClient(SmtpHost, SmtpPort)
        {
            Credentials = new NetworkCredential(SmtpUsername, SmtpPassword),
            EnableSsl = true
        };

        using var mailMessage = new MailMessage
        {
            From = new MailAddress(FromEmail, FromName),
            Subject = message.Subject,
            Body = message.Body,
            IsBodyHtml = message.IsHtml
        };

        mailMessage.To.Add(new MailAddress(message.To, message.ToName ?? string.Empty));

        // Adicionar anexos
        foreach (var attachmentPath in message.Attachments)
        {
            if (System.IO.File.Exists(attachmentPath))
            {
                var attachment = new Attachment(attachmentPath);
                mailMessage.Attachments.Add(attachment);
            }
            else
            {
                _logger.LogWarning("⚠️ Anexo não encontrado: {Path}", attachmentPath);
            }
        }

        await smtpClient.SendMailAsync(mailMessage);
    }
}
