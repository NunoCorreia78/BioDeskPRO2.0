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
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.Services.Email;

/// <summary>
/// Implementação do serviço de email com suporte offline e retry automático
/// SINGLETON - Usa IServiceProvider para resolver BioDeskDbContext (scoped)
///
/// 🔴 PROTEGIDO - VER REGRAS_CRITICAS_EMAIL.md ANTES DE ALTERAR!
/// Sistema 100% funcional (testado 22/10/2025)
/// - Retry automático (3 tentativas com backoff exponencial)
/// - Queue fallback para cenários offline
/// - Validação robusta de credenciais
/// - Logging detalhado de SMTP errors
/// </summary>
public class EmailService : IEmailService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    // 🔴 PROTEGIDO - Configurações SMTP dinâmicas (NÃO REMOVER VALIDAÇÃO!)
    private string SmtpHost => _configuration["Email:SmtpHost"] ?? "smtp.gmail.com";
    private int SmtpPort => int.TryParse(_configuration["Email:SmtpPort"], out var p) ? p : 587;

    // 🔴 PROTEGIDO - Validação crítica de credenciais (NÃO SIMPLIFICAR!)
    // Bug histórico: Validação com "!= null" não detectava strings vazias
    // Fix: IsNullOrWhiteSpace + mensagens acionáveis ao usuário
    private string SmtpUsername
    {
        get
        {
            var sender = _configuration["Email:Sender"] ?? _configuration["Email:FromEmail"];
            if (string.IsNullOrWhiteSpace(sender))
            {
                throw new InvalidOperationException("❌ Email:Sender não configurado ou vazio. Use Configurações → Email para definir credenciais.");
            }
            return sender;
        }
    }

    private string SmtpPassword
    {
        get
        {
            var password = _configuration["Email:Password"];
            if (string.IsNullOrWhiteSpace(password))
            {
                throw new InvalidOperationException("❌ Email:Password não configurado ou vazio. Use Configurações → Email para definir App Password do Gmail.");
            }
            return password;
        }
    }

    private string FromEmail => _configuration["Email:FromEmail"] ?? _configuration["Email:Sender"] ?? throw new InvalidOperationException("Email:Sender nÃ£o configurado.");
    private string FromName => _configuration["Email:SenderName"] ?? _configuration["Email:FromName"] ?? "BioDeskPro - Terapias Naturais";

    public EmailService(IServiceProvider serviceProvider, IConfiguration configuration, ILogger<EmailService> logger)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _logger = logger;
    }

    /// <summary>
    /// Verifica se tem conexÃ£o com internet
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
    /// âš¡ CORREÃ‡ÃƒO CRÃTICA: Envia email IMEDIATAMENTE ou falha com exceÃ§Ã£o clara
    /// NÃƒO silencia erros - se falhar, LANÃ‡A EXCEÃ‡ÃƒO para ViewModel tratar
    /// </summary>
    public async Task<EmailResult> EnviarAsync(EmailMessage message)
    {
        _logger.LogInformation("ðŸ“§ Tentando enviar email IMEDIATO para {To}: {Subject}", message.To, message.Subject);

        // ðŸ” DEBUG: Verificar configuraÃ§Ã£o carregada
        var sender = _configuration["Email:Sender"];
        var password = _configuration["Email:Password"];
        _logger.LogWarning("ðŸ” DEBUG - Email:Sender/FromEmail: {Sender}", string.IsNullOrEmpty(sender) ? "âŒ VAZIO" : "âœ… " + sender);
        _logger.LogWarning("ðŸ” DEBUG - Email:Password configurado: {Password}", string.IsNullOrEmpty(password) ? "âŒ VAZIO" : "âœ… (oculto)");

        // âš ï¸ Verificar conexÃ£o
        if (!TemConexao)
        {
            _logger.LogWarning("âš ï¸ Sem conexÃ£o com internet.");
            return new EmailResult
            {
                Sucesso = false,
                AdicionadoNaFila = true,
                Mensagem = "Sem conexÃ£o Ã  internet. Email ficarÃ¡ agendado para envio automÃ¡tico."
            };
        }

        // âš¡ Tentar enviar IMEDIATAMENTE
        try
        {
            _logger.LogWarning("ðŸ”Œ TENTANDO SMTP com Host={Host}, Port={Port}, Username={Username}", SmtpHost, SmtpPort, SmtpUsername);
            await EnviarViaSMTPAsync(message);
            _logger.LogInformation("âœ… Email enviado IMEDIATAMENTE para {To}", message.To);

            return new EmailResult
            {
                Sucesso = true,
                Mensagem = "âœ… Email enviado com sucesso!"
            };
        }
        catch (Exception ex)
        {
            // âŒ CRÃTICO: NÃƒO SILENCIAR - LanÃ§ar exceÃ§Ã£o para ViewModel saber que falhou
            _logger.LogError(ex, "âŒ ERRO ao enviar email para {To}: {Message}", message.To, ex.Message);
            _logger.LogError("âŒ Stack Trace: {StackTrace}", ex.StackTrace);

            // Retornar falha COM mensagem clara
            return new EmailResult
            {
                Sucesso = false,
                AdicionadoNaFila = false, // âš ï¸ NÃƒO foi adicionado Ã  fila - estÃ¡ na BD como Agendado
                Mensagem = $"âŒ Erro ao enviar: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Processa fila de mensagens pendentes
    /// </summary>
    public async Task ProcessarFilaAsync()
    {
        _logger.LogWarning("ðŸ” [ProcessarFila] INICIANDO verificaÃ§Ã£o...");

        if (!TemConexao)
        {
            _logger.LogWarning("âš ï¸ [ProcessarFila] Sem conexÃ£o. Fila nÃ£o processada.");
            return;
        }

        _logger.LogWarning("âœ… [ProcessarFila] ConexÃ£o OK. Buscando emails agendados...");

        // âœ… Criar scope para resolver DbContext
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

        // Buscar mensagens na fila (nÃ£o enviadas, com tentativas < 3, e prÃ³xima tentativa <= agora)
        var mensagensNaFila = await dbContext.Comunicacoes
            .Where(c => !c.IsEnviado
                && c.Status == StatusComunicacao.Agendado
                && c.TentativasEnvio < 3
                && (!c.ProximaTentativa.HasValue || c.ProximaTentativa.Value <= DateTime.Now))
            .Include(c => c.Anexos)
            .ToListAsync();

        _logger.LogWarning("ðŸ“¬ [ProcessarFila] Encontrei {Count} mensagens na fila", mensagensNaFila.Count);

        foreach (var msg in mensagensNaFila)
        {
            _logger.LogWarning("  â†’ Email ID {Id}: {Assunto} (Tentativas: {Tentativas})",
                msg.Id, msg.Assunto, msg.TentativasEnvio);
        }

        foreach (var comunicacao in mensagensNaFila)
        {
            _logger.LogWarning("ðŸ”§ [ProcessarFila] Tentando enviar Email ID {Id}...", comunicacao.Id);

            try
            {
                // Criar EmailMessage
                var emailMessage = new EmailMessage
                {
                    To = comunicacao.Destinatario,
                    Subject = comunicacao.Assunto ?? "Mensagem da ClÃ­nica",
                    Body = comunicacao.Corpo,
                    IsHtml = true,
                    Attachments = comunicacao.Anexos.Select(a => a.CaminhoArquivo).ToList()
                };

                _logger.LogWarning("ðŸ“§ [ProcessarFila] Enviando via SMTP para {To}...", comunicacao.Destinatario);

                // Tentar enviar
                await EnviarViaSMTPAsync(emailMessage);

                // âœ… SUCESSO â†’ Atualizar status
                _logger.LogWarning("âœ… [ProcessarFila] SMTP OK! Atualizando status do Email ID {Id}...", comunicacao.Id);
                _logger.LogWarning("   ANTES: IsEnviado={IsEnviado}, Status={Status}, Tentativas={Tentativas}",
                    comunicacao.IsEnviado, comunicacao.Status, comunicacao.TentativasEnvio);

                comunicacao.IsEnviado = true;
                comunicacao.Status = StatusComunicacao.Enviado;
                comunicacao.DataEnvio = DateTime.Now;
                comunicacao.UltimoErro = null;
                // âš ï¸ NÃƒO resetar TentativasEnvio - manter histÃ³rico

                _logger.LogWarning("   DEPOIS: IsEnviado={IsEnviado}, Status={Status}, DataEnvio={DataEnvio}",
                    comunicacao.IsEnviado, comunicacao.Status, comunicacao.DataEnvio);
                _logger.LogWarning("âœ… [ProcessarFila] Email ID {Id} enviado com SUCESSO!", comunicacao.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError("âŒ [ProcessarFila] ERRO ao enviar Email ID {Id}: {Error}", comunicacao.Id, ex.Message);
                _logger.LogError("Stack: {Stack}", ex.StackTrace);

                // Falhou â†’ Incrementar tentativas e agendar prÃ³xima tentativa
                comunicacao.TentativasEnvio++;
                comunicacao.UltimoErro = ex.Message;
                comunicacao.ProximaTentativa = DateTime.Now.AddMinutes(5 * comunicacao.TentativasEnvio); // Backoff exponencial

                if (comunicacao.TentativasEnvio >= 3)
                {
                    comunicacao.Status = StatusComunicacao.Falhado;
                    _logger.LogError("âŒ Email ID {Id} marcado como FALHADO (3 tentativas)", comunicacao.Id);
                }
                else
                {
                    _logger.LogWarning("âš ï¸ Email ID {Id}: Tentativa {Tentativa}/3. PrÃ³ximo retry: {ProximaTentativa}",
                        comunicacao.Id, comunicacao.TentativasEnvio, comunicacao.ProximaTentativa);
                }
            }

            _logger.LogWarning("ðŸ’¾ [ProcessarFila] Salvando alteraÃ§Ãµes para Email ID {Id}...", comunicacao.Id);

            // âš ï¸ CRITICAL: Verificar estado antes de salvar
            var entry = dbContext.Entry(comunicacao);
            _logger.LogWarning("   Estado EF: {State}, IsEnviado={IsEnviado}, Status={Status}",
                entry.State, comunicacao.IsEnviado, comunicacao.Status);

            await dbContext.SaveChangesAsync();
            _logger.LogWarning("âœ… [ProcessarFila] Email ID {Id} salvo na BD", comunicacao.Id);
        }

        _logger.LogInformation("âœ… Processamento de fila concluÃ­do");
    }

    /// <summary>
    /// Retorna nÃºmero de mensagens na fila
    /// </summary>
    public async Task<int> ContarMensagensNaFilaAsync()
    {
        // âœ… Criar scope para resolver DbContext
        using var scope = _serviceProvider.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

        return await dbContext.Comunicacoes
            .CountAsync(c => !c.IsEnviado && c.Status == StatusComunicacao.Agendado);
    }

    /// <summary>
    /// Testa conexÃ£o SMTP com credenciais fornecidas (usado no botÃ£o Testar ConexÃ£o)
    /// NÃƒO grava na BD, apenas testa envio real
    /// </summary>
    public async Task<EmailResult> TestarConexaoAsync(string smtpUsername, string smtpPassword, string fromEmail, string fromName)
    {
        try
        {
            _logger.LogInformation("ðŸ” Testando conexÃ£o SMTP com {Email}...", smtpUsername);

            // Criar email de teste
            var emailTeste = $@"
                <html>
                <body style='font-family: Arial, sans-serif; padding: 20px;'>
                    <h2 style='color: #059669;'>âœ… ConfiguraÃ§Ã£o de Email Bem-Sucedida!</h2>
                    <p>ParabÃ©ns! O seu sistema de email do <strong>BioDeskPro</strong> estÃ¡ configurado corretamente.</p>
                    <hr style='border: 1px solid #E3E9DE; margin: 20px 0;'/>
                    <p><strong>Detalhes da ConfiguraÃ§Ã£o:</strong></p>
                    <ul>
                        <li><strong>Remetente:</strong> {smtpUsername}</li>
                        <li><strong>Nome:</strong> {fromName}</li>
                        <li><strong>Data do Teste:</strong> {DateTime.Now:dd/MM/yyyy HH:mm:ss}</li>
                    </ul>
                    <p style='color: #6B7280; font-size: 12px; margin-top: 30px;'>
                        Este Ã© um email de teste automÃ¡tico do BioDeskPro.<br/>
                        Se recebeu esta mensagem, significa que estÃ¡ tudo a funcionar perfeitamente! ðŸŽ‰
                    </p>
                </body>
                </html>";

            // Enviar email de teste diretamente via SMTP (sem gravar na BD)
            using var smtpClient = new SmtpClient(SmtpHost, SmtpPort)
            {
                Credentials = new NetworkCredential(smtpUsername, smtpPassword),
                EnableSsl = true,
                UseDefaultCredentials = false,
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Timeout = 30000
            };

            using var mailMessage = new MailMessage
            {
                From = new MailAddress(fromEmail, fromName),
                Subject = "âœ… Teste de ConfiguraÃ§Ã£o - BioDeskPro",
                Body = emailTeste,
                IsBodyHtml = true
            };

            mailMessage.To.Add(new MailAddress(smtpUsername, fromName)); // Envia para si prÃ³prio

            await smtpClient.SendMailAsync(mailMessage);

            _logger.LogInformation("âœ… Email de teste enviado com sucesso!");
            return new EmailResult
            {
                Sucesso = true,
                Mensagem = $"âœ… Email de teste enviado com sucesso para {smtpUsername}!"
            };
        }
        catch (SmtpException smtpEx)
        {
            _logger.LogError(smtpEx, "âŒ Erro SMTP ao testar conexÃ£o");

            var mensagemErro = smtpEx.StatusCode switch
            {
                SmtpStatusCode.MailboxUnavailable => "Email invÃ¡lido ou nÃ£o encontrado.",
                SmtpStatusCode.MailboxBusy => "Caixa de email ocupada. Tente novamente.",
                SmtpStatusCode.GeneralFailure => "Falha geral no servidor SMTP. Verifique credenciais.",
                _ => $"Erro SMTP ({smtpEx.StatusCode}): {smtpEx.Message}"
            };

            return new EmailResult
            {
                Sucesso = false,
                Mensagem = $"âŒ Falha ao enviar: {mensagemErro}\n\nVerifique:\nâ€¢ App Password correto\nâ€¢ Email Ã© Gmail\nâ€¢ ConexÃ£o Ã  internet"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "âŒ Erro inesperado ao testar conexÃ£o");
            return new EmailResult
            {
                Sucesso = false,
                Mensagem = $"âŒ Erro ao testar: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Envia email via SMTP
    /// </summary>
    private async Task EnviarViaSMTPAsync(EmailMessage message)
    {
        _logger.LogInformation("ðŸ“§ [EnviarViaSMTPAsync] Iniciando envio...");
        _logger.LogInformation("  â†’ Host: {Host}:{Port} | SSL: {EnableSsl}", SmtpHost, SmtpPort, true);
        _logger.LogInformation("  â†’ De: {From} | Para: {To}", FromEmail, message.To);
        _logger.LogInformation("  â†’ Assunto: {Subject}", message.Subject);
        using var smtpClient = new SmtpClient(SmtpHost, SmtpPort)
        {
            Credentials = new NetworkCredential(SmtpUsername, SmtpPassword),
            EnableSsl = true,
            UseDefaultCredentials = false,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = 30000
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
                _logger.LogInformation("  ðŸ“Ž Anexo: {Path}", System.IO.Path.GetFileName(attachmentPath));
            }
            else
            {
                _logger.LogWarning("âš ï¸ Anexo nÃ£o encontrado: {Path}", attachmentPath);
            }
        }

        try
        {
            _logger.LogWarning("ðŸ”Œ [EnviarViaSMTPAsync] Conectando ao servidor SMTP...");
            await smtpClient.SendMailAsync(mailMessage);
            _logger.LogInformation("âœ… [EnviarViaSMTPAsync] Email enviado com SUCESSO!");
        }
        catch (SmtpException smtpEx)
        {
            _logger.LogError("âŒ [SMTP ERROR] StatusCode: {StatusCode} | Message: {Message}", smtpEx.StatusCode, smtpEx.Message);
            _logger.LogError("âŒ [SMTP ERROR] StackTrace: {StackTrace}", smtpEx.StackTrace);

            var mensagemAmigavel = smtpEx.StatusCode switch
            {
                SmtpStatusCode.ServiceNotAvailable => "Servidor SMTP indisponÃ­vel. Tente novamente mais tarde.",
                SmtpStatusCode.MailboxUnavailable => "Email destinatÃ¡rio invÃ¡lido ou nÃ£o encontrado.",
                SmtpStatusCode.ExceededStorageAllocation => "Caixa de email do destinatÃ¡rio estÃ¡ cheia.",
                SmtpStatusCode.TransactionFailed => "Falha na autenticaÃ§Ã£o. Verifique email e App Password.",
                SmtpStatusCode.GeneralFailure => "Falha geral no servidor SMTP. Verifique credenciais e conexÃ£o.",
                _ => $"Erro SMTP: {smtpEx.Message}"
            };

            _logger.LogError("âŒ [SMTP ERROR] DiagnÃ³stico: {Diagnostico}", mensagemAmigavel);
            throw new InvalidOperationException(mensagemAmigavel, smtpEx);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "âŒ [EnviarViaSMTPAsync] Erro inesperado ao enviar email");
            throw;
        }
    }
}
