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
/// </summary>
public class EmailService : IEmailService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailService> _logger;

    // Configurações SMTP dinâmicas (lidas do IConfiguration/User Secrets)
    private string SmtpHost => "smtp.gmail.com";
    private int SmtpPort => 587;
    private string SmtpUsername => _configuration["Email:Sender"] ?? throw new InvalidOperationException("Email:Sender não configurado. Use o botão Configurações.");
    private string SmtpPassword => _configuration["Email:Password"] ?? throw new InvalidOperationException("Email:Password não configurado. Use o botão Configurações.");
    private string FromEmail => _configuration["Email:Sender"] ?? throw new InvalidOperationException("Email:Sender não configurado.");
    private string FromName => _configuration["Email:SenderName"] ?? "BioDeskPro - Terapias Naturais";

    public EmailService(IServiceProvider serviceProvider, IConfiguration configuration, ILogger<EmailService> logger)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
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
    /// ⚡ CORREÇÃO CRÍTICA: Envia email IMEDIATAMENTE ou falha com exceção clara
    /// NÃO silencia erros - se falhar, LANÇA EXCEÇÃO para ViewModel tratar
    /// </summary>
    public async Task<EmailResult> EnviarAsync(EmailMessage message)
    {
        _logger.LogInformation("📧 Tentando enviar email IMEDIATO para {To}: {Subject}", message.To, message.Subject);

        // ⚠️ Verificar conexão
        if (!TemConexao)
        {
            _logger.LogWarning("⚠️ Sem conexão com internet.");
            return new EmailResult
            {
                Sucesso = false,
                AdicionadoNaFila = true,
                Mensagem = "Sem conexão à internet. Email ficará agendado para envio automático."
            };
        }

        // ⚡ Tentar enviar IMEDIATAMENTE
        try
        {
            await EnviarViaSMTPAsync(message);
            _logger.LogInformation("✅ Email enviado IMEDIATAMENTE para {To}", message.To);

            return new EmailResult
            {
                Sucesso = true,
                Mensagem = "✅ Email enviado com sucesso!"
            };
        }
        catch (Exception ex)
        {
            // ❌ CRÍTICO: NÃO SILENCIAR - Lançar exceção para ViewModel saber que falhou
            _logger.LogError(ex, "❌ ERRO ao enviar email para {To}: {Message}", message.To, ex.Message);

            // Retornar falha COM mensagem clara
            return new EmailResult
            {
                Sucesso = false,
                AdicionadoNaFila = false, // ⚠️ NÃO foi adicionado à fila - está na BD como Agendado
                Mensagem = $"❌ Erro ao enviar: {ex.Message}"
            };
        }
    }

    /// <summary>
    /// Processa fila de mensagens pendentes
    /// </summary>
    public async Task ProcessarFilaAsync()
    {
        _logger.LogWarning("🔍 [ProcessarFila] INICIANDO verificação...");

        if (!TemConexao)
        {
            _logger.LogWarning("⚠️ [ProcessarFila] Sem conexão. Fila não processada.");
            return;
        }

        _logger.LogWarning("✅ [ProcessarFila] Conexão OK. Buscando emails agendados...");

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

        _logger.LogWarning("📬 [ProcessarFila] Encontrei {Count} mensagens na fila", mensagensNaFila.Count);

        foreach (var msg in mensagensNaFila)
        {
            _logger.LogWarning("  → Email ID {Id}: {Assunto} (Tentativas: {Tentativas})",
                msg.Id, msg.Assunto, msg.TentativasEnvio);
        }

        foreach (var comunicacao in mensagensNaFila)
        {
            _logger.LogWarning("🔧 [ProcessarFila] Tentando enviar Email ID {Id}...", comunicacao.Id);

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

                _logger.LogWarning("📧 [ProcessarFila] Enviando via SMTP para {To}...", comunicacao.Destinatario);

                // Tentar enviar
                await EnviarViaSMTPAsync(emailMessage);

                // ✅ SUCESSO → Atualizar status
                _logger.LogWarning("✅ [ProcessarFila] SMTP OK! Atualizando status do Email ID {Id}...", comunicacao.Id);
                _logger.LogWarning("   ANTES: IsEnviado={IsEnviado}, Status={Status}, Tentativas={Tentativas}",
                    comunicacao.IsEnviado, comunicacao.Status, comunicacao.TentativasEnvio);

                comunicacao.IsEnviado = true;
                comunicacao.Status = StatusComunicacao.Enviado;
                comunicacao.DataEnvio = DateTime.Now;
                comunicacao.UltimoErro = null;
                // ⚠️ NÃO resetar TentativasEnvio - manter histórico

                _logger.LogWarning("   DEPOIS: IsEnviado={IsEnviado}, Status={Status}, DataEnvio={DataEnvio}",
                    comunicacao.IsEnviado, comunicacao.Status, comunicacao.DataEnvio);
                _logger.LogWarning("✅ [ProcessarFila] Email ID {Id} enviado com SUCESSO!", comunicacao.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError("❌ [ProcessarFila] ERRO ao enviar Email ID {Id}: {Error}", comunicacao.Id, ex.Message);
                _logger.LogError("Stack: {Stack}", ex.StackTrace);

                // Falhou → Incrementar tentativas e agendar próxima tentativa
                comunicacao.TentativasEnvio++;
                comunicacao.UltimoErro = ex.Message;
                comunicacao.ProximaTentativa = DateTime.Now.AddMinutes(5 * comunicacao.TentativasEnvio); // Backoff exponencial

                if (comunicacao.TentativasEnvio >= 3)
                {
                    comunicacao.Status = StatusComunicacao.Falhado;
                    _logger.LogError("❌ Email ID {Id} marcado como FALHADO (3 tentativas)", comunicacao.Id);
                }
                else
                {
                    _logger.LogWarning("⚠️ Email ID {Id}: Tentativa {Tentativa}/3. Próximo retry: {ProximaTentativa}",
                        comunicacao.Id, comunicacao.TentativasEnvio, comunicacao.ProximaTentativa);
                }
            }

            _logger.LogWarning("💾 [ProcessarFila] Salvando alterações para Email ID {Id}...", comunicacao.Id);

            // ⚠️ CRITICAL: Verificar estado antes de salvar
            var entry = dbContext.Entry(comunicacao);
            _logger.LogWarning("   Estado EF: {State}, IsEnviado={IsEnviado}, Status={Status}",
                entry.State, comunicacao.IsEnviado, comunicacao.Status);

            await dbContext.SaveChangesAsync();
            _logger.LogWarning("✅ [ProcessarFila] Email ID {Id} salvo na BD", comunicacao.Id);
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
    /// Testa conexão SMTP com credenciais fornecidas (usado no botão Testar Conexão)
    /// NÃO grava na BD, apenas testa envio real
    /// </summary>
    public async Task<EmailResult> TestarConexaoAsync(string smtpUsername, string smtpPassword, string fromEmail, string fromName)
    {
        try
        {
            _logger.LogInformation("🔍 Testando conexão SMTP com {Email}...", smtpUsername);

            // Criar email de teste
            var emailTeste = $@"
                <html>
                <body style='font-family: Arial, sans-serif; padding: 20px;'>
                    <h2 style='color: #059669;'>✅ Configuração de Email Bem-Sucedida!</h2>
                    <p>Parabéns! O seu sistema de email do <strong>BioDeskPro</strong> está configurado corretamente.</p>
                    <hr style='border: 1px solid #E3E9DE; margin: 20px 0;'/>
                    <p><strong>Detalhes da Configuração:</strong></p>
                    <ul>
                        <li><strong>Remetente:</strong> {smtpUsername}</li>
                        <li><strong>Nome:</strong> {fromName}</li>
                        <li><strong>Data do Teste:</strong> {DateTime.Now:dd/MM/yyyy HH:mm:ss}</li>
                    </ul>
                    <p style='color: #6B7280; font-size: 12px; margin-top: 30px;'>
                        Este é um email de teste automático do BioDeskPro.<br/>
                        Se recebeu esta mensagem, significa que está tudo a funcionar perfeitamente! 🎉
                    </p>
                </body>
                </html>";

            // Enviar email de teste diretamente via SMTP (sem gravar na BD)
            using var smtpClient = new SmtpClient(SmtpHost, SmtpPort)
            {
                Credentials = new NetworkCredential(smtpUsername, smtpPassword),
                EnableSsl = true,
                Timeout = 30000 // 30 segundos
            };

            using var mailMessage = new MailMessage
            {
                From = new MailAddress(fromEmail, fromName),
                Subject = "✅ Teste de Configuração - BioDeskPro",
                Body = emailTeste,
                IsBodyHtml = true
            };

            mailMessage.To.Add(new MailAddress(smtpUsername, fromName)); // Envia para si próprio

            await smtpClient.SendMailAsync(mailMessage);

            _logger.LogInformation("✅ Email de teste enviado com sucesso!");
            return new EmailResult
            {
                Sucesso = true,
                Mensagem = $"✅ Email de teste enviado com sucesso para {smtpUsername}!"
            };
        }
        catch (SmtpException smtpEx)
        {
            _logger.LogError(smtpEx, "❌ Erro SMTP ao testar conexão");

            var mensagemErro = smtpEx.StatusCode switch
            {
                SmtpStatusCode.MailboxUnavailable => "Email inválido ou não encontrado.",
                SmtpStatusCode.MailboxBusy => "Caixa de email ocupada. Tente novamente.",
                SmtpStatusCode.GeneralFailure => "Falha geral no servidor SMTP. Verifique credenciais.",
                _ => $"Erro SMTP ({smtpEx.StatusCode}): {smtpEx.Message}"
            };

            return new EmailResult
            {
                Sucesso = false,
                Mensagem = $"❌ Falha ao enviar: {mensagemErro}\n\nVerifique:\n• App Password correto\n• Email é Gmail\n• Conexão à internet"
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro inesperado ao testar conexão");
            return new EmailResult
            {
                Sucesso = false,
                Mensagem = $"❌ Erro ao testar: {ex.Message}"
            };
        }
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
