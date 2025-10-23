$ProjectPath = $env:PROJECT_PATH
# If $ProjectPath not set, fallback to repository root
if (-not $ProjectPath) { $ProjectPath = "D:\\BioDeskPro2" }
$filePath = Join-Path $ProjectPath "src\BioDesk.Services\Email\EmailService.cs"
$content = Get-Content $filePath -Raw -Encoding UTF8

# Substituir método EnviarViaSMTPAsync
$pattern = '(?s)(\s+/// <summary>\s+/// Envia email via SMTP\s+/// </summary>\s+private async Task EnviarViaSMTPAsync\(EmailMessage message\)\s+\{.*?)await smtpClient\.SendMailAsync\(mailMessage\);\s+\}'

$replacement = @'
$1try
        {
            _logger.LogWarning("🔌 [EnviarViaSMTPAsync] Conectando ao servidor SMTP...");
            await smtpClient.SendMailAsync(mailMessage);
            _logger.LogInformation("✅ [EnviarViaSMTPAsync] Email enviado com SUCESSO!");
        }
        catch (SmtpException smtpEx)
        {
            _logger.LogError("❌ [SMTP ERROR] StatusCode: {StatusCode} | Message: {Message}", smtpEx.StatusCode, smtpEx.Message);
            _logger.LogError("❌ [SMTP ERROR] StackTrace: {StackTrace}", smtpEx.StackTrace);

            var mensagemAmigavel = smtpEx.StatusCode switch
            {
                SmtpStatusCode.ServiceNotAvailable => "Servidor SMTP indisponível. Tente novamente mais tarde.",
                SmtpStatusCode.MailboxUnavailable => "Email destinatário inválido ou não encontrado.",
                SmtpStatusCode.ExceededStorageAllocation => "Caixa de email do destinatário está cheia.",
                SmtpStatusCode.TransactionFailed => "Falha na autenticação. Verifique email e App Password.",
                SmtpStatusCode.GeneralFailure => "Falha geral no servidor SMTP. Verifique credenciais e conexão.",
                _ => $"Erro SMTP: {smtpEx.Message}"
            };

            _logger.LogError("❌ [SMTP ERROR] Diagnóstico: {Diagnostico}", mensagemAmigavel);
            throw new InvalidOperationException(mensagemAmigavel, smtpEx);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ [EnviarViaSMTPAsync] Erro inesperado ao enviar email");
            throw;
        }
    }
'@

# Adicionar logging no início do método
$content = $content -replace '(private async Task EnviarViaSMTPAsync\(EmailMessage message\)\s+\{)', @'
$1
        _logger.LogInformation("📧 [EnviarViaSMTPAsync] Iniciando envio...");
        _logger.LogInformation("  → Host: {Host}:{Port} | SSL: {EnableSsl}", SmtpHost, SmtpPort, true);
        _logger.LogInformation("  → De: {From} | Para: {To}", FromEmail, message.To);
        _logger.LogInformation("  → Assunto: {Subject}", message.Subject);
'@

# Adicionar configurações robustas no SmtpClient
$content = $content -replace '(Credentials = new NetworkCredential\(SmtpUsername, SmtpPassword\),\s+EnableSsl = true)', @'
$1,
            UseDefaultCredentials = false,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = 30000
'@

# Adicionar logging para anexos
$content = $content -replace '(mailMessage\.Attachments\.Add\(attachment\);)', @'
$1
                _logger.LogInformation("  📎 Anexo: {Path}", System.IO.Path.GetFileName(attachmentPath));
'@

# Substituir await final por try-catch
$content = $content -replace $pattern, $replacement

Set-Content $filePath $content -Encoding UTF8 -NoNewline
Write-Host "✅ EmailService.cs atualizado com logging detalhado!"
