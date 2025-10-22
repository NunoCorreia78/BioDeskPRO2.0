# 🚨 CORREÇÃO CRÍTICA - Email não está a ser enviado (22/OUT/2025)

## ❌ ROOT CAUSE IDENTIFICADO

**Local:** `src/BioDesk.ViewModels/Abas/ComunicacaoViewModel.cs` (linha ~475)

### O BUG:

```csharp
// ❌ CÓDIGO ATUAL (ERRADO):
var resultado = await _emailService.EnviarAsync(emailMessage);

// Grava na BD SEMPRE, mesmo quando falha por erro SMTP
var comunicacao = new Comunicacao {
    Status = resultado.Sucesso ? StatusComunicacao.Enviado : StatusComunicacao.Agendado,
    ProximaTentativa = resultado.Sucesso ? null : DateTime.Now.AddMinutes(2),
    // ❌ PROBLEMA: Email que falhou por SMTP fica "Agendado" na fila!
};
```

### POR QUE ESTÁ ERRADO:

1. Utilizador clica "Enviar Email"
2. `EmailService.EnviarAsync()` tenta enviar via SMTP
3. **SMTP FALHA** (credenciais erradas, servidor offline, etc.)
4. `resultado.Sucesso = false`, `resultado.AdicionadoNaFila = false`
5. ViewModel grava na BD com `Status = Agendado` + `ProximaTentativa = NOW + 2 min`
6. ❌ **Email fica na fila de retry, MAS NÃO DEVIA!**

**Comportamento esperado:** Se falhou por erro SMTP → Mostrar erro na UI e **NÃO** gravar na BD.

---

## ✅ CORREÇÃO (APLICAR MANUALMENTE)

**Ficheiro:** `src/BioDesk.ViewModels/Abas/ComunicacaoViewModel.cs`
**Método:** `EnviarEmailAsync()` (linha ~445)

### Substituir de:

```csharp
var resultado = await _emailService.EnviarAsync(emailMessage);

// Usar scope isolado para DbContext
using var scope2 = _scopeFactory.CreateScope();
var dbContext2 = scope2.ServiceProvider.GetRequiredService<BioDeskDbContext>();

// Criar comunicação na DB com STATUS CORRETO desde o início
var comunicacao = new Comunicacao
{
    PacienteId = PacienteAtual.Id,
    // ... (resto do código)
    Status = resultado.Sucesso ? StatusComunicacao.Enviado : StatusComunicacao.Agendado,
    IsEnviado = resultado.Sucesso,
    DataEnvio = resultado.Sucesso ? DateTime.Now : null,
    ProximaTentativa = resultado.Sucesso ? null : DateTime.Now.AddMinutes(2),
    TentativasEnvio = resultado.Sucesso ? 0 : 1,
    UltimoErro = resultado.Sucesso ? null : resultado.Mensagem
};

await dbContext2.Comunicacoes.AddAsync(comunicacao);
await dbContext2.SaveChangesAsync();

// Mensagem de feedback
if (resultado.Sucesso) {
    SuccessMessage = "✅ Email enviado com sucesso!";
} else {
    if (resultado.AdicionadoNaFila) {
        SuccessMessage = "⚠️ Sem conexão. Email agendado para envio automático.";
    } else {
        SuccessMessage = "⚠️ Erro ao enviar. Email agendado para retry em 2 minutos.";
    }
}
```

### Para (CÓDIGO CORRETO):

```csharp
_logger.LogWarning("📧 [ComunicacaoViewModel] Tentando enviar email IMEDIATO para {Email}...", Destinatario);

var resultado = await _emailService.EnviarAsync(emailMessage);

// ✅ CORREÇÃO CRÍTICA: Só grava na BD se ENVIOU COM SUCESSO ou se está SEM INTERNET
// Se falhou por erro SMTP → NÃO gravar na BD (mostrar erro e parar)

if (!resultado.Sucesso && !resultado.AdicionadoNaFila)
{
    // ❌ ERRO SMTP (autenticação, credenciais, etc.) - NÃO AGENDAR!
    ErrorMessage = resultado.Mensagem ?? "Erro desconhecido ao enviar email.";
    _logger.LogError("❌ Email FALHOU e NÃO foi agendado: {Erro}", resultado.Mensagem);
    IsLoading = false;
    return; // ⚠️ PARAR AQUI - Não gravar na BD
}

// ✅ Se chegou aqui: ou enviou com sucesso OU está sem internet (agendado)

// Usar scope isolado para DbContext
using var scope2 = _scopeFactory.CreateScope();
var dbContext2 = scope2.ServiceProvider.GetRequiredService<BioDeskDbContext>();

// Criar comunicação na DB com STATUS CORRETO desde o início
var comunicacao = new Comunicacao
{
    PacienteId = PacienteAtual.Id,
    Tipo = TipoSelecionado,
    Destinatario = Destinatario,
    Assunto = Assunto,
    Corpo = Corpo,
    TemplateUtilizado = TemplateSelecionado,
    Status = resultado.Sucesso ? StatusComunicacao.Enviado : StatusComunicacao.Agendado,
    IsEnviado = resultado.Sucesso,
    DataCriacao = DateTime.Now,
    DataEnvio = resultado.Sucesso ? DateTime.Now : null,
    ProximaTentativa = resultado.Sucesso ? null : DateTime.Now.AddMinutes(2), // Só se sem internet
    TentativasEnvio = resultado.Sucesso ? 0 : 1,
    UltimoErro = resultado.Sucesso ? null : "Sem conexão à internet" // ⚡ Mensagem clara
};

await dbContext2.Comunicacoes.AddAsync(comunicacao);
await dbContext2.SaveChangesAsync();

// Gravar anexos (código igual)
foreach (var caminhoFicheiro in Anexos)
{
    var anexo = new AnexoComunicacao { /* ... */ };
    await dbContext2.Set<AnexoComunicacao>().AddAsync(anexo);
}

if (Anexos.Any())
{
    await dbContext2.SaveChangesAsync();
}

// ✅ Mensagem de feedback conforme resultado
if (resultado.Sucesso)
{
    SuccessMessage = "✅ Email enviado com sucesso!";
    _logger.LogInformation("✅ Email ID {Id} enviado IMEDIATAMENTE (Status={Status})", comunicacao.Id, comunicacao.Status);
}
else if (resultado.AdicionadoNaFila)
{
    // Sem internet → Agendado para retry automático
    SuccessMessage = "⚠️ Sem conexão. Email agendado para envio automático quando houver internet.";
    _logger.LogWarning("⚠️ Email ID {Id} agendado (sem rede, Status={Status})", comunicacao.Id, comunicacao.Status);
}
```

---

## 📋 DIFERENÇAS-CHAVE:

### ANTES (BUG):
- ❌ Grava na BD **SEMPRE** (sucesso ou falha)
- ❌ Email com erro SMTP fica `Status = Agendado`
- ❌ `EmailQueueProcessor` tenta reenviar infinitamente
- ❌ Utilizador vê "Email agendado para retry" (mentira!)

### DEPOIS (CORRETO):
- ✅ **NÃO** grava na BD se falhou por erro SMTP
- ✅ Mostra `ErrorMessage` clara na UI
- ✅ Só agenda se **sem internet** (`AdicionadoNaFila = true`)
- ✅ Utilizador vê erro real e pode corrigir credenciais

---

## 🧪 COMO TESTAR:

### Cenário 1: Credenciais Erradas (SMTP Fail)
1. Configurações → Email → Colocar password errada
2. Tentar enviar email
3. **Esperado:** ❌ Erro "Falha na autenticação. Verifique email e App Password."
4. **Verificar:** Email **NÃO** aparece no histórico (não foi gravado)

### Cenário 2: Sem Internet
1. Desligar WiFi
2. Tentar enviar email
3. **Esperado:** ⚠️ "Sem conexão. Email agendado para envio automático..."
4. **Verificar:** Email aparece no histórico com `Status = Agendado`
5. Religar internet → Após 30s, `EmailQueueProcessor` envia automaticamente

### Cenário 3: Tudo OK
1. Credenciais corretas + Internet ativa
2. Enviar email
3. **Esperado:** ✅ "Email enviado com sucesso!"
4. **Verificar:** Email aparece no histórico com `Status = Enviado`

---

## 🔧 CORREÇÕES ADICIONAIS NECESSÁRIAS (EmailService)

**Ficheiro:** `src/BioDesk.Services/Email/EmailService.cs`

### 1. Validar credenciais vazias (linha ~28):

```csharp
// ❌ ATUAL:
private string SmtpUsername =>
    _configuration["Email:Sender"] ??
    _configuration["Email:FromEmail"] ??
    throw new InvalidOperationException("Email:Sender não configurado.");

// ✅ CORRETO:
private string SmtpUsername
{
    get
    {
        var sender = _configuration["Email:Sender"] ?? _configuration["Email:FromEmail"];
        if (string.IsNullOrWhiteSpace(sender))
        {
            throw new InvalidOperationException(
                "❌ Email:Sender não configurado ou vazio. " +
                "Use Configurações → Email para definir credenciais.");
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
            throw new InvalidOperationException(
                "❌ Email:Password não configurado ou vazio. " +
                "Use Configurações → Email para definir App Password do Gmail.");
        }
        return password;
    }
}
```

### 2. Logging detalhado em EnviarViaSMTPAsync() (linha ~352):

```csharp
private async Task EnviarViaSMTPAsync(EmailMessage message)
{
    _logger.LogInformation("📧 [EnviarViaSMTPAsync] Iniciando envio...");
    _logger.LogInformation("  → Host: {Host}:{Port} | SSL: {EnableSsl}", SmtpHost, SmtpPort, true);
    _logger.LogInformation("  → De: {From} | Para: {To}", FromEmail, message.To);

    using var smtpClient = new SmtpClient(SmtpHost, SmtpPort)
    {
        Credentials = new NetworkCredential(SmtpUsername, SmtpPassword),
        EnableSsl = true,
        UseDefaultCredentials = false,      // ✅ ADICIONAR
        DeliveryMethod = SmtpDeliveryMethod.Network, // ✅ ADICIONAR
        Timeout = 30000 // 30 segundos       // ✅ ADICIONAR
    };

    // ... (criar mailMessage)

    try
    {
        _logger.LogWarning("🔌 [EnviarViaSMTPAsync] Conectando ao servidor SMTP...");
        await smtpClient.SendMailAsync(mailMessage);
        _logger.LogInformation("✅ [EnviarViaSMTPAsync] Email enviado com SUCESSO!");
    }
    catch (SmtpException smtpEx)
    {
        _logger.LogError("❌ [SMTP ERROR] StatusCode: {StatusCode} | Message: {Message}",
            smtpEx.StatusCode, smtpEx.Message);

        // Mensagem amigável baseada no código de erro
        var mensagemAmigavel = smtpEx.StatusCode switch
        {
            SmtpStatusCode.ServiceNotAvailable => "Servidor SMTP indisponível. Tente novamente mais tarde.",
            SmtpStatusCode.MailboxUnavailable => "Email destinatário inválido ou não encontrado.",
            SmtpStatusCode.TransactionFailed => "Falha na autenticação. Verifique email e App Password.",
            SmtpStatusCode.GeneralFailure => "Falha geral no servidor SMTP. Verifique credenciais e conexão.",
            _ => $"Erro SMTP: {smtpEx.Message}"
        };

        _logger.LogError("❌ [SMTP ERROR] Diagnóstico: {Diagnostico}", mensagemAmigavel);
        throw new InvalidOperationException(mensagemAmigavel, smtpEx);
    }
}
```

---

## ✅ CHECKLIST PÓS-CORREÇÃO:

- [ ] Aplicar correção em `ComunicacaoViewModel.cs` (linha ~445)
- [ ] Aplicar validação de strings vazias em `EmailService.cs` (linha ~28)
- [ ] Aplicar logging detalhado em `EmailService.cs` (linha ~352)
- [ ] Compilar: `dotnet build`
- [ ] Testar Cenário 1 (credenciais erradas)
- [ ] Testar Cenário 2 (sem internet)
- [ ] Testar Cenário 3 (tudo OK)
- [ ] Verificar logs em `Logs/biodesk-YYYYMMDD.log`
- [ ] Confirmar que emails falhados **NÃO** aparecem como "Agendados"

---

## 📊 IMPACTO DA CORREÇÃO:

- **Antes:** Emails com erro SMTP ficavam infinitamente na fila de retry → `EmailQueueProcessor` tentava reenviar a cada 30s → BD cheia de emails "Agendados" que nunca seriam enviados
- **Depois:** Emails com erro SMTP **NÃO** são gravados → Utilizador vê erro claro → Pode corrigir credenciais e tentar novamente

---

**Data:** 22 de Outubro de 2025
**Autor:** GitHub Copilot (auditoria aprofundada)
**Prioridade:** 🔴 CRÍTICA - Aplicar IMEDIATAMENTE
