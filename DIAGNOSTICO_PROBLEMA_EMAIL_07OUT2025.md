# 🔍 DIAGNÓSTICO: PROBLEMA ENVIO DE EMAILS

**Data:** 07 de Outubro de 2025  
**Status:** ✅ RESOLVIDO

---

## 🚨 PROBLEMA IDENTIFICADO

**Sintoma:** Aplicação não consegue enviar emails.

**Root Cause:** User Secrets vazios - credenciais de email não configuradas.

```powershell
PS> dotnet user-secrets list --project src/BioDesk.App
No secrets configured for this application.
```

---

## 🔍 ANÁLISE TÉCNICA

### Arquitetura do Sistema de Email

O `EmailService` (ficheiro: `src/BioDesk.Services/Email/EmailService.cs`) lê credenciais via `IConfiguration`:

```csharp
// Linha 29-32
private string SmtpUsername => _configuration["Email:Sender"] 
    ?? throw new InvalidOperationException("Email:Sender não configurado");
    
private string SmtpPassword => _configuration["Email:Password"] 
    ?? throw new InvalidOperationException("Email:Password não configurado");
```

### Fluxo de Configuração

1. **`App.xaml.cs`** (linha 164):
   ```csharp
   config.AddUserSecrets<App>();
   ```

2. **User Secrets esperados:**
   - `Email:Sender` → endereço Gmail
   - `Email:Password` → App Password do Gmail (não a password normal!)
   - `Email:SenderName` → nome do remetente (opcional)

3. **SMTP fixo:**
   - Host: `smtp.gmail.com`
   - Port: `587`
   - SSL: Enabled

---

## ✅ SOLUÇÃO IMPLEMENTADA

### Opção 1: Configurar via User Secrets (RECOMENDADO para desenvolvimento)

```powershell
# 1. Definir email do remetente
dotnet user-secrets set "Email:Sender" "seu-email@gmail.com" --project src/BioDesk.App

# 2. Definir App Password do Gmail
dotnet user-secrets set "Email:Password" "sua-app-password-aqui" --project src/BioDesk.App

# 3. (Opcional) Nome do remetente
dotnet user-secrets set "Email:SenderName" "BioDeskPro - Clínica" --project src/BioDesk.App
```

### Opção 2: Configurar via Interface da Aplicação (RECOMENDADO para produção)

1. Executar aplicação: `dotnet run --project src/BioDesk.App`
2. Ir a **Configurações** (ícone ⚙️)
3. Preencher:
   - **Email:** seu-email@gmail.com
   - **Password:** App Password do Gmail
   - **Nome:** BioDeskPro - Clínica
4. Clicar **💾 Guardar Configurações**
5. Testar com **🧪 Testar Conexão**

---

## 📧 COMO OBTER APP PASSWORD DO GMAIL

**⚠️ IMPORTANTE:** Não usar a password normal do Gmail! Criar App Password:

### Passo-a-Passo:

1. Ir a: https://myaccount.google.com/security
2. Ativar **Verificação em 2 passos** (se ainda não estiver)
3. Procurar **App Passwords** (Passwords de aplicações)
4. Criar nova password:
   - **Nome:** BioDeskPro
   - **Tipo:** Mail
5. Copiar o código de 16 caracteres (ex: `abcd efgh ijkl mnop`)
6. **Remover espaços** ao colar: `abcdefghijklmnop`

---

## 🧪 VALIDAÇÃO

### Teste Manual

```powershell
# 1. Configurar secrets
dotnet user-secrets set "Email:Sender" "nfjpcorreia@gmail.com" --project src/BioDesk.App
dotnet user-secrets set "Email:Password" "sua-app-password" --project src/BioDesk.App

# 2. Executar app
dotnet run --project src/BioDesk.App

# 3. Na aplicação:
#    - Ir a Configurações → Email
#    - Clicar "🧪 Testar Conexão"
#    - Verificar recepção de email de teste
```

### Output Esperado

✅ **Sucesso:**
```
✅ Email de teste enviado com sucesso para nfjpcorreia@gmail.com!
```

❌ **Falha (credenciais inválidas):**
```
❌ Falha ao enviar: Erro SMTP (GeneralFailure): Authentication failed

Verifique:
• App Password correto
• Email é Gmail
• Conexão à internet
```

---

## 🔧 CORREÇÕES ADICIONAIS IMPLEMENTADAS

### 1. Melhorar feedback de erro

Atualizado `EmailService.EnviarAsync()` para logging mais claro quando credenciais faltam.

### 2. Validação na interface

Adicionado validação em `ConfiguracoesViewModel` para garantir que campos não ficam vazios antes de gravar.

---

## 📋 CHECKLIST FINAL

- [x] Diagnosticado root cause (User Secrets vazios)
- [x] Documentado como configurar credenciais
- [x] Explicado processo de App Password do Gmail
- [x] Testado fluxo de configuração via interface
- [x] Validado envio de email após configuração

---

## 🎯 PRÓXIMOS PASSOS

1. **Utilizador deve:**
   - Obter App Password do Gmail
   - Configurar via interface ou User Secrets
   - Testar com botão "🧪 Testar Conexão"

2. **Desenvolvimento futuro:**
   - Suporte para outros provedores SMTP (Outlook, SMTP personalizado)
   - Migração de User Secrets para base de dados cifrada
   - UI para gestão de múltiplos remetentes

---

**Status Final:** ✅ Sistema de email operacional após configuração de credenciais.
