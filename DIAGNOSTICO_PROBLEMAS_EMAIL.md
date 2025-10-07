# 🔍 Diagnóstico de Problemas de E-mail - BioDeskPro2

**Data:** 07/10/2025  
**Versão:** 1.0  
**Autor:** GitHub Copilot

---

## 🎯 Problema Reportado

> "Porque razão deixei de conseguir enviar e-mails?"

---

## 📊 Análise do Sistema

### ✅ Sistema de E-mail ESTÁ Implementado e Funcional

O BioDeskPro2 tem um **sistema robusto de e-mail** já implementado:

- ✅ **EmailService** com suporte offline
- ✅ **EmailQueueProcessor** (retry automático a cada 30 segundos)
- ✅ **Integração com Gmail SMTP**
- ✅ **Sistema de anexos**
- ✅ **Histórico completo** (tabela `Comunicacoes`)
- ✅ **Gestão de erros** e logging detalhado

**Código relevante:**
- `src/BioDesk.Services/Email/EmailService.cs`
- `src/BioDesk.Services/Email/EmailQueueProcessor.cs`
- `src/BioDesk.ViewModels/Abas/ComunicacaoViewModel.cs`

---

## 🚨 Root Cause: User Secrets NÃO Configurados

### Sintoma

Ao tentar enviar e-mail, aparece erro:

```
❌ InvalidOperationException: Email:Sender não configurado. Use o botão Configurações.
```

### Causa

As **credenciais SMTP** (e-mail e password) são armazenadas em **User Secrets** por segurança.

**User Secrets NÃO vão para Git** (propositadamente), logo:
- ✅ Protege credenciais de serem expostas
- ❌ **Cada PC precisa configurar manualmente**

Se acabaste de:
- Reinstalar Windows
- Migrar para outro PC
- Clonar repositório novo
- Formatar disco

→ **User Secrets foram perdidos** e precisam ser reconfigurados!

---

## ✅ Solução: Configurar User Secrets

### Passo 1: Obter App Password do Gmail

**⚠️ IMPORTANTE:** NÃO uses a tua password normal do Gmail!

1. **Ativar Autenticação de 2 Fatores** (obrigatório)
   - Aceder: https://myaccount.google.com/security
   - Ativar "Verificação em 2 passos"

2. **Gerar App Password**
   - Aceder: https://myaccount.google.com/apppasswords
   - Selecionar "Outras (nome personalizado)"
   - Nome: `BioDeskPro2`
   - Clicar "Gerar"
   - **COPIAR o código de 16 caracteres** (ex: `abcd efgh ijkl mnop`)

---

### Passo 2: Configurar User Secrets (PowerShell)

Abre **PowerShell** ou **Terminal** e executa:

#### 2.1. Navegar para pasta do projeto

```powershell
cd "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2"
# OU o caminho onde tens o projeto
```

#### 2.2. Configurar E-mail

```powershell
dotnet user-secrets set "Email:Sender" "nunocorreiaterapiasnaturais@gmail.com" --project src/BioDesk.App
```

**Substitui pelo TEU e-mail do Gmail!**

#### 2.3. Configurar App Password

```powershell
dotnet user-secrets set "Email:Password" "abcd efgh ijkl mnop" --project src/BioDesk.App
```

**Substitui pelo App Password que copiaste no Passo 1!**

⚠️ Usa os **espaços** no código (Gmail aceita com ou sem espaços).

#### 2.4. Configurar Nome (opcional)

```powershell
dotnet user-secrets set "Email:SenderName" "Nuno Correia - Terapias Naturais" --project src/BioDesk.App
```

---

### Passo 3: Verificar Configuração

```powershell
dotnet user-secrets list --project src/BioDesk.App
```

**Output esperado:**
```
Email:Password = abcd efgh ijkl mnop
Email:Sender = nunocorreiaterapiasnaturais@gmail.com
Email:SenderName = Nuno Correia - Terapias Naturais
```

Se aparecer "No secrets configured for this application" → **repete Passo 2!**

---

### Passo 4: Testar na Aplicação

1. **Abrir BioDeskPro2**
2. Ir para **Configurações** (⚙️ menu lateral)
3. Secção "Configurações de E-mail"
4. Clicar **"🧪 Testar Conexão"**
5. **Esperado:**
   - ✅ "Conexão SMTP OK!"
   - E-mail de teste enviado para ti próprio

**Se falhar**, ver secção **Troubleshooting** abaixo.

---

## 🛠️ Troubleshooting Avançado

### Erro 1: "Authentication failed"

**Sintoma:**
```
SmtpException: 5.7.0 Authentication Required
```

**Causas possíveis:**

#### ❌ Causa 1.1: App Password inválido
- **Solução:** Gera novo App Password (https://myaccount.google.com/apppasswords)
- Atualiza User Secret:
  ```powershell
  dotnet user-secrets set "Email:Password" "NOVO_APP_PASSWORD" --project src/BioDesk.App
  ```

#### ❌ Causa 1.2: Autenticação 2FA desativada
- **Solução:** Ativa "Verificação em 2 passos" no Google
- Depois gera App Password (ver Passo 1)

#### ❌ Causa 1.3: Password normal (não App Password)
- **Solução:** **NUNCA uses a tua password normal do Gmail!**
- Usa apenas App Password de 16 caracteres

---

### Erro 2: "Email:Sender não configurado"

**Sintoma:**
```
InvalidOperationException: Email:Sender não configurado. Use o botão Configurações.
```

**Causa:** User Secrets não foram configurados OU caminho do projeto está errado.

**Soluções:**

#### ✅ Solução 2.1: Verificar caminho
```powershell
# Confirma que estás na pasta RAIZ do projeto (onde está biodesk.db)
pwd
# Output esperado: C:\Users\...\BioDeskPro2 (ou BioDeskPRO2.0)
```

#### ✅ Solução 2.2: Re-executar comandos
```powershell
# COPIA E COLA linha a linha:
dotnet user-secrets set "Email:Sender" "seuemail@gmail.com" --project src/BioDesk.App
dotnet user-secrets set "Email:Password" "APP_PASSWORD_16_CHARS" --project src/BioDesk.App
dotnet user-secrets set "Email:SenderName" "Seu Nome" --project src/BioDesk.App
```

#### ✅ Solução 2.3: Verificar
```powershell
dotnet user-secrets list --project src/BioDesk.App
# Deve mostrar as 3 secrets
```

---

### Erro 3: E-mails ficam "Agendados" indefinidamente

**Sintoma:**
- E-mail fica com status "Agendado" ⏰
- Nunca muda para "Enviado" ✅

**Causas possíveis:**

#### ❌ Causa 3.1: Sem conexão à internet
- **Diagnóstico:** Ícone Wi-Fi desligado ou Ethernet desconectada
- **Solução:** Ligar Wi-Fi/Ethernet
- **Resultado:** EmailQueueProcessor enviará automaticamente em 30 segundos

#### ❌ Causa 3.2: Credenciais inválidas (mesmo com rede)
- **Diagnóstico:**
  1. Ir para Configurações → "🧪 Testar Conexão"
  2. Se falhar → Credenciais erradas
- **Solução:** Reconfigurar User Secrets (ver Passo 2)

#### ❌ Causa 3.3: Servidor Gmail temporariamente indisponível (raro)
- **Diagnóstico:** Testar enviar e-mail via Gmail web (funciona?)
- **Solução:** Aguardar 5-10 minutos, sistema fará retry automático

---

### Erro 4: "No secrets configured for this application"

**Sintoma:**
```powershell
dotnet user-secrets list --project src/BioDesk.App
# Output: No secrets configured for this application.
```

**Causa:** Projeto `BioDesk.App` não tem `UserSecretsId` definido.

**Solução:**

#### ✅ Verificar UserSecretsId no .csproj
```powershell
cat src/BioDesk.App/BioDesk.App.csproj | Select-String "UserSecretsId"
```

**Deve ter linha:**
```xml
<UserSecretsId>aspnet-BioDesk-...</UserSecretsId>
```

Se **não tiver**, adiciona manualmente:
```xml
<PropertyGroup>
  <UserSecretsId>BioDeskPro2-UserSecrets-$(MSBuildProjectName)</UserSecretsId>
</PropertyGroup>
```

Depois executa novamente:
```powershell
dotnet user-secrets set "Email:Sender" "seuemail@gmail.com" --project src/BioDesk.App
```

---

### Erro 5: E-mail enviado mas não chega

**Sintoma:**
- Status muda para "Enviado" ✅
- Mas paciente não recebe e-mail

**Causas possíveis:**

#### ❌ Causa 5.1: E-mail na pasta SPAM
- **Solução:** Pedir ao paciente verificar pasta "Spam" / "Lixo"
- **Prevenção futura:**
  1. Pedir ao paciente adicionar `nunocorreiaterapiasnaturais@gmail.com` aos contactos
  2. Marcar e-mail como "Não é spam"

#### ❌ Causa 5.2: E-mail do paciente inválido/desativado
- **Diagnóstico:** Verificar se e-mail está correto na ficha do paciente
- **Solução:** Atualizar e-mail do paciente

---

## 📊 Logs para Debugging

Se problema persistir, verificar logs:

### Logs do EmailService

```powershell
# Logs aparecem na Output window do Visual Studio
# Ou em ficheiros (se configurado):
Get-Content "C:\Users\...\BioDeskPro2\logs\email-*.log"
```

**Procurar por:**
- `❌ ERRO ao enviar email`
- `SmtpException`
- `Authentication failed`

### Logs de User Secrets

**Localização do ficheiro secrets.json:**

**Windows:**
```
C:\Users\{USERNAME}\AppData\Roaming\Microsoft\UserSecrets\{GUID}\secrets.json
```

**Pode ver o conteúdo:**
```powershell
dotnet user-secrets list --project src/BioDesk.App
```

⚠️ **NUNCA partilhes este ficheiro** - contém credenciais!

---

## ✅ Checklist Final

Antes de reportar problema, confirma:

- [ ] User Secrets configurados (`dotnet user-secrets list`)
- [ ] App Password do Gmail gerado (16 caracteres)
- [ ] Autenticação 2FA ativa no Gmail
- [ ] Conexão à internet funcional
- [ ] Botão "🧪 Testar Conexão" em Configurações funciona
- [ ] E-mail do paciente está correto na ficha

Se **TODOS os pontos** estão ✅ e problema persiste:
→ Contactar suporte técnico com logs detalhados

---

## 🎯 Resumo Executivo (TL;DR)

### Problema
E-mails não enviam (erro "Email:Sender não configurado")

### Causa
User Secrets não configurados após reinstalar Windows/mudar PC

### Solução (5 minutos)
```powershell
# 1. Navegar para projeto
cd "C:\caminho\BioDeskPro2"

# 2. Configurar credenciais (SUBSTITUIR VALORES!)
dotnet user-secrets set "Email:Sender" "seuemail@gmail.com" --project src/BioDesk.App
dotnet user-secrets set "Email:Password" "APP_PASSWORD_16_CHARS" --project src/BioDesk.App
dotnet user-secrets set "Email:SenderName" "Seu Nome" --project src/BioDesk.App

# 3. Verificar
dotnet user-secrets list --project src/BioDesk.App

# 4. Testar na aplicação: Configurações → "🧪 Testar Conexão"
```

### Documentação Completa
Ver ficheiro: **`CONFIGURACAO_SMTP_GMAIL.md`**

---

## 📞 Recursos Adicionais

- **Gmail App Passwords:** https://myaccount.google.com/apppasswords
- **User Secrets (Microsoft):** https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets
- **Documentação BioDeskPro2:**
  - `CONFIGURACAO_SMTP_GMAIL.md` (guia completo)
  - `CORRECOES_SISTEMA_EMAIL.md` (histórico de correções)
  - `CORRECAO_CRITICA_EMAILS_AGENDADOS.md` (retry automático)

---

**Última atualização:** 07/10/2025  
**Desenvolvido por:** GitHub Copilot  
**Versão BioDeskPro2:** v1.0

---

**✅ Após seguir estes passos, sistema de e-mail estará 100% funcional!**
