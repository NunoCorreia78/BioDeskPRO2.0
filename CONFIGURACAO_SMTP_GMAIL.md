# 📧 Guia de Configuração SMTP para Gmail - BioDeskPro2

**Data:** 07/10/2025  
**Versão:** 1.0  
**Autor:** GitHub Copilot

---

## 🎯 Objetivo

Este guia explica como configurar as credenciais SMTP do Gmail para o sistema de e-mail do BioDeskPro2 funcionar corretamente.

---

## ⚠️ Problema Atual

O sistema de e-mail do BioDeskPro2 **NÃO ESTÁ CONFIGURADO** por padrão. Ao tentar enviar e-mails, verás erro:

```
❌ InvalidOperationException: Email:Sender não configurado. Use o botão Configurações.
```

**Motivo:** As credenciais SMTP são armazenadas em **User Secrets** (não no código) por segurança.

---

## 🔧 Solução: Configurar User Secrets

### Passo 1: Obter App Password do Gmail

1. **Aceder às Definições da Conta Google:**
   - Vai a: https://myaccount.google.com/
   - Clica em "Segurança" (Security)

2. **Ativar Autenticação de 2 Fatores (obrigatório):**
   - Se ainda não tens, ativa "Verificação em 2 passos"
   - Sem isto, não podes criar App Passwords

3. **Criar App Password:**
   - Vai a: https://myaccount.google.com/apppasswords
   - Seleciona "Outras (nome personalizado)"
   - Nome sugerido: `BioDeskPro2`
   - Clica em "Gerar"
   - **GUARDA O CÓDIGO DE 16 CARACTERES** (ex: `abcd efgh ijkl mnop`)

---

### Passo 2: Configurar User Secrets

Abre **PowerShell** ou **Terminal** e executa os seguintes comandos:

#### 2.1. Navegar para a pasta do projeto

```powershell
cd "C:\Users\[SEU_USUARIO]\OneDrive\Documentos\BioDeskPro2"
# OU
cd "C:\caminho\onde\clonaste\BioDeskPRO2.0"
```

#### 2.2. Configurar E-mail Remetente

```powershell
dotnet user-secrets set "Email:Sender" "seuemail@gmail.com" --project src/BioDesk.App
```

**Exemplo:**
```powershell
dotnet user-secrets set "Email:Sender" "nunocorreiaterapiasnaturais@gmail.com" --project src/BioDesk.App
```

#### 2.3. Configurar App Password

```powershell
dotnet user-secrets set "Email:Password" "abcd efgh ijkl mnop" --project src/BioDesk.App
```

**⚠️ IMPORTANTE:** Usa o App Password de 16 caracteres (com espaços), **NÃO a tua password normal do Gmail!**

#### 2.4. Configurar Nome do Remetente (opcional)

```powershell
dotnet user-secrets set "Email:SenderName" "Nuno Correia - Terapias Naturais" --project src/BioDesk.App
```

---

### Passo 3: Verificar Configuração

Executa este comando para confirmar que as secrets foram guardadas:

```powershell
dotnet user-secrets list --project src/BioDesk.App
```

**Output esperado:**
```
Email:Password = abcd efgh ijkl mnop
Email:Sender = nunocorreiaterapiasnaturais@gmail.com
Email:SenderName = Nuno Correia - Terapias Naturais
```

---

## ✅ Testar Envio de E-mail

### Opção 1: Via Aplicação (Recomendado)

1. **Abrir BioDeskPro2**
2. Ir para **Configurações** (ícone ⚙️ no menu lateral)
3. Secção **"Configurações de E-mail"**
4. Clicar em **"🧪 Testar Conexão"**
5. **Esperado:** 
   - ✅ "Conexão SMTP OK!"
   - E-mail de teste enviado para ti próprio

### Opção 2: Via Ficha de Paciente

1. Abrir ficha de qualquer paciente
2. Ir para aba **"Comunicação & Seguimento"**
3. Selecionar template "Prescrição"
4. Clicar em **"📤 Enviar Email"**
5. **Esperado:**
   - ✅ "Email enviado com sucesso!"
   - Status muda para "Enviado" instantaneamente

---

## 🚨 Troubleshooting

### Erro: "Email:Sender não configurado"

**Causa:** User Secrets não foram configuradas ou projeto errado.

**Solução:**
1. Confirma que estás na pasta raiz do projeto
2. Re-executa os comandos `dotnet user-secrets set ...`
3. Verifica com `dotnet user-secrets list --project src/BioDesk.App`

---

### Erro: "Authentication failed"

**Causa:** App Password inválido ou autenticação 2FA desativada.

**Solução:**
1. Verifica que ativaste **Autenticação de 2 Fatores** no Gmail
2. Gera **novo App Password**: https://myaccount.google.com/apppasswords
3. Atualiza User Secret:
   ```powershell
   dotnet user-secrets set "Email:Password" "NOVO_APP_PASSWORD" --project src/BioDesk.App
   ```

---

### Erro: "SmtpException: 5.7.0 Authentication Required"

**Causa:** Gmail está a bloquear "apps menos seguras".

**Solução:**
- **NÃO USES** a password normal do Gmail
- **USA** um App Password de 16 caracteres (ver Passo 1)

---

### E-mail fica "Agendado" indefinidamente

**Possíveis causas:**

#### 1. Sem conexão à internet
- Verifica Wi-Fi/Ethernet
- Email será enviado automaticamente quando rede voltar (máx 30 segundos)

#### 2. Credenciais inválidas
- Testa com botão "🧪 Testar Conexão" em Configurações
- Se falhar, reconfigura User Secrets (ver Passo 2)

#### 3. Servidor SMTP do Gmail indisponível (raro)
- Aguarda 2-5 minutos (retry automático)
- Após 3 tentativas falhadas, status muda para "Falhado"
- Podes clicar **"🚫 Cancelar"** no histórico

---

## 📂 Onde Ficam Armazenadas as Secrets?

**Windows:**
```
C:\Users\[SEU_USUARIO]\AppData\Roaming\Microsoft\UserSecrets\[GUID]\secrets.json
```

**Linux/Mac:**
```
~/.microsoft/usersecrets/[GUID]/secrets.json
```

**⚠️ IMPORTANTE:**
- **NUNCA** partilhes este ficheiro!
- **NUNCA** comites para Git (já está em `.gitignore`)
- Se mudares de PC, terás de **reconfigurar** os User Secrets

---

## 🔒 Segurança

### ✅ Boas Práticas
- ✅ App Passwords são **menos arriscados** que password principal
- ✅ Podes **revogar** App Passwords sem alterar password do Gmail
- ✅ User Secrets **NÃO vão para Git** (ficheiro local)

### ⚠️ Revogação de App Password
Se suspeitares que o App Password foi comprometido:
1. Vai a https://myaccount.google.com/apppasswords
2. Clica em "Remover" no App Password do BioDeskPro2
3. Gera **novo** App Password
4. Atualiza User Secret (ver Passo 2.3)

---

## 📚 Referências

- [Gmail App Passwords (Official)](https://support.google.com/accounts/answer/185833)
- [.NET User Secrets (Microsoft Docs)](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets)
- [SMTP Settings Gmail](https://support.google.com/mail/answer/7126229)

---

## 🎯 Resumo Rápido (TL;DR)

```powershell
# 1. Gerar App Password no Gmail (16 caracteres)
# https://myaccount.google.com/apppasswords

# 2. Navegar para pasta do projeto
cd "C:\caminho\BioDeskPro2"

# 3. Configurar credenciais
dotnet user-secrets set "Email:Sender" "seuemail@gmail.com" --project src/BioDesk.App
dotnet user-secrets set "Email:Password" "APP_PASSWORD_16_CHARS" --project src/BioDesk.App
dotnet user-secrets set "Email:SenderName" "Seu Nome" --project src/BioDesk.App

# 4. Verificar
dotnet user-secrets list --project src/BioDesk.App

# 5. Testar na aplicação: Configurações → "🧪 Testar Conexão"
```

---

**✅ Após seguir estes passos, o sistema de e-mail estará 100% funcional!**
