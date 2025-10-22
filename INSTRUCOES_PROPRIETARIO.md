# 🔐 Instruções para o Proprietário - Configuração Rápida

## Nuno Correia - Configuração das Credenciais

### ⚡ Opção 1: Método Rápido (Recomendado)

Abra o **PowerShell** como administrador na pasta do projeto e execute:

```powershell
# Navegar para a pasta do projeto App
cd src\BioDesk.App

# Configurar suas credenciais (copie e cole cada linha)
dotnet user-secrets set "Email:Sender" "nunocorreiaterapiasnaturais@gmail.com"
dotnet user-secrets set "Email:Password" "keagmwjrcygsbffo"
dotnet user-secrets set "Email:FromEmail" "nunocorreiaterapiasnaturais@gmail.com"
dotnet user-secrets set "Email:FromName" "Nuno Correia - Terapias Naturais"

# Verificar que ficou configurado
dotnet user-secrets list
```

**Resultado esperado**:
```
Email:Sender = nunocorreiaterapiasnaturais@gmail.com
Email:Password = keagmwjrcygsbffo
Email:FromEmail = nunocorreiaterapiasnaturais@gmail.com
Email:FromName = Nuno Correia - Terapias Naturais
```

✅ **Pronto!** Agora pode executar a aplicação normalmente com `dotnet run`.

---

### 🛠️ Opção 2: Via Visual Studio

1. No **Solution Explorer**, clique com botão direito no projeto `BioDesk.App`
2. Selecione **"Manage User Secrets"**
3. Cole o seguinte JSON:

```json
{
  "Email": {
    "Sender": "nunocorreiaterapiasnaturais@gmail.com",
    "Password": "keagmwjrcygsbffo",
    "FromEmail": "nunocorreiaterapiasnaturais@gmail.com",
    "FromName": "Nuno Correia - Terapias Naturais"
  }
}
```

4. Gravar (Ctrl+S) e fechar

✅ **Pronto!** As credenciais estão configuradas.

---

### 🎯 Opção 3: Script Automático

Se ainda tem o `appsettings.json` com as credenciais antigas:

```powershell
# Na pasta raiz do projeto
.\Scripts\MigrarCredenciais.ps1
```

O script irá ler as credenciais do `appsettings.json` e configurar automaticamente os User Secrets.

---

## 🔍 Como Verificar se Está Tudo Configurado

### Teste 1: Verificar User Secrets

```powershell
cd src\BioDesk.App
dotnet user-secrets list
```

Deve mostrar as 4 linhas com suas credenciais.

### Teste 2: Executar Aplicação

```powershell
dotnet run --project src\BioDesk.App
```

O Dashboard deve abrir normalmente sem erros.

### Teste 3: Testar Envio de Email

1. Abrir a aplicação
2. Ir para **Configurações → Email**
3. Clicar em **"Testar Conexão"**
4. Deve receber email de teste no Gmail

---

## 📍 Onde Ficam Guardadas as Credenciais?

As credenciais ficam guardadas **FORA do projeto**, no seu perfil do Windows:

```
C:\Users\Nuno\AppData\Roaming\Microsoft\UserSecrets\biodesk-app-secrets-2025\secrets.json
```

**Vantagens**:
- ✅ Não vão para o Git (nunca serão commitadas)
- ✅ Seguras no seu perfil de utilizador
- ✅ Outros desenvolvedores não veem as suas credenciais
- ✅ Fácil de fazer backup

---

## 💾 Backup das Credenciais (Recomendado)

Para criar um backup encriptado das suas credenciais:

```powershell
.\Scripts\BackupCredenciais.ps1
```

O script irá:
1. Ler os User Secrets
2. Pedir uma senha de encriptação
3. Criar backup em `Backups/credentials_backup_YYYYMMDD_HHMMSS.enc`

⚠️ **Guarde a senha do backup em local seguro!**

---

## 🚨 Se Algo Correr Mal

### Problema: "Email:Password não configurado"

**Solução**: As credenciais não estão configuradas. Execute a Opção 1 novamente.

### Problema: "App Password incorreto"

**Solução**: 
1. Verificar se a senha está correta: `keagmwjrcygsbffo`
2. Se não funcionar, gerar nova App Password no Gmail
3. Atualizar com: `dotnet user-secrets set "Email:Password" "nova-senha"`

### Problema: "Não consigo executar dotnet user-secrets"

**Solução**:
1. Verificar que .NET 8 SDK está instalado: `dotnet --version`
2. Deve mostrar versão 8.x.x
3. Se não tiver, instalar de [dotnet.microsoft.com](https://dotnet.microsoft.com/download)

---

## 📋 Checklist Final

Antes de começar a trabalhar:

- [ ] User Secrets configurados (`dotnet user-secrets list` funciona)
- [ ] Aplicação executa sem erros (`dotnet run`)
- [ ] Teste de email funciona (recebe email de teste)
- [ ] Backup criado (opcional mas recomendado)

Se todos os pontos estiverem ✅, está tudo pronto para usar!

---

## 🔒 Segurança - Importante!

**NUNCA faça**:
- ❌ Commit de `appsettings.json` com a senha preenchida
- ❌ Partilhar o ficheiro `secrets.json` por email/chat
- ❌ Publicar a App Password online

**SEMPRE faça**:
- ✅ Usar User Secrets para desenvolvimento
- ✅ Verificar `git status` antes de commit
- ✅ Manter backups das credenciais em local seguro

---

## 📞 Documentação Completa

Para mais informações:
- [CONFIGURACAO_SEGURA_EMAIL.md](./CONFIGURACAO_SEGURA_EMAIL.md) - Guia completo de segurança
- [CONFIGURACAO_INICIAL.md](./CONFIGURACAO_INICIAL.md) - Setup para novos desenvolvedores
- [CHECKLIST_SEGURANCA.md](./CHECKLIST_SEGURANCA.md) - Checklist de verificação

---

**Data**: 21 de Outubro de 2025  
**Para**: Nuno Correia  
**Projeto**: BioDeskPro2

**Tudo pronto!** 🚀 Se tiver alguma dúvida, consultar a documentação completa acima.
