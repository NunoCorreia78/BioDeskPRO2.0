# 🚀 Configuração Inicial - BioDeskPro2

## Para Desenvolvedores (Primeira Execução)

### ⚠️ IMPORTANTE: Configurar Credenciais de Email

O projeto **NÃO** inclui credenciais de email no código-fonte por questões de segurança.

### Passo 1: Copiar Template de Configuração

```powershell
# Copiar o ficheiro de exemplo para appsettings.json
cd src/BioDesk.App
copy appsettings.example.json appsettings.json
```

### Passo 2: Configurar User Secrets (Recomendado)

**Opção A: Via Visual Studio**
1. Clicar com botão direito em `BioDesk.App` no Solution Explorer
2. Selecionar **"Manage User Secrets"**
3. Cole o seguinte (substitua com suas credenciais):

```json
{
  "Email": {
    "Sender": "seu-email@gmail.com",
    "Password": "sua-app-password-do-gmail",
    "FromEmail": "seu-email@gmail.com",
    "FromName": "Seu Nome - Terapias Naturais"
  }
}
```

**Opção B: Via Terminal**
```powershell
cd src/BioDesk.App

dotnet user-secrets set "Email:Sender" "seu-email@gmail.com"
dotnet user-secrets set "Email:Password" "sua-app-password"
dotnet user-secrets set "Email:FromEmail" "seu-email@gmail.com"
dotnet user-secrets set "Email:FromName" "Seu Nome"

# Verificar
dotnet user-secrets list
```

### Passo 3: Obter App Password do Gmail

1. Ir para [https://myaccount.google.com/security](https://myaccount.google.com/security)
2. Ativar **"Verificação em 2 passos"**
3. Procurar **"Palavras-passe de aplicações"** (App Passwords)
4. Gerar nova App Password para "BioDeskPro2"
5. Copiar a senha de 16 caracteres (sem espaços)

### Passo 4: Executar a Aplicação

```powershell
# Build
dotnet build

# Run
dotnet run --project src/BioDesk.App
```

---

## Para Utilizadores Finais

### ⚡ Configuração Rápida

1. **Instalar a aplicação** (seguir o instalador)
2. **Abrir BioDeskPro2**
3. Ir para **Configurações → Email**
4. Preencher:
   - Email do remetente
   - App Password do Gmail (ver passo 3 acima)
   - Nome do remetente
5. Clicar em **"Testar Conexão"**
6. Se testar com sucesso, clicar em **"Gravar"**

---

## 📖 Documentação Completa

Para mais detalhes sobre segurança e configuração avançada, consultar:
- [CONFIGURACAO_SEGURA_EMAIL.md](./CONFIGURACAO_SEGURA_EMAIL.md)

---

## 🔒 Segurança

**NUNCA** commitar ficheiros com credenciais reais:
- ❌ `appsettings.json` com passwords
- ❌ `secrets.json`
- ❌ Ficheiros `.local.json`

**SEMPRE** usar:
- ✅ User Secrets (desenvolvimento)
- ✅ Interface da aplicação (produção)
- ✅ Variáveis de ambiente (servidor)

---

**Questões?** Consultar [CONFIGURACAO_SEGURA_EMAIL.md](./CONFIGURACAO_SEGURA_EMAIL.md)
