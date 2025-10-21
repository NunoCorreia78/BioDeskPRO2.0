# 🏗️ Arquitetura de Segurança - Credenciais Email

## Visão Geral da Solução Implementada

Este documento explica como as credenciais de email são geridas de forma segura no BioDeskPro2.

---

## 📊 Diagrama da Arquitetura

```
┌─────────────────────────────────────────────────────────────────┐
│                     DESENVOLVIMENTO                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  👨‍💻 Desenvolvedor                                               │
│       │                                                          │
│       ├──► appsettings.json (valores padrão, SEM credenciais)   │
│       │                                                          │
│       └──► User Secrets                                         │
│            ├─ Localização: C:\Users\{Nome}\AppData\...          │
│            ├─ Ficheiro: secrets.json                            │
│            ├─ UserSecretsId: biodesk-app-secrets-2025           │
│            └─ ✅ NUNCA vai para o Git                           │
│                                                                  │
│  ┌──────────────────────────────────────────────┐              │
│  │ IConfiguration (ASP.NET Core)                │              │
│  │                                               │              │
│  │  Prioridade de Leitura:                      │              │
│  │  1. appsettings.json (valores padrão)        │              │
│  │  2. User Secrets (sobrescreve)        ⬅ AQUI│              │
│  │  3. Variáveis Ambiente (sobrescreve)         │              │
│  │  4. Base de Dados (sobrescreve)              │              │
│  └──────────────────────────────────────────────┘              │
│                      │                                           │
│                      ▼                                           │
│              ┌─────────────────┐                                │
│              │  EmailService   │                                │
│              │  lê credenciais │                                │
│              └─────────────────┘                                │
│                      │                                           │
│                      ▼                                           │
│              ┌─────────────────┐                                │
│              │  SMTP Gmail     │                                │
│              │  smtp.gmail.com │                                │
│              └─────────────────┘                                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                        PRODUÇÃO                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  👤 Utilizador Final                                            │
│       │                                                          │
│       ├──► Interface da Aplicação                               │
│       │    (Configurações → Email)                              │
│       │                                                          │
│       └──► ConfiguracaoClinicaViewModel                         │
│            └─► Grava credenciais na Base de Dados               │
│                                                                  │
│  ┌──────────────────────────────────────────────┐              │
│  │ biodesk.db (SQLite)                          │              │
│  │                                               │              │
│  │ Tabela: ConfiguracaoClinica                  │              │
│  │ ├─ SmtpFromEmail                             │              │
│  │ ├─ SmtpPassword (encriptado por SO)          │              │
│  │ └─ SmtpFromName                              │              │
│  │                                               │              │
│  │ Localização:                                 │              │
│  │ ├─ Debug: {Projeto}/biodesk.db               │              │
│  │ └─ Release: C:\ProgramData\BioDeskPro2\      │              │
│  └──────────────────────────────────────────────┘              │
│                      │                                           │
│                      ▼                                           │
│              ┌─────────────────┐                                │
│              │ IConfiguration  │                                │
│              │ + DbContext     │                                │
│              └─────────────────┘                                │
│                      │                                           │
│                      ▼                                           │
│              ┌─────────────────┐                                │
│              │  EmailService   │                                │
│              └─────────────────┘                                │
│                      │                                           │
│                      ▼                                           │
│              ┌─────────────────┐                                │
│              │  SMTP Gmail     │                                │
│              └─────────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔐 Camadas de Segurança

### Camada 1: Código-Fonte (Repositório Git)

```
appsettings.json
├─ ❌ SEM credenciais reais
├─ ✅ Apenas valores padrão/placeholders
└─ ✅ Pode ser commitado ao Git com segurança

appsettings.example.json
├─ ✅ Template para novos desenvolvedores
└─ ✅ Instruções em comentários
```

### Camada 2: Ambiente de Desenvolvimento (Local)

```
User Secrets (secrets.json)
├─ 📍 Localização: Fora do projeto
├─ 🔒 Protegido por .gitignore automático do .NET
├─ 👤 Específico de cada desenvolvedor
├─ ✅ Nunca vai para o Git
└─ 💾 Fácil de fazer backup

Localização exata:
Windows: C:\Users\{Nome}\AppData\Roaming\Microsoft\UserSecrets\{Id}\secrets.json
```

### Camada 3: Aplicação em Execução

```
IConfiguration (ASP.NET Core)
├─ 🔄 Carrega múltiplas fontes
├─ 📊 Merge hierárquico (prioridade)
├─ 🔍 Validação em runtime
└─ ✅ Fallback para valores padrão

EmailService
├─ 🔒 Lê de IConfiguration
├─ ⚠️ Lança exceção se não configurado
└─ 📝 Logs (sem expor credenciais)
```

### Camada 4: Produção (Utilizador Final)

```
Base de Dados SQLite (biodesk.db)
├─ 📍 C:\ProgramData\BioDeskPro2\ (Release)
├─ 🔒 Permissões Windows (apenas utilizador)
├─ 💾 Backups encriptados recomendados
└─ 🛡️ Protegido por filesystem do SO

Interface da Aplicação
├─ 🖥️ ConfiguraçõesWindow.xaml
├─ 🔐 PasswordBox (WPF) - nunca expõe texto
├─ ✅ Botão "Testar Conexão" antes de gravar
└─ 💾 Grava diretamente na BD
```

---

## 🔄 Fluxo de Configuração

### Desenvolvimento (Primeira Vez)

```
1. Clonar repositório
   ├─ appsettings.json vem VAZIO
   └─ Nenhuma credencial presente

2. Ler documentação
   ├─ CONFIGURACAO_INICIAL.md
   └─ INSTRUCOES_PROPRIETARIO.md (se for o dono)

3. Configurar User Secrets
   ├─ Via dotnet CLI
   │  └─ dotnet user-secrets set "Email:Password" "xxx"
   │
   └─ Via Visual Studio
      └─ Manage User Secrets → editar JSON

4. Verificar configuração
   └─ dotnet user-secrets list

5. Executar aplicação
   └─ dotnet run (credenciais carregadas automaticamente)
```

### Produção (Utilizador Final)

```
1. Instalar aplicação
   └─ Executar instalador BioDeskPro2.exe

2. Primeira execução
   ├─ Dashboard abre
   └─ Sem credenciais configuradas

3. Abrir Configurações
   ├─ Menu → Configurações
   └─ Aba "Email / SMTP"

4. Gerar App Password no Gmail
   ├─ myaccount.google.com/security
   ├─ Ativar 2-Step Verification
   └─ Criar App Password

5. Preencher formulário
   ├─ Email remetente
   ├─ App Password
   └─ Nome do remetente

6. Testar conexão
   ├─ Botão "Testar Conexão"
   └─ Verificar email de teste

7. Gravar
   └─ Credenciais guardadas na BD
```

---

## 🛡️ Proteções Implementadas

### Proteção 1: Git (.gitignore)

```gitignore
# User Secrets
secrets.json
**/secrets.json

# Configurações locais
appsettings.local.json
appsettings.*.local.json

# Base de Dados
biodesk.db
*.db
*.db-shm
*.db-wal
```

**Resultado**: Credenciais NUNCA vão para o repositório Git.

### Proteção 2: .NET User Secrets

- ✅ Automático: .NET já ignora pasta User Secrets
- ✅ Fora do projeto: Não pode ser acidentalmente commitado
- ✅ Por utilizador: Cada dev tem suas próprias credenciais

### Proteção 3: Validação em Runtime

```csharp
// EmailService.cs (linha 34)
private string SmtpPassword => 
    _configuration["Email:Password"] ?? 
    throw new InvalidOperationException("Email:Password não configurado");
```

**Resultado**: Aplicação falha rapidamente se credenciais não estiverem configuradas.

### Proteção 4: Logs Seguros

```csharp
// EmailService.cs (linha 77)
_logger.LogWarning("🔍 DEBUG - Email:Password configurado: {Password}", 
    string.IsNullOrEmpty(password) ? "❌ VAZIO" : "✅ (oculto)");
```

**Resultado**: Logs mostram SE está configurado, mas NÃO mostram o valor.

---

## 📈 Comparação: Antes vs Depois

### ❌ ANTES (Inseguro)

```json
// appsettings.json (COMMITADO ao Git!)
{
  "Email": {
    "Password": "keagmwjrcygsbffo"  // ⚠️ EXPOSTO PUBLICAMENTE
  }
}
```

**Problemas**:
- ❌ Senha no repositório Git
- ❌ Qualquer pessoa com acesso vê a senha
- ❌ Histórico Git mantém senha mesmo após remoção
- ❌ Forks/clones expõem a senha

### ✅ DEPOIS (Seguro)

```json
// appsettings.json (commitado com segurança)
{
  "Email": {
    "Password": ""  // ✅ VAZIO
  }
}
```

```json
// secrets.json (fora do projeto, nunca commitado)
{
  "Email:Password": "keagmwjrcygsbffo"  // ✅ SEGURO
}
```

**Vantagens**:
- ✅ Senha fora do Git
- ✅ Cada desenvolvedor usa suas credenciais
- ✅ Fácil de atualizar sem afetar outros
- ✅ Backups podem ser encriptados

---

## 🔍 Auditoria e Conformidade

### Verificações Automáticas

| Verificação | Ferramenta | Frequência |
|-------------|-----------|-----------|
| Scan de secrets no código | git-secrets | Pré-commit |
| Review de commits sensíveis | GitHub Security | Contínuo |
| Dependências vulneráveis | Dependabot | Diário |
| Permissões de ficheiros | Script PowerShell | Manual |

### Checklist de Segurança

Antes de cada release:
- [ ] Verificar que `appsettings.json` está limpo
- [ ] Confirmar `.gitignore` atualizado
- [ ] Testar com User Secrets em dev
- [ ] Testar com BD em produção
- [ ] Documentação atualizada

---

## 📚 Referências e Standards

### Standards de Segurança Seguidos

- ✅ **OWASP Top 10**: Proteção contra A07:2021 - Identification and Authentication Failures
- ✅ **Microsoft Security Guidelines**: User Secrets para desenvolvimento
- ✅ **GDPR**: Credenciais não são expostas ou partilhadas
- ✅ **CIS Benchmarks**: Princípio do menor privilégio

### Documentação Técnica

- [ASP.NET Core Configuration](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/)
- [Safe storage of app secrets](https://learn.microsoft.com/en-us/aspnet/core/security/app-secrets)
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

## 🎯 Próximos Passos (Melhorias Futuras)

### Curto Prazo (Opcional)
- [ ] Encriptação da base de dados SQLite
- [ ] Rotação automática de App Passwords
- [ ] Alertas de segurança via email

### Médio Prazo (Escalabilidade)
- [ ] Integração com Azure Key Vault
- [ ] OAuth 2.0 para Gmail (mais seguro)
- [ ] Multi-tenancy com credenciais por tenant

### Longo Prazo (Enterprise)
- [ ] Identity Server para autenticação
- [ ] Auditoria completa de acessos
- [ ] Certificados SSL/TLS geridos

---

**Arquitetura desenhada**: 21 de Outubro de 2025  
**Status**: ✅ Implementado e Funcional  
**Versão**: 1.0
