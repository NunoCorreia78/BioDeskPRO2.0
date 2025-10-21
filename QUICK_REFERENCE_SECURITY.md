# 🚀 Quick Reference - Proteção de Senha

## 📌 Comandos Essenciais

### Configurar User Secrets (Primeira Vez)
```powershell
cd src\BioDesk.App
dotnet user-secrets set "Email:Sender" "seu-email@gmail.com"
dotnet user-secrets set "Email:Password" "sua-app-password"
dotnet user-secrets set "Email:FromEmail" "seu-email@gmail.com"
dotnet user-secrets set "Email:FromName" "Seu Nome"
```

### Verificar Configuração
```powershell
cd src\BioDesk.App
dotnet user-secrets list
```

### Executar Aplicação
```powershell
dotnet run --project src\BioDesk.App
```

---

## 📂 Estrutura de Ficheiros

```
BioDeskPro2/
├── 📄 INSTRUCOES_PROPRIETARIO.md      ⭐ COMEÇAR AQUI (Nuno)
├── 📄 CONFIGURACAO_INICIAL.md         ⭐ COMEÇAR AQUI (Novos devs)
├── 📄 RESUMO_PROTECAO_SENHA.md        📊 Visão geral completa
├── 📄 CONFIGURACAO_SEGURA_EMAIL.md    📖 Guia detalhado
├── 📄 CHECKLIST_SEGURANCA.md          ✅ Verificações
├── 📄 ARQUITETURA_SEGURANCA_CREDENCIAIS.md  🏗️ Arquitetura
│
├── Scripts/
│   ├── MigrarCredenciais.ps1          🔄 Migrar automático
│   └── BackupCredenciais.ps1          💾 Backup seguro
│
└── src/BioDesk.App/
    ├── appsettings.json               ✅ Limpo (sem passwords)
    └── appsettings.example.json       📋 Template
```

---

## 🎯 Guia Rápido por Tarefa

| Tarefa | Comando | Documentação |
|--------|---------|--------------|
| **Primeira configuração** | `dotnet user-secrets set ...` | `INSTRUCOES_PROPRIETARIO.md` |
| **Verificar secrets** | `dotnet user-secrets list` | `CONFIGURACAO_INICIAL.md` |
| **Migrar credenciais** | `.\Scripts\MigrarCredenciais.ps1` | `CONFIGURACAO_SEGURA_EMAIL.md` |
| **Fazer backup** | `.\Scripts\BackupCredenciais.ps1` | `CONFIGURACAO_SEGURA_EMAIL.md` |
| **Verificar segurança** | Ver checklist | `CHECKLIST_SEGURANCA.md` |
| **Entender arquitetura** | Ler diagramas | `ARQUITETURA_SEGURANCA_CREDENCIAIS.md` |

---

## ⚡ Resolução Rápida de Problemas

### ❌ "Email:Password não configurado"
**Solução**: Configurar User Secrets
```powershell
cd src\BioDesk.App
dotnet user-secrets set "Email:Password" "sua-senha"
```

### ❌ "App Password incorreto"
**Solução**: Gerar nova senha no Google → myaccount.google.com/security

### ❌ "Não consigo executar dotnet user-secrets"
**Solução**: Instalar .NET 8 SDK → dotnet.microsoft.com/download

---

## 🔐 Localização das Credenciais

### Desenvolvimento (User Secrets)
```
C:\Users\{SeuNome}\AppData\Roaming\Microsoft\UserSecrets\biodesk-app-secrets-2025\secrets.json
```

### Produção (Base de Dados)
```
Debug:   {Projeto}\biodesk.db
Release: C:\ProgramData\BioDeskPro2\biodesk.db
```

---

## ✅ Checklist Rápido

Antes de commitar:
- [ ] `git status` - Verificar ficheiros
- [ ] `git diff` - Verificar mudanças
- [ ] Não comitar: `secrets.json`, `*.db`, `appsettings.local.json`

Antes de executar:
- [ ] User Secrets configurados
- [ ] `dotnet user-secrets list` mostra 4 entradas
- [ ] App Password válido

---

## 📞 Ajuda Rápida

| Preciso de... | Ver documento |
|---------------|---------------|
| Configurar pela primeira vez | `INSTRUCOES_PROPRIETARIO.md` |
| Entender como funciona | `RESUMO_PROTECAO_SENHA.md` |
| Guia completo de segurança | `CONFIGURACAO_SEGURA_EMAIL.md` |
| Verificar se está tudo OK | `CHECKLIST_SEGURANCA.md` |
| Ver diagramas técnicos | `ARQUITETURA_SEGURANCA_CREDENCIAIS.md` |

---

## 🎓 Hierarquia de Documentação

```
┌─────────────────────────────────────┐
│  QUICK_REFERENCE_SECURITY.md        │  ⬅ VOCÊ ESTÁ AQUI
│  (Este ficheiro - referência rápida)│
└─────────────────────────────────────┘
                │
    ┌───────────┴───────────┐
    ▼                       ▼
┌─────────────┐      ┌─────────────┐
│ PROPRIETÁRIO│      │   NOVOS     │
│ (Nuno)      │      │   DEVS      │
└──────┬──────┘      └──────┬──────┘
       │                    │
       ▼                    ▼
┌─────────────────────────────────────┐
│ INSTRUCOES_PROPRIETARIO.md          │
│ CONFIGURACAO_INICIAL.md             │
└─────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ RESUMO_PROTECAO_SENHA.md            │
│ (Visão geral executiva)             │
└─────────────────────────────────────┘
                │
        ┌───────┴────────┐
        ▼                ▼
┌──────────────┐  ┌──────────────┐
│ CONFIGURACAO │  │  CHECKLIST   │
│ SEGURA_EMAIL │  │  SEGURANCA   │
└──────────────┘  └──────────────┘
                │
                ▼
┌─────────────────────────────────────┐
│ ARQUITETURA_SEGURANCA_CREDENCIAIS   │
│ (Documentação técnica profunda)     │
└─────────────────────────────────────┘
```

---

## 🔥 Comandos Mais Usados

```powershell
# Setup inicial (copiar e colar)
cd src\BioDesk.App
dotnet user-secrets set "Email:Sender" "email@gmail.com"
dotnet user-secrets set "Email:Password" "app-password"
dotnet user-secrets set "Email:FromEmail" "email@gmail.com"
dotnet user-secrets set "Email:FromName" "Nome"

# Verificar
dotnet user-secrets list

# Executar
cd ..\..
dotnet run --project src\BioDesk.App

# Migrar credenciais antigas
.\Scripts\MigrarCredenciais.ps1

# Backup
.\Scripts\BackupCredenciais.ps1
```

---

**Tempo médio de setup**: 2 minutos  
**Complexidade**: ⭐⭐☆☆☆ (Fácil)  
**Segurança**: ⭐⭐⭐⭐⭐ (Máxima)

---

**Versão**: 1.0  
**Data**: 21 de Outubro de 2025  
**Status**: ✅ Pronto para usar
