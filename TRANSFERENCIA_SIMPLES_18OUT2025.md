# 🚀 Transferência Simples PC - BioDeskPro2
**Data**: 18 de outubro de 2025
**Status**: ✅ Build OK | ✅ 150 Testes Passaram | ✅ Backup Criado

---

## 📋 RESUMO: 3 PASSOS APENAS

### **PC ANTIGO**
1. **Git**: Commit + Push
2. **Verificar**: Backup BD existe
3. **OneDrive**: Deixar sincronizar (se usar OneDrive)

### **PC NOVO**
1. **Git**: Clone repositório
2. **Copiar**: `biodesk.db` do backup
3. **Executar**: `dotnet build` + `dotnet run`

---

## 🔴 PC ANTIGO - AGORA

### Passo 1: Git Commit + Push

```powershell
# Ir para pasta do projeto
cd C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2

# Pull remoto
git pull origin copilot/vscode1760742399628

# Adicionar ficheiros
git add -A

# Commit
git commit -m "✨ Preparação transferência PC - HS3 completo + 150 testes OK"

# Push
git push origin copilot/vscode1760742399628
```

**✅ PRONTO**: Verificar em GitHub que commit apareceu

---

### Passo 2: Verificar Backup BD

```powershell
# Ver se BD existe
Get-Item "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db"

# Ver tamanho (deve ser >700KB se tiver dados)
(Get-Item "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db").Length / 1KB

# Copiar BD para backup (se ainda não fez)
Copy-Item "biodesk.db" "C:\Backups\BioDeskPro2\BD_Manual\biodesk_18OUT2025.db"
```

**✅ PRONTO**: BD guardada em `C:\Backups\BioDeskPro2\BD_Manual\`

---

### Passo 3: OneDrive (Se Usar)

Se a pasta está em **OneDrive**, deixar sincronizar automaticamente.

**OU** copiar pasta manualmente para pendrive/disco externo.

---

## 🟢 PC NOVO - DEPOIS

### Pré-requisitos (Instalar Primeiro)
- **.NET 8 SDK**: https://dotnet.microsoft.com/download/dotnet/8.0
- **Git**: https://git-scm.com/download/win
- **VS Code**: https://code.visualstudio.com/

---

### Passo 1: Clonar Repositório

```powershell
# Ir para pasta de trabalho
cd C:\Users\[SEU_USERNAME]\OneDrive\Documentos

# Clonar (OPÇÃO 1 - Recomendado)
git clone https://github.com/NunoCorreia78/BioDeskPRO2.0.git BioDeskPro2
cd BioDeskPro2

# Checkout branch correta
git checkout copilot/vscode1760742399628
git pull origin copilot/vscode1760742399628
```

**OU copiar pasta** do OneDrive/pendrive (OPÇÃO 2)

---

### Passo 2: Restaurar Base de Dados

```powershell
# Copiar BD do backup para pasta projeto
Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\biodesk_18OUT2025.db" `
          "C:\Users\[SEU_USERNAME]\OneDrive\Documentos\BioDeskPro2\biodesk.db"

# Verificar tamanho
(Get-Item "biodesk.db").Length / 1KB
```

**✅ CHECKPOINT**: Deve mostrar >700KB (se tiver dados)

---

### Passo 3: Build e Testar

```powershell
# Restaurar dependências
dotnet restore

# Build
dotnet build
```

**✅ Verificar**: 0 Errors (warnings AForge são normais)

```powershell
# Testar
dotnet test src/BioDesk.Tests
```

**✅ Verificar**: 150 testes passam

```powershell
# Executar aplicação
dotnet run --project src/BioDesk.App
```

**✅ Verificar**: Dashboard abre + Pacientes aparecem

---

### Passo 4: VS Code (Opcional mas Recomendado)

```powershell
# Abrir VS Code
code .
```

**Instalar extensões** (quando VS Code pedir):
- C# Dev Kit
- C#
- GitLens

**Aguardar** IntelliSense carregar (1-2 min primeira vez)

---

## 🔴 AVISOS CRÍTICOS

### ⚠️ NUNCA
1. Alterar `PathService.cs` → Perde BD
2. Deletar `biodesk.db` sem backup → PERDA IRREVERSÍVEL
3. Alterar `App.xaml.cs` linha DbContext → Cria BD vazia

### ✅ SEMPRE
1. Verificar tamanho `biodesk.db` >700KB (se tiver dados)
2. Executar testes no PC novo (`dotnet test`)
3. Backup antes de alterações críticas

---

## 🆘 Problemas Comuns

### Build falha no PC novo
```powershell
dotnet clean
dotnet restore --force
dotnet build --no-incremental
```

### BD vazia após restaurar
```powershell
# Verificar tamanho
(Get-Item "biodesk.db").Length / 1KB

# Se <10KB, restaurar de novo
Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\biodesk_18OUT2025.db" `
          "biodesk.db" -Force
```

### IntelliSense não funciona
1. Fechar VS Code
2. Reabrir VS Code
3. `Ctrl+Shift+P` → "OmniSharp: Restart OmniSharp"

---

## 📦 Ficheiros Importantes

### **Via Git** (automático)
- Todo código `src/`
- Configurações `.vscode`, `omnisharp.json`
- Documentação

### **Cópia Manual** (CRÍTICO)
- **`biodesk.db`** ← BASE DE DADOS
- `Pacientes/` (fotos íris)
- `Documentos/` (PDFs)
- `Prescricoes/` (prescrições)
- `Consentimentos/` (assinaturas)

---

## ✅ CHECKLIST RÁPIDO

### PC ANTIGO
- [ ] `git push` executado
- [ ] BD copiada para `C:\Backups\`
- [ ] OneDrive sincronizado OU pasta copiada

### PC NOVO
- [ ] .NET 8 instalado (`dotnet --version`)
- [ ] Repositório clonado
- [ ] `biodesk.db` restaurada
- [ ] `dotnet build` OK
- [ ] `dotnet test` → 150 passam
- [ ] `dotnet run` → Dashboard abre

---

**Backup Automático Criado**: ✅ `C:\Backups\BioDeskPro2\backup_20251018_120523.zip` (149 MB)
**Build Status**: ✅ 0 Errors
**Testes**: ✅ 150/150 Passed

---

**PRONTO PARA TRANSFERIR!** 🚀
