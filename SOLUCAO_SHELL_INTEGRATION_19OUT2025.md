# Solução: VS Code Shell Integration + Copilot Terminal
**Data:** 19 de outubro de 2025
**Problema:** Copilot não conseguia ler output do terminal automaticamente

---

## ❌ Problema Original

O GitHub Copilot não conseguia "ver" o output dos comandos executados no terminal, mesmo quando o utilizador colava manualmente. Isto impedia workflows como:
- "Run tests and fix errors"
- "What was the output of the last command?"
- Debugging automático baseado em erros de build

---

## 🔍 Causa Raiz Identificada

**VS Code Shell Integration não estava ativa** devido a:

### 1. **Perfil PowerShell inexistente**
- Caminho: `C:\Users\nfjpc\OneDrive\Documentos\WindowsPowerShell\Microsoft.VSCode_profile.ps1`
- Estado inicial: **NÃO EXISTIA** (`Test-Path $PROFILE` retornava `False`)
- Consequência: VS Code não carregava integração automaticamente

### 2. **Função `prompt` customizada sobrescrevia integração**
- Quando criado, o perfil tinha uma função `prompt` simples
- Esta função **sobrescreve** o prompt complexo do VS Code
- VS Code Shell Integration **depende de controlar o prompt** para capturar comandos

### 3. **Código de diagnóstico errado**
```powershell
# ❌ ERRADO - Procurar por funções __vsc_*
Get-Command __vsc_* | Select-Object Name  # Retorna vazio!
```

**VS Code Shell Integration NÃO usa funções `__vsc_*`!** Usa:
- Variável `$Global:__VSCodeState`
- Prompt complexo com sequências de escape OSC 633
- Códigos de controle ANSI para comunicar com VS Code

---

## ✅ Solução Implementada

### 1. **Criado Perfil PowerShell Otimizado**

**Ficheiro:** `C:\Users\nfjpc\OneDrive\Documentos\WindowsPowerShell\Microsoft.VSCode_profile.ps1`

```powershell
# ========================================
# VS Code Shell Integration (CRÍTICO)
# ========================================
if ($env:TERM_PROGRAM -eq "vscode") {
    try {
        # Localizar integração shell do VS Code
        # NOTA: Usamos 'pwsh' porque VS Code não suporta 'powershell' como argumento,
        # mas o script shellIntegration.ps1 funciona com Windows PowerShell 5.1 também
        $shellIntegrationPath = & code --locate-shell-integration-path pwsh

        if ($shellIntegrationPath -and (Test-Path $shellIntegrationPath)) {
            . $shellIntegrationPath
            Write-Host "✅ VS Code Shell Integration ativada ($shellIntegrationPath)" -ForegroundColor Green
        }
        else {
            Write-Warning "⚠️ Caminho de Shell Integration não encontrado: $shellIntegrationPath"
        }
    }
    catch {
        Write-Warning "⚠️ Erro ao carregar VS Code Shell Integration: $_"
    }
}

# ========================================
# PSReadLine - Evitar bug de acessibilidade
# ========================================
try {
    Import-Module PSReadLine -ErrorAction Stop

    # Configurações compatíveis com Windows PowerShell 5.1
    # Nota: PredictionViewStyle só existe no PowerShell 7+
    if ($PSVersionTable.PSVersion.Major -ge 7) {
        Set-PSReadLineOption -PredictionViewStyle ListView
    }

    Write-Host "✅ PSReadLine carregado" -ForegroundColor Green
}
catch {
    Write-Warning "⚠️ PSReadLine não disponível: $_"
}

# ========================================
# Aliases úteis para desenvolvimento .NET
# ========================================
Set-Alias -Name build -Value dotnet
Set-Alias -Name test -Value dotnet

# ========================================
# Prompt customizado (DESATIVADO - conflita com VS Code Shell Integration)
# ========================================
# IMPORTANTE: NÃO definir função prompt aqui pois sobrescreve a integração do VS Code!
# O VS Code Shell Integration depende de controlar o prompt para capturar comandos.
#
# function prompt {
#     $path = Split-Path -Leaf (Get-Location)
#     "$path> "
# }

Write-Host "🚀 Perfil PowerShell carregado - BioDeskPro2" -ForegroundColor Cyan
```

### 2. **Configurações VS Code (`.vscode/settings.json`)**

```json
{
    // ===== CONFIGURAÇÕES DE TERMINAL (OTIMIZADO - COM SHELL INTEGRATION) =====
    "terminal.integrated.defaultProfile.windows": "PowerShell",
    "terminal.integrated.shellIntegration.enabled": true,
    "terminal.integrated.enablePersistentSessions": false,
    "terminal.integrated.tabs.enabled": true,

    // ===== CONFIGURAÇÕES COPILOT CHAT TERMINAL =====
    "github.copilot.chat.agent.runTasks": true,
    "chat.tools.terminal.autoApprove": {
        "git": true,
        "/^dotnet( |$)/": true,
        "/^npm( |$)/": true
    },

    // ===== DESATIVAR SINAIS DE ACESSIBILIDADE (FIX PSREADLINE) =====
    "accessibility.signals.terminalCommandFailed": {
        "sound": "off"
    },
    "accessibility.signals.terminalCommandSucceeded": {
        "sound": "off"
    },
    "accessibility.verbosity.terminal": false
}
```

### 3. **Diagnóstico Correto da Shell Integration**

```powershell
# ✅ CORRETO - Verificar variável __VSCodeState
Get-Variable __VSCodeState -ErrorAction SilentlyContinue

# ✅ CORRETO - Ver prompt do VS Code (deve mostrar código complexo com OSC 633)
$function:Prompt
```

**Output esperado do `$function:Prompt` (ATIVO):**
```powershell
$FakeCode = [int]!$global:?
Set-StrictMode -Off
$LastHistoryEntry = Get-History -Count 1
$Result = ""
# ... MUITO CÓDIGO com $Global:__VSCodeState ...
# ... Sequências de escape como "$([char]0x1b)]633;D`a" ...
return $Result
```

**Output quando NÃO ATIVO (problema):**
```powershell
$p = Split-Path -leaf -path (Get-Location)
"$p> "
```

---

## 🧪 Testes de Validação

### Teste 1: Shell Integration Ativa
```powershell
# Deve retornar objeto com propriedades
Get-Variable __VSCodeState

Name                           Value
----                           -----
__VSCodeState                  {ContinuationPrompt, Nonce, OriginalPrompt, H...
```

### Teste 2: Prompt Complexo
```powershell
$function:Prompt | Measure-Object -Line

Lines Words Characters Property
----- ----- ---------- --------
   50   ...       2000+
```
Se retornar **1 linha** e **~15 caracteres**, a integração NÃO está ativa.

### Teste 3: Copilot Lê Terminal
```powershell
dotnet --info
```
Depois perguntar ao Copilot: **"Qual a versão do .NET SDK instalada?"**

Se responder automaticamente (ex: "8.0.415"), **SUCESSO!**

---

## ⚠️ Limitações Descobertas

### 🔴 Copilot pode não ler terminais existentes
Mesmo com Shell Integration ativa:
- Copilot conseguiu **ler output quando executou comandos ele próprio** (via tool `run_in_terminal`)
- Mas **NÃO conseguiu ler** comandos executados manualmente pelo utilizador no terminal

**Possível causa:** Copilot precisa de **criar/controlar o terminal** para ter acesso ao histórico.

**Workaround:** Usar `#terminal` no chat e pedir ao Copilot para executar comandos.

---

## 📋 Checklist Rápida para Outros PCs

### Verificar se Shell Integration está ativa:
```powershell
# 1. Variável existe?
Get-Variable __VSCodeState

# 2. Prompt é complexo?
($function:Prompt).Length -gt 100

# 3. Setting ativo?
# Abrir Settings → procurar "terminal.integrated.shellIntegration.enabled" → Deve ser TRUE
```

### Ativar Shell Integration (se não funcionar):
1. Criar perfil PowerShell:
   ```powershell
   New-Item -ItemType File -Path $PROFILE -Force
   code $PROFILE
   ```

2. Colar código do perfil (ver secção "Solução Implementada")

3. **NUNCA** definir função `prompt` no perfil

4. Reiniciar VS Code completamente

---

## 🎯 Resumo Executivo

| Item | Estado | Notas |
|------|--------|-------|
| **Shell Integration** | ✅ ATIVA | Variável `__VSCodeState` presente, prompt complexo |
| **Perfil PowerShell** | ✅ CRIADO | `Microsoft.VSCode_profile.ps1` sem função `prompt` |
| **Settings VS Code** | ✅ CONFIGURADO | `shellIntegration.enabled: true` + autoApprove |
| **Copilot lê terminal** | ⚠️ PARCIAL | Lê comandos que ELE executa, não manuais do user |

---

## 📚 Referências

- [VS Code Shell Integration Docs](https://code.visualstudio.com/docs/terminal/shell-integration)
- [GitHub Copilot Chat Tools](https://code.visualstudio.com/docs/copilot/copilot-chat#_chat-tools)
- Script Shell Integration: `C:\Users\nfjpc\AppData\Local\Programs\Microsoft VS Code\resources\app\out\vs\workbench\contrib\terminal\common\scripts\shellIntegration.ps1`

---

**Autor:** GitHub Copilot
**Validado em:** Windows 11, VS Code 1.105.1, PowerShell 5.1.26100
