# 💻 SETUP ULTRA-RÁPIDO - NOVO PC
## Copy/Paste estes comandos no PowerShell

```powershell
# ========================================
# 🚀 BIODESK PRO2 - SETUP COMPLETO
# ========================================

Write-Host "🩺 BioDeskPro2 - Setup Novo PC" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Verificar .NET 8
Write-Host "⚡ Verificando .NET 8..." -ForegroundColor Yellow
if (Get-Command "dotnet" -ErrorAction SilentlyContinue) {
    dotnet --version
    Write-Host "✅ .NET encontrado!" -ForegroundColor Green
} else {
    Write-Host "❌ .NET 8 SDK não encontrado!" -ForegroundColor Red
    Write-Host "📥 Baixe em: https://dotnet.microsoft.com/download/dotnet/8.0" -ForegroundColor Yellow
    exit 1
}

# Configurar Git
Write-Host "⚡ Configurando Git..." -ForegroundColor Yellow
git config --global user.name "Nuno Correia"
git config --global user.email "nuno.correia@email.com"
Write-Host "✅ Git configurado!" -ForegroundColor Green

# Navegar para Documents
Write-Host "⚡ Navegando para Documents..." -ForegroundColor Yellow
Set-Location "$env:USERPROFILE\Documents"

# Clonar repositório
Write-Host "⚡ Clonando BioDeskPro2..." -ForegroundColor Yellow
git clone https://github.com/NunoCorreia78/BioDeskPRO2.0.git
Set-Location "BioDeskPRO2.0"

# Restaurar dependências
Write-Host "⚡ Restaurando dependências..." -ForegroundColor Yellow
dotnet restore

# Build projeto
Write-Host "⚡ Compilando projeto..." -ForegroundColor Yellow
dotnet build

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Build bem-sucedido!" -ForegroundColor Green
    
    # Executar aplicação
    Write-Host "⚡ Iniciando sistema médico..." -ForegroundColor Yellow
    Write-Host "🩺 O BioDeskPro2 vai abrir com 11 expanders médicos!" -ForegroundColor Cyan
    dotnet run --project src/BioDesk.App
    
} else {
    Write-Host "❌ Erro na compilação!" -ForegroundColor Red
    Write-Host "🔍 Verifique os logs acima" -ForegroundColor Yellow
}

Write-Host "🎉 Setup concluído!" -ForegroundColor Green
```

## 📋 CHECKLIST MANUAL:

### ✅ **Antes de executar:**
1. **Instalar .NET 8 SDK:** https://dotnet.microsoft.com/download/dotnet/8.0
2. **Instalar VS Code:** https://code.visualstudio.com/
3. **Extensão C#:** No VS Code → Ctrl+Shift+X → "C# Dev Kit"

### ✅ **Depois de executar:**
1. **Dashboard** abre automaticamente
2. **"➕ Novo Paciente"** funciona
3. **TAB 2: "📋 Declaração & Anamnese"** existe
4. **11 EXPANDERS** médicos visíveis
5. **Chips + sliders** funcionais

## 🆘 **Se algo falhar:**

```powershell
# Limpar e tentar novamente:
dotnet clean
dotnet restore
dotnet build

# Verificar versão .NET:
dotnet --version  # Deve ser 8.0.x

# Verificar Git:
git --version
git remote -v
```

## 🎯 **Resultado esperado:**
**Sistema médico completo funcionando em ~5 minutos!** 🚀