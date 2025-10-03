# ========================================
# 🚀 BIODESK PRO 2 - BACKUP LIMPO FUNCIONAL
# ========================================
# Data: 2025-10-03
# Status: ✅ SISTEMA 100% FUNCIONAL
# ========================================

$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$nomeBackup = "BioDeskPro2_FUNCIONAL_$timestamp"
$pastaBackups = "C:\Users\Nuno Correia\OneDrive\Documentos\Backups_BioDeskPro2"
$destino = Join-Path $pastaBackups $nomeBackup

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🚀 CRIANDO BACKUP LIMPO" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Criar pasta de backups se não existir
if (-not (Test-Path $pastaBackups)) {
    New-Item -ItemType Directory -Path $pastaBackups -Force | Out-Null
    Write-Host "✅ Pasta de backups criada: $pastaBackups" -ForegroundColor Green
}

# Criar pasta do backup
Write-Host "📁 Criando pasta: $nomeBackup" -ForegroundColor Yellow
New-Item -ItemType Directory -Path $destino -Force | Out-Null

# Copiar APENAS ficheiros essenciais (sem obj/bin/logs)
Write-Host "📋 Copiando ficheiros essenciais..." -ForegroundColor Yellow

$origem = "C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2"

# Pastas a EXCLUIR
$excluir = @(
    "obj",
    "bin",
    "Debug",
    "Release",
    ".vs",
    "node_modules",
    "packages"
)

# Ficheiros a EXCLUIR
$excluirFicheiros = @(
    "*.db-shm",
    "*.db-wal",
    "LOGS_DEBUG.txt",
    "*.log",
    "*.tmp"
)

# Função para verificar se pasta deve ser excluída
function Test-ShouldExclude($path) {
    foreach ($item in $excluir) {
        if ($path -like "*\$item\*" -or $path -like "*\$item") {
            return $true
        }
    }
    return $false
}

# Copiar recursivamente
Get-ChildItem -Path $origem -Recurse | ForEach-Object {
    $relativePath = $_.FullName.Substring($origem.Length)
    $targetPath = Join-Path $destino $relativePath

    # Verificar se deve excluir
    if (Test-ShouldExclude $_.FullName) {
        return
    }

    # Verificar extensão de ficheiro
    $skip = $false
    foreach ($pattern in $excluirFicheiros) {
        if ($_.Name -like $pattern) {
            $skip = $true
            break
        }
    }
    if ($skip) { return }

    # Copiar
    if ($_.PSIsContainer) {
        New-Item -ItemType Directory -Path $targetPath -Force | Out-Null
    } else {
        Copy-Item -Path $_.FullName -Destination $targetPath -Force
    }
}

Write-Host "✅ Ficheiros copiados!" -ForegroundColor Green

# Criar README do backup
$readmeContent = @"
# 🚀 BIODESK PRO 2 - BACKUP FUNCIONAL
**Data:** $(Get-Date -Format "dd/MM/yyyy HH:mm")
**Status:** ✅ SISTEMA 100% FUNCIONAL

## ✅ FUNCIONALIDADES IMPLEMENTADAS:

### 1. Camera sem Freeze (Triple Deadlock Fix)
- StartPreviewAsync sem .Wait()
- StopPreviewAsync com Task.Run + polling assíncrono
- Camera para SEMPRE antes de MessageBox

### 2. UI Irisdiagnóstico Reconstruída
- Grid 2 colunas (galeria + preview)
- Botões icon-only modernos (⊕📷🗑️)
- Preview + Zoom + ColorPicker terroso
- Canvas para marcações

### 3. Paleta de Cores Terrosa
- 4 cores: Vermelho Terroso, Verde Musgo, Azul Petróleo, Amarelo Mostarda
- Seleção visual com bordas dinâmicas

### 4. Botão Remove Funcional (File Lock Fix)
- PathToImageSourceConverter com BitmapCacheOption.OnLoad
- Carrega imagem em memória e liberta ficheiro
- Delete de ficheiros físicos funcionando perfeitamente

## 🏗️ ARQUITETURA:

- .NET 8.0 LTS
- WPF com MVVM (CommunityToolkit.Mvvm)
- Entity Framework Core 8.0.8 + SQLite
- Dependency Injection (Microsoft.Extensions.DependencyInjection)
- FluentValidation para validações
- AForge.NET para câmara USB

## 📂 ESTRUTURA:

\`\`\`
BioDeskPro2/
├── src/
│   ├── BioDesk.App/           # WPF UI
│   ├── BioDesk.ViewModels/    # MVVM ViewModels
│   ├── BioDesk.Domain/        # Entidades
│   ├── BioDesk.Data/          # EF Core + Repositories
│   └── BioDesk.Services/      # Serviços (Navegação, Câmara, etc)
├── global.json                # .NET 8 SDK fixo
└── BioDeskPro2.sln
\`\`\`

## 🎯 BUILD:

\`\`\`powershell
dotnet build
dotnet run --project src/BioDesk.App
\`\`\`

## ✅ STATUS: PRONTO PARA PRODUÇÃO
"@

Set-Content -Path (Join-Path $destino "README_BACKUP.md") -Value $readmeContent -Encoding UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ BACKUP CRIADO COM SUCESSO!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📁 Localização: $destino" -ForegroundColor Yellow
Write-Host ""

# Listar backups antigos
Write-Host "📋 BACKUPS EXISTENTES:" -ForegroundColor Yellow
Get-ChildItem -Path $pastaBackups -Directory | Sort-Object Name | ForEach-Object {
    $tamanho = (Get-ChildItem -Path $_.FullName -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
    Write-Host "   📦 $($_.Name) - $([math]::Round($tamanho, 2)) MB" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "⚠️  PRÓXIMO PASSO: Execute 'APAGAR_BACKUPS_ANTIGOS.ps1' para limpar backups antigos" -ForegroundColor Yellow
Write-Host ""
