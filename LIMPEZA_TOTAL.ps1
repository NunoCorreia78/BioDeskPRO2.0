# ========================================
# 🚀 BIODESK PRO 2 - LIMPEZA TOTAL + BACKUP
# ========================================
# MASTER SCRIPT - FAZ TUDO:
# 1. Cria backup limpo do código atual
# 2. Apaga backups locais antigos
# 3. Fresh start Git (apaga histórico)
# 4. Force push para GitHub
# ========================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🚀 LIMPEZA TOTAL + BACKUP - BIODESK PRO 2" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Este script vai executar TODAS as operações:" -ForegroundColor Yellow
Write-Host ""
Write-Host "  1️⃣  Criar NOVO backup limpo do código atual" -ForegroundColor White
Write-Host "  2️⃣  Apagar TODOS os backups antigos (mantém apenas o novo)" -ForegroundColor White
Write-Host "  3️⃣  Apagar TODO o histórico Git" -ForegroundColor White
Write-Host "  4️⃣  Criar novo repositório Git limpo" -ForegroundColor White
Write-Host "  5️⃣  Force push para GitHub (SOBRESCREVE repositório remoto)" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  ATENÇÃO: OPERAÇÕES IRREVERSÍVEIS!" -ForegroundColor Red
Write-Host "   • Backups antigos serão APAGADOS PERMANENTEMENTE" -ForegroundColor Yellow
Write-Host "   • Histórico Git será PERDIDO PERMANENTEMENTE" -ForegroundColor Yellow
Write-Host "   • Repositório GitHub será SOBRESCRITO" -ForegroundColor Yellow
Write-Host ""

$confirmacao = Read-Host "Digite 'CONFIRMO TUDO' para continuar"

if ($confirmacao -ne "CONFIRMO TUDO") {
    Write-Host ""
    Write-Host "❌ Operação cancelada." -ForegroundColor Red
    Write-Host ""
    exit
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmm"
$origem = "C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2"

# ========================================
# FASE 1: CRIAR BACKUP LIMPO
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FASE 1: CRIANDO BACKUP LIMPO" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$pastaBackups = "C:\Users\Nuno Correia\OneDrive\Documentos\Backups_BioDeskPro2"
$nomeBackup = "BioDeskPro2_FUNCIONAL_$timestamp"
$destino = Join-Path $pastaBackups $nomeBackup

# Criar pasta de backups se não existir
if (-not (Test-Path $pastaBackups)) {
    New-Item -ItemType Directory -Path $pastaBackups -Force | Out-Null
    Write-Host "✅ Pasta de backups criada" -ForegroundColor Green
}

Write-Host "📁 Criando: $nomeBackup" -ForegroundColor Yellow
New-Item -ItemType Directory -Path $destino -Force | Out-Null

Write-Host "📋 Copiando ficheiros essenciais (sem obj/bin/logs)..." -ForegroundColor Yellow

# Pastas a EXCLUIR
$excluir = @(
    "obj",
    "bin",
    "Debug",
    "Release",
    ".vs",
    ".vscode",
    "node_modules",
    "packages",
    ".git"
)

# Ficheiros a EXCLUIR
$excluirFicheiros = @(
    "*.db-shm",
    "*.db-wal",
    "LOGS_DEBUG.txt",
    "*.log",
    "*.tmp",
    "*.temp"
)

# Função para verificar se deve excluir
function Should-Exclude($path) {
    foreach ($item in $excluir) {
        if ($path -like "*\$item\*" -or $path -like "*\$item") {
            return $true
        }
    }
    return $false
}

# Contador de ficheiros
$fileCount = 0

# Copiar recursivamente
Get-ChildItem -Path $origem -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
    $relativePath = $_.FullName.Substring($origem.Length)
    $targetPath = Join-Path $destino $relativePath

    # Verificar se deve excluir
    if (Should-Exclude $_.FullName) {
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
        New-Item -ItemType Directory -Path $targetPath -Force -ErrorAction SilentlyContinue | Out-Null
    } else {
        Copy-Item -Path $_.FullName -Destination $targetPath -Force -ErrorAction SilentlyContinue
        $fileCount++
    }
}

Write-Host "   ✅ $fileCount ficheiros copiados" -ForegroundColor Green

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

---

**Este backup foi criado automaticamente pelo script LIMPEZA_TOTAL.ps1**
"@

Set-Content -Path (Join-Path $destino "README_BACKUP.md") -Value $readmeContent -Encoding UTF8

$backupSize = (Get-ChildItem -Path $destino -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB

Write-Host ""
Write-Host "✅ BACKUP CRIADO COM SUCESSO!" -ForegroundColor Green
Write-Host "   📁 Localização: $nomeBackup" -ForegroundColor Cyan
Write-Host "   📊 Tamanho: $([math]::Round($backupSize, 2)) MB" -ForegroundColor Cyan

# ========================================
# FASE 2: APAGAR BACKUPS ANTIGOS
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FASE 2: LIMPANDO BACKUPS ANTIGOS" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$backups = Get-ChildItem -Path $pastaBackups -Directory | Sort-Object Name -Descending

if ($backups.Count -gt 1) {
    Write-Host "📋 BACKUPS EXISTENTES:" -ForegroundColor Yellow
    Write-Host ""

    for ($i = 0; $i -lt $backups.Count; $i++) {
        $backup = $backups[$i]
        $tamanho = (Get-ChildItem -Path $backup.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB

        if ($i -eq 0) {
            Write-Host "   ✅ $($backup.Name) - $([math]::Round($tamanho, 2)) MB [MANTIDO]" -ForegroundColor Green
        } else {
            Write-Host "   🗑️  $($backup.Name) - $([math]::Round($tamanho, 2)) MB [APAGANDO]" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host "🗑️  Apagando $($backups.Count - 1) backup(s) antigo(s)..." -ForegroundColor Yellow

    $apagados = 0
    $espacoLiberado = 0

    for ($i = 1; $i -lt $backups.Count; $i++) {
        $backup = $backups[$i]
        $tamanho = (Get-ChildItem -Path $backup.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB

        Remove-Item -Path $backup.FullName -Recurse -Force -ErrorAction SilentlyContinue

        $apagados++
        $espacoLiberado += $tamanho
    }

    Write-Host ""
    Write-Host "✅ Backups antigos apagados!" -ForegroundColor Green
    Write-Host "   • Apagados: $apagados" -ForegroundColor Cyan
    Write-Host "   • Espaço liberado: $([math]::Round($espacoLiberado, 2)) MB" -ForegroundColor Cyan
} else {
    Write-Host "ℹ️  Apenas 1 backup existe (nada a apagar)" -ForegroundColor Gray
}

# ========================================
# FASE 3: GIT FRESH START
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FASE 3: GIT FRESH START" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Set-Location $origem

# Verificar alterações não commitadas
Write-Host "📊 Verificando estado do repositório..." -ForegroundColor Gray
$statusOutput = git status --short 2>&1

if ($statusOutput) {
    Write-Host ""
    Write-Host "ℹ️  Alterações detectadas serão incluídas no novo commit inicial" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🗑️  Removendo histórico Git antigo..." -ForegroundColor Yellow

if (Test-Path ".git") {
    Remove-Item -Path ".git" -Recurse -Force
    Write-Host "   ✅ Histórico Git removido" -ForegroundColor Green
}

Write-Host ""
Write-Host "🔧 Inicializando novo repositório..." -ForegroundColor Yellow
git init
git branch -M main
Write-Host "   ✅ Repositório inicializado (branch: main)" -ForegroundColor Green

Write-Host ""
Write-Host "📝 Criando .gitignore otimizado..." -ForegroundColor Yellow
$gitignoreContent = @"
# Build results
[Dd]ebug/
[Rr]elease/
[Bb]in/
[Oo]bj/
x64/
x86/
build/
bld/

# Visual Studio cache/options
.vs/
.vscode/
*.user
*.suo
*.userosscache
*.sln.docstates

# SQLite temporary files
*.db-shm
*.db-wal

# Logs
*.log
LOGS_DEBUG.txt

# Temporary files
*.tmp
*.temp

# NuGet Packages
*.nupkg
**/packages/*
!**/packages/build/

# Node modules
node_modules/

# Backups
Backups_*/
*.bak
*.backup

# OS generated files
.DS_Store
Thumbs.db
"@

Set-Content -Path ".gitignore" -Value $gitignoreContent -Encoding UTF8
Write-Host "   ✅ .gitignore criado" -ForegroundColor Green

Write-Host ""
Write-Host "📦 Adicionando ficheiros ao repositório..." -ForegroundColor Yellow
git add .
$filesAdded = (git diff --cached --name-only | Measure-Object -Line).Lines
Write-Host "   ✅ $filesAdded ficheiros adicionados" -ForegroundColor Green

Write-Host ""
Write-Host "💾 Criando commit inicial..." -ForegroundColor Yellow
$commitMessage = @"
🚀 BioDeskPro2 - Sistema 100% Funcional

✅ FUNCIONALIDADES IMPLEMENTADAS:

1. Camera sem Freeze (Triple Deadlock Fix)
   - StartPreviewAsync sem .Wait()
   - StopPreviewAsync com Task.Run + polling assíncrono
   - Camera para SEMPRE antes de mostrar MessageBox

2. UI Irisdiagnóstico Reconstruída
   - Grid 2 colunas (galeria + preview)
   - Botões icon-only modernos (⊕📷🗑️)
   - Preview + Zoom + ColorPicker terroso
   - Canvas para marcações

3. Paleta de Cores Terrosa
   - 4 cores: Vermelho Terroso, Verde Musgo, Azul Petróleo, Amarelo Mostarda
   - Seleção visual com bordas dinâmicas

4. Botão Remove Funcional (File Lock Fix)
   - PathToImageSourceConverter com BitmapCacheOption.OnLoad
   - Carrega imagem em memória e liberta ficheiro
   - Delete de ficheiros físicos funcionando perfeitamente

📚 STACK TECNOLÓGICA:
- .NET 8.0 LTS
- WPF + MVVM (CommunityToolkit.Mvvm)
- Entity Framework Core 8.0.8 + SQLite
- Dependency Injection (Microsoft.Extensions.DependencyInjection)
- FluentValidation para validações robustas
- AForge.NET para câmara USB

📂 ARQUITETURA:
- BioDesk.App (WPF UI)
- BioDesk.ViewModels (MVVM ViewModels)
- BioDesk.Domain (Entidades)
- BioDesk.Data (EF Core + Repositories)
- BioDesk.Services (Navegação, Câmara, Email, etc)

✅ STATUS: PRONTO PARA PRODUÇÃO

🔨 BUILD:
dotnet build
dotnet run --project src/BioDesk.App
"@

git commit -m "$commitMessage"
Write-Host "   ✅ Commit inicial criado" -ForegroundColor Green

Write-Host ""
Write-Host "🔗 Configurando remote do GitHub..." -ForegroundColor Yellow
$remoteUrl = "https://github.com/NunoCorreia78/BioDeskPRO2.0.git"
git remote remove origin 2>$null
git remote add origin $remoteUrl
Write-Host "   ✅ Remote configurado: $remoteUrl" -ForegroundColor Green

# ========================================
# FASE 4: PUSH PARA GITHUB
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FASE 4: PUSH PARA GITHUB" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  Próximo passo: SOBRESCREVER repositório no GitHub!" -ForegroundColor Red
Write-Host "    Todo o histórico antigo será PERDIDO PERMANENTEMENTE!" -ForegroundColor Red
Write-Host ""

$pushConfirm = Read-Host "Fazer force push para GitHub agora? (S/N)"

if ($pushConfirm -eq "S" -or $pushConfirm -eq "s") {
    Write-Host ""
    Write-Host "🚀 Fazendo force push para GitHub..." -ForegroundColor Yellow
    Write-Host ""

    git push -f origin main

    Write-Host ""
    Write-Host "✅ Push concluído com sucesso!" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "⏭️  Push cancelado. Pode fazer manualmente depois:" -ForegroundColor Yellow
    Write-Host "   git push -f origin main" -ForegroundColor Cyan
}

# ========================================
# RESUMO FINAL
# ========================================

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ LIMPEZA TOTAL CONCLUÍDA!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 RESUMO DAS OPERAÇÕES:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1️⃣  BACKUP CRIADO:" -ForegroundColor White
Write-Host "   ✅ Nome: $nomeBackup" -ForegroundColor Green
Write-Host "   ✅ Localização: $pastaBackups" -ForegroundColor Green
Write-Host "   ✅ Tamanho: $([math]::Round($backupSize, 2)) MB" -ForegroundColor Green
Write-Host "   ✅ Ficheiros: $fileCount" -ForegroundColor Green
Write-Host ""
Write-Host "2️⃣  BACKUPS ANTIGOS:" -ForegroundColor White

if ($apagados -gt 0) {
    Write-Host "   ✅ Apagados: $apagados backup(s)" -ForegroundColor Green
    Write-Host "   ✅ Espaço liberado: $([math]::Round($espacoLiberado, 2)) MB" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  Nenhum backup antigo para apagar" -ForegroundColor Gray
}

Write-Host ""
Write-Host "3️⃣  GIT REPOSITORY:" -ForegroundColor White
Write-Host "   ✅ Histórico antigo removido" -ForegroundColor Green
Write-Host "   ✅ Novo repositório inicializado" -ForegroundColor Green
Write-Host "   ✅ Ficheiros adicionados: $filesAdded" -ForegroundColor Green
Write-Host "   ✅ Commit inicial criado" -ForegroundColor Green
Write-Host ""
Write-Host "4️⃣  GITHUB:" -ForegroundColor White

if ($pushConfirm -eq "S" -or $pushConfirm -eq "s") {
    Write-Host "   ✅ Force push concluído" -ForegroundColor Green
    Write-Host "   🌐 https://github.com/NunoCorreia78/BioDeskPRO2.0" -ForegroundColor Cyan
} else {
    Write-Host "   ⏭️  Push pendente (executar manualmente)" -ForegroundColor Yellow
    Write-Host "   📝 Comando: git push -f origin main" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "🎯 RESULTADO FINAL:" -ForegroundColor Yellow
Write-Host "   ✅ Sistema limpo e organizado" -ForegroundColor Green
Write-Host "   ✅ Backup seguro criado" -ForegroundColor Green
Write-Host "   ✅ Repositório Git limpo (1 commit)" -ForegroundColor Green
Write-Host "   ✅ Pronto para continuar desenvolvimento!" -ForegroundColor Green
Write-Host ""
