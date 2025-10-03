# ========================================
# 🧹 BIODESK PRO 2 - LIMPEZA COMPLETA
# ========================================
# Apaga backups antigos + Fresh start Git
# ========================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🧹 LIMPEZA COMPLETA - BIODESK PRO 2" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Este script vai:" -ForegroundColor Yellow
Write-Host "  1️⃣  Apagar TODOS os backups locais antigos (mantém apenas o mais recente)" -ForegroundColor Gray
Write-Host "  2️⃣  Apagar TODO o histórico Git antigo" -ForegroundColor Gray
Write-Host "  3️⃣  Criar novo repositório Git limpo" -ForegroundColor Gray
Write-Host "  4️⃣  Fazer force push para GitHub (SOBRESCREVE repositório remoto)" -ForegroundColor Gray
Write-Host ""
Write-Host "⚠️  ATENÇÃO: OPERAÇÕES IRREVERSÍVEIS!" -ForegroundColor Red
Write-Host ""

$confirmacao = Read-Host "Digite 'CONFIRMO' para continuar"

if ($confirmacao -ne "CONFIRMO") {
    Write-Host ""
    Write-Host "❌ Operação cancelada." -ForegroundColor Red
    Write-Host ""
    exit
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FASE 1: LIMPEZA DE BACKUPS LOCAIS" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$pastaBackups = "C:\Users\Nuno Correia\OneDrive\Documentos\Backups_BioDeskPro2"

if (Test-Path $pastaBackups) {
    $backups = Get-ChildItem -Path $pastaBackups -Directory | Sort-Object Name -Descending

    if ($backups.Count -gt 0) {
        Write-Host "📋 BACKUPS ENCONTRADOS:" -ForegroundColor Yellow
        Write-Host ""

        for ($i = 0; $i -lt $backups.Count; $i++) {
            $backup = $backups[$i]
            $tamanho = (Get-ChildItem -Path $backup.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB
            $data = $backup.CreationTime.ToString("dd/MM/yyyy HH:mm")

            if ($i -eq 0) {
                Write-Host "   ✅ $($backup.Name) - $([math]::Round($tamanho, 2)) MB - $data [SERÁ MANTIDO]" -ForegroundColor Green
            } else {
                Write-Host "   🗑️  $($backup.Name) - $([math]::Round($tamanho, 2)) MB - $data [SERÁ APAGADO]" -ForegroundColor Gray
            }
        }

        if ($backups.Count -gt 1) {
            Write-Host ""
            Write-Host "🗑️  Apagando $($backups.Count - 1) backup(s) antigo(s)..." -ForegroundColor Yellow

            $apagados = 0
            $espacoLiberado = 0

            for ($i = 1; $i -lt $backups.Count; $i++) {
                $backup = $backups[$i]
                $tamanho = (Get-ChildItem -Path $backup.FullName -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1MB

                Write-Host "   🗑️  Apagando: $($backup.Name)..." -ForegroundColor Gray
                Remove-Item -Path $backup.FullName -Recurse -Force -ErrorAction SilentlyContinue

                $apagados++
                $espacoLiberado += $tamanho
            }

            Write-Host ""
            Write-Host "✅ Backups limpos!" -ForegroundColor Green
            Write-Host "   • Apagados: $apagados" -ForegroundColor Cyan
            Write-Host "   • Espaço liberado: $([math]::Round($espacoLiberado, 2)) MB" -ForegroundColor Cyan
            Write-Host "   • Mantido: $($backups[0].Name)" -ForegroundColor Green
        } else {
            Write-Host ""
            Write-Host "✅ Apenas 1 backup existe (nada a apagar)" -ForegroundColor Green
        }
    } else {
        Write-Host "ℹ️  Nenhum backup encontrado" -ForegroundColor Gray
    }
} else {
    Write-Host "ℹ️  Pasta de backups não existe" -ForegroundColor Gray
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FASE 2: GIT FRESH START" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$repoPath = "C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2"
Set-Location $repoPath

# Verificar se tem alterações não commitadas
Write-Host "📊 Verificando estado do repositório..." -ForegroundColor Gray
$statusOutput = git status --short 2>&1

if ($statusOutput) {
    Write-Host ""
    Write-Host "⚠️  ATENÇÃO: Existem alterações não commitadas:" -ForegroundColor Yellow
    Write-Host $statusOutput -ForegroundColor Gray
    Write-Host ""
    Write-Host "Estas alterações vão ser incluídas no novo commit inicial." -ForegroundColor Yellow
    Write-Host ""

    $continuar = Read-Host "Continuar assim mesmo? (S/N)"
    if ($continuar -ne "S" -and $continuar -ne "s") {
        Write-Host ""
        Write-Host "❌ Operação cancelada. Faça commit das alterações primeiro." -ForegroundColor Red
        Write-Host ""
        exit
    }
}

Write-Host ""
Write-Host "🗑️  Removendo histórico Git antigo..." -ForegroundColor Yellow

if (Test-Path ".git") {
    Remove-Item -Path ".git" -Recurse -Force
    Write-Host "   ✅ Histórico Git removido" -ForegroundColor Green
} else {
    Write-Host "   ℹ️  Repositório Git não existe" -ForegroundColor Gray
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

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "FASE 3: PUSH PARA GITHUB" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  O próximo passo vai SOBRESCREVER completamente o repositório no GitHub!" -ForegroundColor Red
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
    Write-Host ""
    Write-Host "🌐 Repositório GitHub atualizado:" -ForegroundColor Cyan
    Write-Host "   https://github.com/NunoCorreia78/BioDeskPRO2.0" -ForegroundColor Cyan
} else {
    Write-Host ""
    Write-Host "⏭️  Push cancelado. Pode fazer manualmente depois:" -ForegroundColor Yellow
    Write-Host "   git push -f origin main" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ LIMPEZA COMPLETA CONCLUÍDA!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 RESUMO:" -ForegroundColor Yellow
Write-Host "   ✅ Backups antigos apagados (mantido apenas o mais recente)" -ForegroundColor Green
Write-Host "   ✅ Histórico Git limpo (1 commit inicial)" -ForegroundColor Green
Write-Host "   ✅ .gitignore otimizado" -ForegroundColor Green

if ($pushConfirm -eq "S" -or $pushConfirm -eq "s") {
    Write-Host "   ✅ Repositório GitHub atualizado" -ForegroundColor Green
}

Write-Host ""
Write-Host "🎯 PRÓXIMOS PASSOS:" -ForegroundColor Yellow
Write-Host "   1. Verifique o repositório no GitHub" -ForegroundColor Cyan
Write-Host "   2. Clone em outras máquinas (se necessário)" -ForegroundColor Cyan
Write-Host "   3. Continue desenvolvendo! 🚀" -ForegroundColor Cyan
Write-Host ""
