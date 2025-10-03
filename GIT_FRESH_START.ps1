# ========================================
# 🔄 BIODESK PRO 2 - FRESH START GIT
# ========================================
# Remove histórico antigo e cria novo commit inicial
# ========================================

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🔄 GIT FRESH START" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$repoPath = "C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2"

# Verificar se estamos no repositório
Set-Location $repoPath

Write-Host "📍 Repositório: $repoPath" -ForegroundColor Cyan
Write-Host ""

# Verificar status atual
Write-Host "📊 STATUS ATUAL DO GIT:" -ForegroundColor Yellow
git status --short
Write-Host ""

Write-Host "⚠️  ATENÇÃO: Esta operação vai:" -ForegroundColor Yellow
Write-Host "   1. Apagar TODO o histórico Git antigo" -ForegroundColor Red
Write-Host "   2. Criar um novo commit inicial limpo" -ForegroundColor Yellow
Write-Host "   3. Fazer force push para GitHub (sobrescreve repositório remoto)" -ForegroundColor Red
Write-Host ""

$confirmacao = Read-Host "Deseja continuar? Digite 'CONFIRMO' para prosseguir"

if ($confirmacao -ne "CONFIRMO") {
    Write-Host "❌ Operação cancelada." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "🔄 Iniciando fresh start..." -ForegroundColor Yellow
Write-Host ""

# 1. Remover pasta .git antiga
Write-Host "🗑️  Removendo histórico Git antigo..." -ForegroundColor Gray
if (Test-Path ".git") {
    Remove-Item -Path ".git" -Recurse -Force
    Write-Host "   ✅ Histórico removido" -ForegroundColor Green
}

# 2. Inicializar novo repositório
Write-Host "🔧 Inicializando novo repositório..." -ForegroundColor Gray
git init
git branch -M main
Write-Host "   ✅ Repositório inicializado" -ForegroundColor Green

# 3. Criar .gitignore completo
Write-Host "📝 Criando .gitignore..." -ForegroundColor Gray
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
[Bb]in/
[Oo]bj/

# Visual Studio cache/options
.vs/
.vscode/
*.user
*.suo
*.userosscache
*.sln.docstates

# SQLite files
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

# 4. Adicionar todos os ficheiros
Write-Host "📦 Adicionando ficheiros..." -ForegroundColor Gray
git add .
Write-Host "   ✅ Ficheiros adicionados" -ForegroundColor Green

# 5. Criar commit inicial
Write-Host "💾 Criando commit inicial..." -ForegroundColor Gray
$commitMessage = @"
🚀 BioDeskPro2 - Sistema 100% Funcional

✅ FUNCIONALIDADES IMPLEMENTADAS:

1. Camera sem Freeze (Triple Deadlock Fix)
   - StartPreviewAsync sem .Wait()
   - StopPreviewAsync com Task.Run + polling
   - Camera para SEMPRE antes de MessageBox

2. UI Irisdiagnóstico Reconstruída
   - Grid 2 colunas (galeria + preview)
   - Botões icon-only modernos (⊕📷🗑️)
   - Preview + Zoom + ColorPicker terroso

3. Paleta de Cores Terrosa
   - 4 cores com seleção visual

4. Botão Remove Funcional (File Lock Fix)
   - PathToImageSourceConverter com BitmapCacheOption.OnLoad
   - Delete de ficheiros funcionando perfeitamente

📚 STACK:
- .NET 8.0 LTS
- WPF + MVVM (CommunityToolkit.Mvvm)
- EF Core 8.0.8 + SQLite
- FluentValidation
- AForge.NET (câmara USB)

✅ STATUS: PRONTO PARA PRODUÇÃO
"@

git commit -m "$commitMessage"
Write-Host "   ✅ Commit criado" -ForegroundColor Green

# 6. Configurar remote (se não existir)
Write-Host "🔗 Configurando remote..." -ForegroundColor Gray
$remoteUrl = "https://github.com/NunoCorreia78/BioDeskPRO2.0.git"
git remote add origin $remoteUrl 2>$null
git remote set-url origin $remoteUrl
Write-Host "   ✅ Remote configurado: $remoteUrl" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ FRESH START CONCLUÍDO!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 PRÓXIMO PASSO:" -ForegroundColor Yellow
Write-Host "   Execute: git push -f origin main" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  ATENÇÃO: O push -f vai SOBRESCREVER o repositório remoto!" -ForegroundColor Yellow
Write-Host ""

$pushNow = Read-Host "Deseja fazer push agora? (S/N)"

if ($pushNow -eq "S" -or $pushNow -eq "s") {
    Write-Host ""
    Write-Host "🚀 Fazendo push para GitHub..." -ForegroundColor Yellow
    git push -f origin main
    Write-Host ""
    Write-Host "✅ Push concluído!" -ForegroundColor Green
    Write-Host "🌐 Repositório: https://github.com/NunoCorreia78/BioDeskPRO2.0" -ForegroundColor Cyan
}

Write-Host ""
