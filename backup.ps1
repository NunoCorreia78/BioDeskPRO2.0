# Script de Backup Automático - BioDeskPro2
# Data: 14 de outubro de 2025
# Executa backup completo do código-fonte

$ErrorActionPreference = "Stop"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$projectRoot = $PSScriptRoot
$backupRoot = "C:\Backups\BioDeskPro2"
$backupFolder = Join-Path $backupRoot "backup_$timestamp"

Write-Host "🔄 BioDeskPro2 - Backup Automático" -ForegroundColor Cyan
Write-Host "=" * 60

# Criar pasta de backups se não existe
if (-not (Test-Path $backupRoot)) {
    New-Item -Path $backupRoot -ItemType Directory -Force | Out-Null
    Write-Host "✅ Pasta de backups criada: $backupRoot" -ForegroundColor Green
}

Write-Host "📦 Criando backup em: $backupFolder" -ForegroundColor Yellow

# Criar pasta do backup
New-Item -Path $backupFolder -ItemType Directory -Force | Out-Null

# ===== BACKUP DO CÓDIGO-FONTE =====
Write-Host ""
Write-Host "📁 Copiando código-fonte..." -ForegroundColor Yellow

$foldersToBackup = @(
    "src",
    ".vscode",
    ".github"
)

$filesToBackup = @(
    "BioDeskPro2.sln",
    "global.json",
    "omnisharp.json",
    ".editorconfig",
    ".gitignore",
    "README.md",
    "FLUENTVALIDATION_IMPLEMENTACAO_14OUT2025.md",
    "RELATORIO_SPRINT2_COMPLETO_12OUT2025.md",
    "PLANO_DESENVOLVIMENTO_RESTANTE.md"
)

foreach ($folder in $foldersToBackup) {
    $sourcePath = Join-Path $projectRoot $folder
    $destPath = Join-Path $backupFolder $folder
    
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination $destPath -Recurse -Force
        Write-Host "  ✅ $folder" -ForegroundColor Green
    }
}

foreach ($file in $filesToBackup) {
    $sourcePath = Join-Path $projectRoot $file
    $destPath = Join-Path $backupFolder $file
    
    if (Test-Path $sourcePath) {
        Copy-Item -Path $sourcePath -Destination $destPath -Force
        Write-Host "  ✅ $file" -ForegroundColor Green
    }
}

# ===== ESTATÍSTICAS DO BACKUP =====
Write-Host ""
Write-Host "📊 Estatísticas do Backup:" -ForegroundColor Cyan

$backupSize = (Get-ChildItem -Path $backupFolder -Recurse | Measure-Object -Property Length -Sum).Sum
$backupSizeMB = [math]::Round($backupSize / 1MB, 2)
$fileCount = (Get-ChildItem -Path $backupFolder -Recurse -File).Count

Write-Host "  📦 Tamanho total: $backupSizeMB MB" -ForegroundColor White
Write-Host "  📄 Ficheiros: $fileCount" -ForegroundColor White
Write-Host "  📂 Localização: $backupFolder" -ForegroundColor White

# ===== CRIAR ZIP (OPCIONAL) =====
Write-Host ""
$createZip = Read-Host 'Criar arquivo ZIP? (S/N)'

if ($createZip -eq "S" -or $createZip -eq "s") {
    $zipPath = "$backupFolder.zip"
    Write-Host "📦 Comprimindo backup..." -ForegroundColor Yellow
    
    Compress-Archive -Path $backupFolder -DestinationPath $zipPath -Force
    
    $zipSize = (Get-Item $zipPath).Length
    $zipSizeMB = [math]::Round($zipSize / 1MB, 2)
    
    Write-Host "  ✅ ZIP criado: $zipSizeMB MB" -ForegroundColor Green
    Write-Host "  📂 $zipPath" -ForegroundColor White
}

# ===== LIMPEZA DE BACKUPS ANTIGOS =====
Write-Host ""
Write-Host "🧹 Verificando backups antigos..." -ForegroundColor Yellow

$backupsAntigos = Get-ChildItem -Path $backupRoot -Directory | 
    Where-Object { $_.Name -match "^backup_\d{8}_\d{6}$" } |
    Sort-Object CreationTime -Descending |
    Select-Object -Skip 5

if ($backupsAntigos) {
    Write-Host "  ⚠️  Encontrados $($backupsAntigos.Count) backups com mais de 5 versões" -ForegroundColor Yellow
    $limpar = Read-Host 'Remover backups antigos? (S/N)'
    
    if ($limpar -eq "S" -or $limpar -eq "s") {
        foreach ($backup in $backupsAntigos) {
            Remove-Item -Path $backup.FullName -Recurse -Force
            Write-Host "  🗑️  Removido: $($backup.Name)" -ForegroundColor Gray
        }
        Write-Host "  ✅ Limpeza concluída" -ForegroundColor Green
    }
} else {
    Write-Host "  ✅ Sem backups antigos para remover" -ForegroundColor Green
}

# ===== RESUMO FINAL =====
Write-Host ""
Write-Host "=" * 60
Write-Host "✅ BACKUP CONCLUÍDO COM SUCESSO!" -ForegroundColor Green
Write-Host "=" * 60
Write-Host ""
Write-Host "📂 Backup salvo em:" -ForegroundColor Cyan
Write-Host "   $backupFolder" -ForegroundColor White
Write-Host ""
Write-Host "💡 Dica: Execute este script regularmente para manter backups atualizados" -ForegroundColor Yellow
Write-Host ""

# Pause para ler mensagem
Read-Host 'Pressione ENTER para sair'
