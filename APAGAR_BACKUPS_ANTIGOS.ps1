# ========================================
# 🗑️ BIODESK PRO 2 - APAGAR BACKUPS ANTIGOS
# ========================================

$pastaBackups = "C:\Users\Nuno Correia\OneDrive\Documentos\Backups_BioDeskPro2"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🗑️  LIMPEZA DE BACKUPS ANTIGOS" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $pastaBackups)) {
    Write-Host "❌ Pasta de backups não existe: $pastaBackups" -ForegroundColor Red
    exit
}

# Listar todos os backups
$backups = Get-ChildItem -Path $pastaBackups -Directory | Sort-Object Name -Descending

if ($backups.Count -eq 0) {
    Write-Host "✅ Nenhum backup encontrado." -ForegroundColor Green
    exit
}

Write-Host "📋 BACKUPS ENCONTRADOS:" -ForegroundColor Yellow
Write-Host ""

for ($i = 0; $i -lt $backups.Count; $i++) {
    $backup = $backups[$i]
    $tamanho = (Get-ChildItem -Path $backup.FullName -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
    $data = $backup.CreationTime.ToString("dd/MM/yyyy HH:mm")

    if ($i -eq 0) {
        Write-Host "   ✅ [$($i+1)] $($backup.Name) - $([math]::Round($tamanho, 2)) MB - $data [MAIS RECENTE]" -ForegroundColor Green
    } else {
        Write-Host "   🗑️  [$($i+1)] $($backup.Name) - $([math]::Round($tamanho, 2)) MB - $data" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "⚠️  ATENÇÃO: Isto vai APAGAR todos os backups EXCETO o mais recente!" -ForegroundColor Yellow
Write-Host ""

$confirmacao = Read-Host "Deseja continuar? (S/N)"

if ($confirmacao -ne "S" -and $confirmacao -ne "s") {
    Write-Host "❌ Operação cancelada." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "🗑️  Apagando backups antigos..." -ForegroundColor Yellow

$apagados = 0
$espacoLiberado = 0

for ($i = 1; $i -lt $backups.Count; $i++) {
    $backup = $backups[$i]
    $tamanho = (Get-ChildItem -Path $backup.FullName -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB

    Write-Host "   🗑️  Apagando: $($backup.Name)..." -ForegroundColor Gray
    Remove-Item -Path $backup.FullName -Recurse -Force

    $apagados++
    $espacoLiberado += $tamanho
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "✅ LIMPEZA CONCLUÍDA!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📊 ESTATÍSTICAS:" -ForegroundColor Yellow
Write-Host "   • Backups apagados: $apagados" -ForegroundColor Cyan
Write-Host "   • Espaço liberado: $([math]::Round($espacoLiberado, 2)) MB" -ForegroundColor Cyan
Write-Host "   • Backup mantido: $($backups[0].Name)" -ForegroundColor Green
Write-Host ""
