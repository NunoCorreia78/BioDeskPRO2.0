# Script Simples para Extrair Logs de Validacao HS3
$hoje = Get-Date -Format "yyyyMMdd"
$logFile = "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\biodesk-$hoje.log"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LOGS DE VALIDACAO HS3" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $logFile)) {
    Write-Host "ERRO: Ficheiro nao encontrado: $logFile" -ForegroundColor Red
    Write-Host ""
    Write-Host "Ficheiros disponiveis:" -ForegroundColor Yellow
    Get-ChildItem "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\biodesk-*.log" | ForEach-Object { Write-Host "  $($_.Name)" }
    exit 1
}

Write-Host "Ficheiro de log: $logFile" -ForegroundColor Green
Write-Host ""
Write-Host "LOGS DE VALIDACAO:" -ForegroundColor Yellow
Write-Host "=" * 80

# Filtrar linhas com "Validating" ou "SetFuncGen" ou "Hardware validation"
Get-Content $logFile -Encoding UTF8 | Where-Object {
    $_ -match "Validating physical hardware" -or
    $_ -match "SetFuncGenFrequency.*returned" -or
    $_ -match "SetFuncGenAmplitude.*returned" -or
    $_ -match "Hardware validation"
} | ForEach-Object {
    if ($_ -match "SetFuncGen") {
        Write-Host $_ -ForegroundColor Cyan
    } elseif ($_ -match "PASSED") {
        Write-Host $_ -ForegroundColor Green
    } elseif ($_ -match "FAILED") {
        Write-Host $_ -ForegroundColor Red
    } else {
        Write-Host $_
    }
}

Write-Host ""
Write-Host "=" * 80
Write-Host ""
Write-Host "Para ver TODOS os logs de hoje:" -ForegroundColor Yellow
Write-Host "  Get-Content '$logFile' -Tail 200" -ForegroundColor Gray
