# Script 8: Re-captura com filtros expandidos
# Captura TODAS as operacoes relevantes do InergetixCoRe.exe

$ErrorActionPreference = "Stop"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Re-captura Process Monitor - Filtros EXPANDIDOS" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] Os logs anteriores capturaram APENAS 'Load Image' de hs3.dll" -ForegroundColor Yellow
Write-Host "[INFO] Precisamos capturar TODAS as operacoes do processo!" -ForegroundColor Yellow
Write-Host ""

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " NOVA CONFIGURACAO DE FILTROS" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "No Process Monitor, configure APENAS 1 FILTRO:" -ForegroundColor Green
Write-Host ""
Write-Host "  Filter -> Filter... -> RESET (limpar todos)" -ForegroundColor White
Write-Host ""
Write-Host "  Adicionar filtro UNICO:" -ForegroundColor Yellow
Write-Host "    [Process Name] [is] [InergetixCoRe.exe] [Include] [Add]" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Apply -> OK" -ForegroundColor White
Write-Host ""

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " TESTE 1: COM EQUIPAMENTO (Re-captura)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Conectar HS3 ao USB" -ForegroundColor White
Write-Host "2. Fechar InergetixCoRe (se aberto)" -ForegroundColor White
Write-Host "3. Process Monitor: Edit -> Clear Display (Ctrl+X)" -ForegroundColor White
Write-Host "4. Process Monitor: Iniciar captura (Ctrl+E - lupa VERDE)" -ForegroundColor White
Write-Host "5. Lancar InergetixCoRe.exe" -ForegroundColor White
Write-Host "6. Aguardar deteccao do HS3 (~15 segundos)" -ForegroundColor White
Write-Host "7. Process Monitor: Parar captura (Ctrl+E - lupa CINZA)" -ForegroundColor White
Write-Host "8. File -> Save -> CSV -> Nome: " -ForegroundColor White
Write-Host "   LogComEquipamento.csv" -ForegroundColor Cyan
Write-Host "   (salvar em: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts\)" -ForegroundColor Gray
Write-Host ""

Write-Host "Pressione ENTER quando terminar TESTE 1..." -ForegroundColor Yellow
Read-Host

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " TESTE 2: SEM EQUIPAMENTO (Re-captura)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "1. Fechar InergetixCoRe" -ForegroundColor White
Write-Host "2. DESCONECTAR HS3 do USB" -ForegroundColor White
Write-Host "3. Process Monitor: Edit -> Clear Display (Ctrl+X)" -ForegroundColor White
Write-Host "4. Process Monitor: Iniciar captura (Ctrl+E - lupa VERDE)" -ForegroundColor White
Write-Host "5. Lancar InergetixCoRe.exe" -ForegroundColor White
Write-Host "6. Observar erro/aviso (~15 segundos)" -ForegroundColor White
Write-Host "7. Process Monitor: Parar captura (Ctrl+E - lupa CINZA)" -ForegroundColor White
Write-Host "8. File -> Save -> CSV -> Nome: " -ForegroundColor White
Write-Host "   LogSemEquipamento.csv" -ForegroundColor Cyan
Write-Host "   (salvar em: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts\)" -ForegroundColor Gray
Write-Host ""

Write-Host "Pressione ENTER quando terminar TESTE 2..." -ForegroundColor Yellow
Read-Host

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host " TESTES COMPLETOS!" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Verificando arquivos..." -ForegroundColor Yellow
$scriptDir = $PSScriptRoot
$logCom = Join-Path $scriptDir "LogComEquipamento.csv"
$logSem = Join-Path $scriptDir "LogSemEquipamento.csv"

if (Test-Path $logCom) {
    $tamanhoCom = (Get-Item $logCom).Length
    Write-Host "[OK] LogComEquipamento.csv: $tamanhoCom bytes" -ForegroundColor Green
}
else {
    Write-Host "[AVISO] LogComEquipamento.csv nao encontrado!" -ForegroundColor Yellow
}

if (Test-Path $logSem) {
    $tamanhoSem = (Get-Item $logSem).Length
    Write-Host "[OK] LogSemEquipamento.csv: $tamanhoSem bytes" -ForegroundColor Green
}
else {
    Write-Host "[AVISO] LogSemEquipamento.csv nao encontrado!" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " PROXIMO PASSO" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Execute a analise completa:" -ForegroundColor Yellow
Write-Host "  .\09_AnalyzeExpandedLogs.ps1" -ForegroundColor White
Write-Host ""
