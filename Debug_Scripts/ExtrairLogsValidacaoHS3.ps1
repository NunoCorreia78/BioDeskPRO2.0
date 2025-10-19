# ========================================
# Script para Extrair Logs de Validação HS3
# ========================================
# Este script procura e extrai as linhas específicas da validação de hardware HS3

$hoje = Get-Date -Format "yyyyMMdd"
$logFile = "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\biodesk-$hoje.log"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  EXTRATOR DE LOGS DE VALIDAÇÃO HS3" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar se o ficheiro de log existe
if (-not (Test-Path $logFile)) {
    Write-Host "❌ ERRO: Ficheiro de log não encontrado!" -ForegroundColor Red
    Write-Host "   Esperado: $logFile" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Ficheiros de log disponíveis:" -ForegroundColor Yellow
    Get-ChildItem "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\biodesk-*.log" |
        ForEach-Object { Write-Host "   - $($_.Name)" -ForegroundColor Gray }
    exit 1
}

Write-Host "✅ Ficheiro de log encontrado: $logFile" -ForegroundColor Green
Write-Host ""

# Ler todo o conteúdo do log
$logContent = Get-Content $logFile -Encoding UTF8

# Procurar pelas linhas de validação
$validacaoLinhas = @()
$capturando = $false

for ($i = 0; $i -lt $logContent.Count; $i++) {
    $linha = $logContent[$i]

    # Detectar início da validação
    if ($linha -match "Validating physical hardware connection") {
        $capturando = $true
        $validacaoLinhas += ""
        $validacaoLinhas += "=" * 80
        $validacaoLinhas += "BLOCO DE VALIDAÇÃO ENCONTRADO:"
        $validacaoLinhas += "=" * 80
    }

    # Capturar linhas relevantes
    if ($capturando) {
        $validacaoLinhas += $linha

        # Parar após a linha de conclusão
        if ($linha -match "Hardware validation (PASSED|FAILED)") {
            $capturando = $false
            $validacaoLinhas += "=" * 80
            $validacaoLinhas += ""
        }
    }
}

# Mostrar resultados
if ($validacaoLinhas.Count -eq 0) {
    Write-Host "⚠️  NENHUMA validação encontrada no log!" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Últimas 50 linhas do log (para diagnóstico):" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Gray
    $logContent | Select-Object -Last 50 | ForEach-Object { Write-Host $_ -ForegroundColor Gray }
} else {
    Write-Host "🎯 LOGS DE VALIDAÇÃO EXTRAÍDOS:" -ForegroundColor Green
    Write-Host ""

    foreach ($linha in $validacaoLinhas) {
        # Colorir linhas importantes
        if ($linha -match "SetFuncGenFrequency.*returned") {
            Write-Host $linha -ForegroundColor Cyan
        } elseif ($linha -match "SetFuncGenAmplitude.*returned") {
            Write-Host $linha -ForegroundColor Cyan
        } elseif ($linha -match "PASSED") {
            Write-Host $linha -ForegroundColor Green
        } elseif ($linha -match "FAILED") {
            Write-Host $linha -ForegroundColor Red
        } elseif ($linha -match "====") {
            Write-Host $linha -ForegroundColor Yellow
        } else {
            Write-Host $linha
        }
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Total de blocos de validação: $([math]::Floor($validacaoLinhas.Count / 10))" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📋 Para copiar TODOS os logs de hoje:" -ForegroundColor Yellow
Write-Host "   Get-Content '$logFile' -Tail 200" -ForegroundColor Gray
