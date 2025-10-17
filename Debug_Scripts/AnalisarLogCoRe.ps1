# AnalisarLogCoRe.ps1
# Analisa log do Process Monitor exportado como CSV
# Extrai chamadas LibTiePie e operacoes de arquivo

param(
    [Parameter(Mandatory=$true)]
    [string]$LogPath
)

Write-Host "=== ANALISE LOG PROCESS MONITOR (CoRe) ===" -ForegroundColor Cyan
Write-Host ""

# Verificar se arquivo existe
if (-not (Test-Path $LogPath)) {
    Write-Host "ERRO: Log nao encontrado: $LogPath" -ForegroundColor Red
    exit 1
}

Write-Host "Lendo log: $LogPath" -ForegroundColor White
$log = Import-Csv -Path $LogPath

Write-Host "Total de eventos: $($log.Count)" -ForegroundColor Green
Write-Host ""

# Filtrar eventos relevantes
Write-Host "Filtrando eventos relevantes..." -ForegroundColor Cyan

# 1. Operacoes com libtiepie.dll
$libtiepieOps = $log | Where-Object { $_.Path -like "*libtiepie*" }
Write-Host "   - Operacoes libtiepie.dll: $($libtiepieOps.Count)" -ForegroundColor White

# 2. Leitura de arquivos .TXT (programas de frequencias)
$txtReads = $log | Where-Object { $_.Path -like "*.txt" -and $_.Operation -eq "ReadFile" }
Write-Host "   - Leituras de .TXT: $($txtReads.Count)" -ForegroundColor White

# 3. Operacoes de Registry (configuracoes)
$regOps = $log | Where-Object { $_.Path -like "*CoRe*" -and $_.Operation -like "Reg*" }
Write-Host "   - Operacoes Registry: $($regOps.Count)" -ForegroundColor White

Write-Host ""

# Analise detalhada
Write-Host "=== ANALISE DETALHADA ===" -ForegroundColor Yellow
Write-Host ""

# 1. Arquivos de frequencias lidos
if ($txtReads.Count -gt 0) {
    Write-Host "Arquivos de Frequencias Carregados:" -ForegroundColor Cyan
    $txtReads | Select-Object -Unique Path | ForEach-Object {
        $filename = Split-Path $_.Path -Leaf
        Write-Host "   - $filename" -ForegroundColor White

        # Tentar ler conteudo
        if (Test-Path $_.Path) {
            Write-Host "     Primeiras 5 linhas:" -ForegroundColor Gray
            Get-Content $_.Path -First 5 | ForEach-Object {
                Write-Host "     $_" -ForegroundColor Gray
            }
        }
        Write-Host ""
    }
}

# 2. Sequencia de operacoes LibTiePie
if ($libtiepieOps.Count -gt 0) {
    Write-Host "Sequencia Operacoes LibTiePie:" -ForegroundColor Cyan
    $libtiepieOps | Select-Object -First 20 Time, Operation, Path, Detail | ForEach-Object {
        $op = $_.Operation
        $detail = if ($_.Detail.Length -gt 50) { $_.Detail.Substring(0, 50) + "..." } else { $_.Detail }
        Write-Host "   [$($_.Time)] $op - $detail" -ForegroundColor White
    }
    if ($libtiepieOps.Count -gt 20) {
        Write-Host "   ... e mais $($libtiepieOps.Count - 20) operacoes" -ForegroundColor Gray
    }
    Write-Host ""
}

# 3. Configuracoes do Registry
if ($regOps.Count -gt 0) {
    Write-Host "Configuracoes Registry (CoRe):" -ForegroundColor Cyan
    $regOps | Select-Object -Unique Path | ForEach-Object {
        Write-Host "   - $($_.Path)" -ForegroundColor White
    }
    Write-Host ""
}

# 4. Padroes de frequencias (se conseguirmos extrair dos .TXT)
Write-Host "Analise de Padroes de Frequencias:" -ForegroundColor Cyan
$txtReads | Select-Object -Unique Path | ForEach-Object {
    if (Test-Path $_.Path) {
        $content = Get-Content $_.Path

        # Procurar padroes numericos (frequencias em Hz)
        $frequencies = $content | Select-String -Pattern "\d+\.?\d*\s*Hz" -AllMatches | ForEach-Object { $_.Matches.Value }

        if ($frequencies) {
            Write-Host "   Arquivo: $(Split-Path $_.Path -Leaf)" -ForegroundColor White
            Write-Host "   Frequencias detectadas: $($frequencies.Count)" -ForegroundColor White
            $freqList = $frequencies | Select-Object -First 5
            Write-Host "   Exemplos: $($freqList -join ', ')" -ForegroundColor Gray
            Write-Host ""
        }
    }
}

# 5. Timeline de emissoes
Write-Host "Timeline de Emissoes:" -ForegroundColor Cyan
$emissionEvents = $log | Where-Object {
    $_.Detail -like "*GenStart*" -or
    $_.Detail -like "*GenStop*" -or
    $_.Detail -like "*frequency*" -or
    $_.Detail -like "*amplitude*"
}

if ($emissionEvents.Count -gt 0) {
    Write-Host "   Total de eventos de emissao: $($emissionEvents.Count)" -ForegroundColor White

    $emissionEvents | Select-Object -First 10 Time, Detail | ForEach-Object {
        Write-Host "   [$($_.Time)] $($_.Detail)" -ForegroundColor White
    }

    if ($emissionEvents.Count -gt 10) {
        Write-Host "   ... e mais $($emissionEvents.Count - 10) eventos" -ForegroundColor Gray
    }
} else {
    Write-Host "   Nenhum evento de emissao detectado" -ForegroundColor Yellow
    Write-Host "   (Talvez seja necessario captura com API Monitor mais detalhada)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== RELATORIO GERADO ===" -ForegroundColor Green
Write-Host ""
Write-Host "Dicas para proxima captura:" -ForegroundColor Cyan
Write-Host "   1. Usar API Monitor para capturar parametros de funcao" -ForegroundColor White
Write-Host "   2. Capturar durante execucao de terapia completa (inicio ao fim)" -ForegroundColor White
Write-Host "   3. Anotar manualmente: frequencia inicial, final, duracao" -ForegroundColor White
Write-Host ""
