# Script 12: Analisar resultados do API Monitor
# Compara capturas COM vs SEM equipamento

param(
    [string]$ComCsvPath = "",
    [string]$SemCsvPath = ""
)

$ErrorActionPreference = "Stop"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Analise API Monitor - hs3.dll" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Se nao passou parametros, procurar arquivos
if (-not $ComCsvPath) {
    $csvFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.csv" | Where-Object { $_.Name -match "com|equipamento" -and $_.Name -match "api" }
    if ($csvFiles) {
        $ComCsvPath = $csvFiles[0].FullName
        Write-Host "[INFO] Encontrado CSV COM: $($csvFiles[0].Name)" -ForegroundColor Yellow
    }
}

if (-not $SemCsvPath) {
    $csvFiles = Get-ChildItem -Path $PSScriptRoot -Filter "*.csv" | Where-Object { $_.Name -match "sem" -and $_.Name -match "api" }
    if ($csvFiles) {
        $SemCsvPath = $csvFiles[0].FullName
        Write-Host "[INFO] Encontrado CSV SEM: $($csvFiles[0].Name)" -ForegroundColor Yellow
    }
}

# Validar arquivos
if (-not $ComCsvPath -or -not (Test-Path $ComCsvPath)) {
    Write-Host "[ERRO] Arquivo COM nao encontrado!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Use:" -ForegroundColor Yellow
    Write-Host "  .\12_AnalyzeAPIMonitorResults.ps1 -ComCsvPath 'path\to\com.csv' -SemCsvPath 'path\to\sem.csv'" -ForegroundColor White
    Write-Host ""
    Write-Host "Ou exporte de API Monitor:" -ForegroundColor Yellow
    Write-Host "  File → Export → CSV" -ForegroundColor White
    exit 1
}

if (-not $SemCsvPath -or -not (Test-Path $SemCsvPath)) {
    Write-Host "[ERRO] Arquivo SEM nao encontrado!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Use:" -ForegroundColor Yellow
    Write-Host "  .\12_AnalyzeAPIMonitorResults.ps1 -ComCsvPath 'path\to\com.csv' -SemCsvPath 'path\to\sem.csv'" -ForegroundColor White
    exit 1
}

Write-Host "[OK] Arquivos encontrados:" -ForegroundColor Green
Write-Host "  COM: $ComCsvPath" -ForegroundColor White
Write-Host "  SEM: $SemCsvPath" -ForegroundColor White
Write-Host ""

# Carregar CSVs
Write-Host "[INFO] Carregando eventos..." -ForegroundColor Yellow
try {
    $comEvents = Import-Csv -Path $ComCsvPath -Encoding UTF8
    $semEvents = Import-Csv -Path $SemCsvPath -Encoding UTF8
    Write-Host "[OK] COM Equipamento: $($comEvents.Count) eventos" -ForegroundColor Green
    Write-Host "[OK] SEM Equipamento: $($semEvents.Count) eventos" -ForegroundColor Green
}
catch {
    Write-Host "[ERRO] Falha ao carregar CSVs: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " ANALISE" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# ==================================================
# ANALISE 1: Funcoes de hs3.dll chamadas
# ==================================================
Write-Host "[ANALISE 1] Funcoes de hs3.dll" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$hs3FunctionsCom = $comEvents | Where-Object {
    $_."API Name" -or $_."Module" -match "hs3" -or $_."Function" -match "^(Init|Set|Emit|Close|Get|HS3_)"
} | Select-Object -Property @{Name="Function";Expression={$_."API Name" -or $_."Function"}},
                             @{Name="ReturnValue";Expression={$_."Return Value" -or $_."Result"}},
                             @{Name="Parameters";Expression={$_."Parameters" -or $_."Details"}}

$hs3FunctionsSem = $semEvents | Where-Object {
    $_."API Name" -or $_."Module" -match "hs3" -or $_."Function" -match "^(Init|Set|Emit|Close|Get|HS3_)"
} | Select-Object -Property @{Name="Function";Expression={$_."API Name" -or $_."Function"}},
                             @{Name="ReturnValue";Expression={$_."Return Value" -or $_."Result"}},
                             @{Name="Parameters";Expression={$_."Parameters" -or $_."Details"}}

if ($hs3FunctionsCom.Count -gt 0) {
    Write-Host "[OK] COM Equipamento: $($hs3FunctionsCom.Count) chamadas hs3.dll" -ForegroundColor Green
    $hs3FunctionsCom | Select-Object -First 10 | Format-Table -AutoSize
}
else {
    Write-Host "[AVISO] Nenhuma funcao hs3.dll capturada COM equipamento" -ForegroundColor Yellow
}

if ($hs3FunctionsSem.Count -gt 0) {
    Write-Host "[OK] SEM Equipamento: $($hs3FunctionsSem.Count) chamadas hs3.dll" -ForegroundColor Green
    $hs3FunctionsSem | Select-Object -First 10 | Format-Table -AutoSize
}
else {
    Write-Host "[AVISO] Nenhuma funcao hs3.dll capturada SEM equipamento" -ForegroundColor Yellow
}

Write-Host ""

# ==================================================
# ANALISE 2: Funcoes exclusivas COM equipamento
# ==================================================
Write-Host "[ANALISE 2] Funcoes Exclusivas COM Equipamento" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$functionNamesCom = $hs3FunctionsCom | Select-Object -ExpandProperty Function -Unique
$functionNamesSem = $hs3FunctionsSem | Select-Object -ExpandProperty Function -Unique

$exclusivas = $functionNamesCom | Where-Object { $_ -and $_ -notin $functionNamesSem }

if ($exclusivas) {
    Write-Host "[DESCOBERTA] Funcoes chamadas APENAS COM equipamento:" -ForegroundColor Green
    foreach ($func in $exclusivas) {
        Write-Host "  ✅ $func" -ForegroundColor White
        $detalhes = $hs3FunctionsCom | Where-Object { $_.Function -eq $func }
        if ($detalhes) {
            Write-Host "     Return Values: $($detalhes.ReturnValue -join ', ')" -ForegroundColor Gray
        }
    }
    Write-Host ""
    Write-Host "[IMPORTANTE] Estas funcoes SAO candidatas para validacao!" -ForegroundColor Yellow
}
else {
    Write-Host "[INFO] Nenhuma funcao exclusiva detectada" -ForegroundColor Yellow
}

Write-Host ""

# ==================================================
# ANALISE 3: Return Values Diferentes
# ==================================================
Write-Host "[ANALISE 3] Return Values Diferentes" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$funcoesComuns = $functionNamesCom | Where-Object { $_ -and $_ -in $functionNamesSem }

$returnValuesDiff = @()

foreach ($func in $funcoesComuns) {
    $returnsCom = ($hs3FunctionsCom | Where-Object { $_.Function -eq $func }).ReturnValue | Select-Object -Unique
    $returnsSem = ($hs3FunctionsSem | Where-Object { $_.Function -eq $func }).ReturnValue | Select-Object -Unique

    if ($returnsCom -ne $returnsSem) {
        $returnValuesDiff += [PSCustomObject]@{
            Function = $func
            ReturnCOM = $returnsCom -join ", "
            ReturnSEM = $returnsSem -join ", "
        }
    }
}

if ($returnValuesDiff.Count -gt 0) {
    Write-Host "[DESCOBERTA] Funcoes com return values diferentes:" -ForegroundColor Green
    $returnValuesDiff | Format-Table -AutoSize
    Write-Host "[IMPORTANTE] Estas funcoes PODEM indicar status de hardware!" -ForegroundColor Yellow
}
else {
    Write-Host "[INFO] Nenhuma diferenca em return values detectada" -ForegroundColor Yellow
}

Write-Host ""

# ==================================================
# ANALISE 4: LoadLibrary de hs3.dll
# ==================================================
Write-Host "[ANALISE 4] Carregamento de hs3.dll" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$loadLibraryCom = $comEvents | Where-Object {
    ($_."API Name" -eq "LoadLibrary" -or $_."Function" -eq "LoadLibrary") -and
    ($_.Parameters -match "hs3\.dll" -or $_."Path" -match "hs3\.dll")
}

$loadLibrarySem = $semEvents | Where-Object {
    ($_."API Name" -eq "LoadLibrary" -or $_."Function" -eq "LoadLibrary") -and
    ($_.Parameters -match "hs3\.dll" -or $_."Path" -match "hs3\.dll")
}

if ($loadLibraryCom) {
    Write-Host "[OK] COM: hs3.dll carregada" -ForegroundColor Green
    Write-Host "     Return Value: $($loadLibraryCom.'Return Value' -or $loadLibraryCom.Result)" -ForegroundColor Gray
}

if ($loadLibrarySem) {
    Write-Host "[OK] SEM: hs3.dll carregada" -ForegroundColor Green
    Write-Host "     Return Value: $($loadLibrarySem.'Return Value' -or $loadLibrarySem.Result)" -ForegroundColor Gray
}

Write-Host ""

# ==================================================
# ANALISE 5: GetProcAddress (busca de funcoes)
# ==================================================
Write-Host "[ANALISE 5] GetProcAddress (descobrir funcoes)" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$getProcCom = $comEvents | Where-Object {
    $_."API Name" -eq "GetProcAddress" -or $_."Function" -eq "GetProcAddress"
} | Select-Object -Property @{Name="Module";Expression={$_.Module}},
                             @{Name="Function";Expression={$_.Parameters -replace '.*"([^"]+)".*','$1'}},
                             @{Name="Address";Expression={$_."Return Value" -or $_.Result}}

if ($getProcCom.Count -gt 0) {
    Write-Host "[OK] Funcoes buscadas via GetProcAddress:" -ForegroundColor Green
    $getProcCom | Where-Object { $_.Function -match "HS3|Init|Set|Emit|Get" } | Format-Table -AutoSize
}
else {
    Write-Host "[INFO] Nenhum GetProcAddress capturado" -ForegroundColor Yellow
}

Write-Host ""

# ==================================================
# CONCLUSOES
# ==================================================
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " CONCLUSOES" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

$descobertas = @()

if ($exclusivas) {
    Write-Host "[✅] DESCOBERTA CRITICA: Funcoes exclusivas COM equipamento!" -ForegroundColor Green
    Write-Host "    Implementar estas funcoes em BioDeskPro2 para validacao" -ForegroundColor White
    $descobertas += "Funcoes exclusivas: $($exclusivas -join ', ')"
}

if ($returnValuesDiff.Count -gt 0) {
    Write-Host "[✅] DESCOBERTA: Return values diferentes!" -ForegroundColor Green
    Write-Host "    Usar return values para detectar hardware" -ForegroundColor White
    $descobertas += "Return values diferentes em: $($returnValuesDiff.Function -join ', ')"
}

if (-not $exclusivas -and $returnValuesDiff.Count -eq 0) {
    Write-Host "[⚠️] ATENCAO: Nenhuma diferenca significativa detectada" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Possiveis causas:" -ForegroundColor Yellow
    Write-Host "  1. Filtros API Monitor nao capturaram funcoes hs3.dll" -ForegroundColor White
    Write-Host "  2. Hook customizado nao configurado corretamente" -ForegroundColor White
    Write-Host "  3. Validacao ocorre dentro de funcao (nao capturavel)" -ForegroundColor White
    Write-Host ""
    Write-Host "Proximos passos:" -ForegroundColor Cyan
    Write-Host "  - Verificar se hook hs3.dll esta ativo no API Monitor" -ForegroundColor White
    Write-Host "  - Re-capturar com filtros mais amplos" -ForegroundColor White
    Write-Host "  - OU implementar Opcao A (UX Defensiva)" -ForegroundColor White
}

Write-Host ""

# Salvar relatorio
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = "$PSScriptRoot\..\Logs\APIMonitor\Analise\RELATORIO_API_$timestamp.txt"
$reportDir = Split-Path $reportPath
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

$report = @"
====================================================
 RELATORIO ANALISE API MONITOR
====================================================
Data: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")

Arquivos analisados:
- COM: $ComCsvPath
- SEM: $SemCsvPath

Eventos:
- COM Equipamento: $($comEvents.Count) eventos
- SEM Equipamento: $($semEvents.Count) eventos

[ANALISE 1] Funcoes hs3.dll
- COM: $($hs3FunctionsCom.Count) chamadas
- SEM: $($hs3FunctionsSem.Count) chamadas

[ANALISE 2] Funcoes Exclusivas COM Equipamento
$(if ($exclusivas) { "ENCONTRADAS:`n" + ($exclusivas | ForEach-Object { "  - $_" }) -join "`n" } else { "Nenhuma funcao exclusiva" })

[ANALISE 3] Return Values Diferentes
$(if ($returnValuesDiff.Count -gt 0) { ($returnValuesDiff | Format-Table | Out-String) } else { "Nenhuma diferenca detectada" })

[CONCLUSOES]
$(if ($descobertas) { ($descobertas | ForEach-Object { "✅ $_" }) -join "`n" } else { "⚠️ Nenhuma diferenca significativa detectada" })

====================================================
"@

$report | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Relatorio salvo em:" -ForegroundColor Green
Write-Host "  $reportPath" -ForegroundColor White
Write-Host ""
