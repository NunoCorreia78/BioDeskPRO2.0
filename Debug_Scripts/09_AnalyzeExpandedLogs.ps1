# Script 9: Analise COMPLETA dos logs expandidos
# Identifica diferencas criticas entre COM e SEM equipamento

param(
    [string]$LogComPath = "$PSScriptRoot\LogComEquipamento.csv",
    [string]$LogSemPath = "$PSScriptRoot\LogSemEquipamento.csv"
)

$ErrorActionPreference = "Continue"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " ANALISE COMPLETA - COM vs SEM Equipamento" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Verificar arquivos
if (-not (Test-Path $LogComPath)) {
    Write-Host "[ERRO] Arquivo nao encontrado: $LogComPath" -ForegroundColor Red
    Write-Host "Execute primeiro: .\08_RecaptureWithExpandedFilters.ps1" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path $LogSemPath)) {
    Write-Host "[ERRO] Arquivo nao encontrado: $LogSemPath" -ForegroundColor Red
    Write-Host "Execute primeiro: .\08_RecaptureWithExpandedFilters.ps1" -ForegroundColor Yellow
    exit 1
}

# Carregar logs
Write-Host "[INFO] Carregando logs..." -ForegroundColor Yellow
$eventsCom = Import-Csv -Path $LogComPath -Encoding UTF8
$eventsSem = Import-Csv -Path $LogSemPath -Encoding UTF8

Write-Host "[OK] COM Equipamento: $($eventsCom.Count) eventos" -ForegroundColor Green
Write-Host "[OK] SEM Equipamento: $($eventsSem.Count) eventos" -ForegroundColor Green
Write-Host ""

# Criar pasta de relatorio
$reportDir = "$PSScriptRoot\..\Logs\ProcessMonitor\Analise"
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

$reportPath = "$reportDir\RELATORIO_ANALISE_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$reportContent = @()

$reportContent += "="*80
$reportContent += " RELATORIO DE ANALISE - Inergetix CoRe vs TiePie HS3"
$reportContent += " Data: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')"
$reportContent += "="*80
$reportContent += ""

# === ANALISE 1: Registry USB ===
Write-Host "[ANALISE 1] Acessos ao Registry USB" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$reportContent += "-"*80
$reportContent += "[ANALISE 1] REGISTRY USB - Procurando VID:PID"
$reportContent += "-"*80
$reportContent += ""

$regUsbCom = $eventsCom | Where-Object {
    $_.Path -match "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB" -or
    $_.Path -match "USB\\VID_" -or
    $_.Path -match "USBSTOR"
}

$regUsbSem = $eventsSem | Where-Object {
    $_.Path -match "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB" -or
    $_.Path -match "USB\\VID_" -or
    $_.Path -match "USBSTOR"
}

if ($regUsbCom) {
    Write-Host "[DESCOBERTA] COM Equipamento: $($regUsbCom.Count) acessos USB registry" -ForegroundColor Green
    $reportContent += "COM Equipamento: $($regUsbCom.Count) acessos ao registry USB"
    $reportContent += ""

    # Procurar VID:PID
    $vidPids = @{}
    foreach ($reg in $regUsbCom) {
        if ($reg.Path -match "(VID_[0-9A-F]{4}&PID_[0-9A-F]{4})") {
            $vidPid = $matches[1]
            if (-not $vidPids.ContainsKey($vidPid)) {
                $vidPids[$vidPid] = @()
            }
            $vidPids[$vidPid] += $reg
        }
    }

    if ($vidPids.Count -gt 0) {
        Write-Host ""
        Write-Host "[CRITICO] VID:PID detectados:" -ForegroundColor Yellow
        $reportContent += "VID:PID DETECTADOS (Candidatos a TiePie HS3):"
        $reportContent += ""
        foreach ($vp in $vidPids.Keys) {
            Write-Host "  - $vp ($($vidPids[$vp].Count) acessos)" -ForegroundColor Cyan
            $reportContent += "  $vp - $($vidPids[$vp].Count) acessos"
            $reportContent += "    Primeira ocorrencia: $($vidPids[$vp][0].Path)"
        }
        $reportContent += ""
    }
}
else {
    Write-Host "[INFO] Nenhum acesso USB registry detectado COM equipamento" -ForegroundColor Gray
    $reportContent += "COM Equipamento: Nenhum acesso USB registry detectado"
    $reportContent += ""
}

if ($regUsbSem) {
    Write-Host "[INFO] SEM Equipamento: $($regUsbSem.Count) acessos USB registry" -ForegroundColor Yellow
    $reportContent += "SEM Equipamento: $($regUsbSem.Count) acessos USB registry"
}
else {
    Write-Host "[INFO] SEM Equipamento: Nenhum acesso USB registry" -ForegroundColor Gray
    $reportContent += "SEM Equipamento: Nenhum acesso USB registry"
}

Write-Host ""
$reportContent += ""

# === ANALISE 2: CreateFile / DeviceIoControl ===
Write-Host "[ANALISE 2] Operacoes de Dispositivo (CreateFile/DeviceIoControl)" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$reportContent += "-"*80
$reportContent += "[ANALISE 2] OPERACOES DE DISPOSITIVO"
$reportContent += "-"*80
$reportContent += ""

$deviceOpsCom = $eventsCom | Where-Object {
    $_.Operation -match "CreateFile|DeviceIoControl|QueryInformation" -and
    ($_.Path -match "\\Device\\|\\DosDevices\\|\\\.\\")
}

$deviceOpsSem = $eventsSem | Where-Object {
    $_.Operation -match "CreateFile|DeviceIoControl|QueryInformation" -and
    ($_.Path -match "\\Device\\|\\DosDevices\\|\\\.\\")
}

$deviceExclusivos = $deviceOpsCom | Where-Object {
    $path = $_.Path
    $op = $_.Operation
    -not ($deviceOpsSem | Where-Object { $_.Path -eq $path -and $_.Operation -eq $op })
}

if ($deviceExclusivos) {
    Write-Host "[DESCOBERTA CRITICA] Operacoes EXCLUSIVAS com equipamento:" -ForegroundColor Red
    $reportContent += "OPERACOES EXCLUSIVAS quando equipamento CONECTADO:"
    $reportContent += ""

    $deviceExclusivos | Select-Object -First 20 | ForEach-Object {
        Write-Host "  [$($_.'Time of Day')] $($_.Operation)" -ForegroundColor Yellow
        Write-Host "    Path: $($_.Path)" -ForegroundColor White
        Write-Host "    Result: $($_.Result)" -ForegroundColor $(if ($_.Result -eq "SUCCESS") { "Green" } else { "Yellow" })

        $reportContent += "  [$($_.'Time of Day')] $($_.Operation)"
        $reportContent += "    Path: $($_.Path)"
        $reportContent += "    Result: $($_.Result)"
        $reportContent += ""
    }

    if ($deviceExclusivos.Count -gt 20) {
        Write-Host "  ... e mais $($deviceExclusivos.Count - 20) operacoes" -ForegroundColor Gray
        $reportContent += "  [... e mais $($deviceExclusivos.Count - 20) operacoes]"
    }
}
else {
    Write-Host "[INFO] Nenhuma operacao exclusiva detectada" -ForegroundColor Gray
    $reportContent += "Nenhuma operacao de dispositivo exclusiva"
}

Write-Host ""
$reportContent += ""

# === ANALISE 3: DLLs e Funcoes ===
Write-Host "[ANALISE 3] DLLs Carregadas" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$reportContent += "-"*80
$reportContent += "[ANALISE 3] DLLs CARREGADAS"
$reportContent += "-"*80
$reportContent += ""

$dllsCom = $eventsCom | Where-Object { $_.Operation -match "Load Image" } | Select-Object -ExpandProperty Path -Unique
$dllsSem = $eventsSem | Where-Object { $_.Operation -match "Load Image" } | Select-Object -ExpandProperty Path -Unique

$dllsExclusivas = $dllsCom | Where-Object { $_ -notin $dllsSem }

if ($dllsExclusivas) {
    Write-Host "[DESCOBERTA] DLLs carregadas APENAS com equipamento:" -ForegroundColor Green
    $reportContent += "DLLs carregadas APENAS quando equipamento CONECTADO:"
    $reportContent += ""

    $dllsExclusivas | Where-Object { $_ -match "usb|device|setup|tiepie|hs3" } | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Yellow
        $reportContent += "  $_"
    }
    $reportContent += ""
}
else {
    Write-Host "[INFO] Mesmas DLLs em ambos os cenarios" -ForegroundColor Gray
    $reportContent += "Mesmas DLLs carregadas em ambos os cenarios"
    $reportContent += ""
}

Write-Host ""

# === ANALISE 4: Resultados SUCCESS vs FAILURE ===
Write-Host "[ANALISE 4] Diferencas em Resultados de Operacoes" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$reportContent += "-"*80
$reportContent += "[ANALISE 4] SUCCESS vs FAILURE"
$reportContent += "-"*80
$reportContent += ""

$opsComHash = @{}
$eventsCom | ForEach-Object {
    $key = "$($_.Operation)|$($_.Path)"
    $opsComHash[$key] = $_.Result
}

$opsSemHash = @{}
$eventsSem | ForEach-Object {
    $key = "$($_.Operation)|$($_.Path)"
    $opsSemHash[$key] = $_.Result
}

$diferencas = @()
foreach ($key in $opsComHash.Keys) {
    if ($opsSemHash.ContainsKey($key)) {
        if ($opsComHash[$key] -ne $opsSemHash[$key]) {
            $parts = $key -split '\|'
            $diferencas += [PSCustomObject]@{
                Operation = $parts[0]
                Path = $parts[1]
                ComEquipamento = $opsComHash[$key]
                SemEquipamento = $opsSemHash[$key]
            }
        }
    }
}

if ($diferencas) {
    Write-Host "[DESCOBERTA CRITICA] Operacoes com resultados diferentes:" -ForegroundColor Red
    $reportContent += "OPERACOES COM RESULTADOS DIFERENTES:"
    $reportContent += ""

    $diferencas | Select-Object -First 30 | ForEach-Object {
        Write-Host "  [$($_.Operation)]" -ForegroundColor Cyan
        Write-Host "    Path: $($_.Path)" -ForegroundColor White
        Write-Host "    COM: $($_.ComEquipamento)" -ForegroundColor Green
        Write-Host "    SEM: $($_.SemEquipamento)" -ForegroundColor Yellow
        Write-Host ""

        $reportContent += "  [$($_.Operation)]"
        $reportContent += "    Path: $($_.Path)"
        $reportContent += "    COM Equipamento: $($_.ComEquipamento)"
        $reportContent += "    SEM Equipamento: $($_.SemEquipamento)"
        $reportContent += ""
    }

    if ($diferencas.Count -gt 30) {
        Write-Host "  ... e mais $($diferencas.Count - 30) diferencas" -ForegroundColor Gray
        $reportContent += "  [... e mais $($diferencas.Count - 30) diferencas]"
    }
}
else {
    Write-Host "[INFO] Nenhuma diferenca significativa em resultados" -ForegroundColor Gray
    $reportContent += "Nenhuma diferenca significativa em resultados"
}

Write-Host ""
$reportContent += ""

# === CONCLUSOES ===
$reportContent += "="*80
$reportContent += "CONCLUSOES E RECOMENDACOES"
$reportContent += "="*80
$reportContent += ""

Write-Host "=====================================================" -ForegroundColor Green
Write-Host " CONCLUSOES" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""

if ($vidPids.Count -gt 0) {
    Write-Host "[SUCESSO] VID:PID do HS3 identificado!" -ForegroundColor Green
    Write-Host "Implementar deteccao USB no BioDeskPro2" -ForegroundColor Cyan
    $reportContent += "METODO DE VALIDACAO IDENTIFICADO:"
    $reportContent += "  - Deteccao via VID:PID USB"
    $reportContent += "  - Implementar USB Device Enumeration"
    foreach ($vp in $vidPids.Keys) {
        $reportContent += "  - Candidato: $vp"
    }
}
elseif ($deviceExclusivos -and $deviceExclusivos.Count -gt 0) {
    Write-Host "[SUCESSO] Operacoes de dispositivo exclusivas identificadas!" -ForegroundColor Green
    Write-Host "Analisar CreateFile/DeviceIoControl patterns" -ForegroundColor Cyan
    $reportContent += "METODO DE VALIDACAO IDENTIFICADO:"
    $reportContent += "  - Operacoes CreateFile/DeviceIoControl especificas"
    $reportContent += "  - Analisar paths exclusivos"
}
elseif ($diferencas.Count -gt 0) {
    Write-Host "[SUCESSO] Diferencas em resultados identificadas!" -ForegroundColor Green
    Write-Host "Analisar operacoes SUCCESS vs FAILURE" -ForegroundColor Cyan
    $reportContent += "METODO DE VALIDACAO IDENTIFICADO:"
    $reportContent += "  - Diferencias em resultados de operacoes"
    $reportContent += "  - Verificar paths com SUCCESS/FAILURE alternados"
}
else {
    Write-Host "[AVISO] Nenhuma diferenca significativa detectada" -ForegroundColor Yellow
    Write-Host "Pode ser necessario capturar mais eventos ou usar filtros diferentes" -ForegroundColor Yellow
    $reportContent += "ATENCAO: Nenhuma diferenca critica identificada"
    $reportContent += "  - Capturar mais eventos"
    $reportContent += "  - Verificar se CoRe realmente detecta hardware"
    $reportContent += "  - Considerar usar API Monitor para funcoes DLL"
}

$reportContent += ""
$reportContent += "="*80
$reportContent += "FIM DO RELATORIO"
$reportContent += "="*80

# Salvar relatorio
$reportContent | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host ""
Write-Host "Relatorio salvo em:" -ForegroundColor Green
Write-Host "  $reportPath" -ForegroundColor White
Write-Host ""
