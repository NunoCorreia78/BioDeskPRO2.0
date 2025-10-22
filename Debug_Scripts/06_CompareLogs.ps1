# Script 6: Comparar logs de diferentes cenarios (Conectado vs Desconectado)
# Identifica diferencas criticas que indicam metodo de validacao

$ErrorActionPreference = "Continue"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Comparacao de Logs - Conectado vs Desconectado" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

$logsFolder = "$PSScriptRoot\..\Logs\ProcessMonitor"

# Listar logs disponiveis
$csvFiles = Get-ChildItem -Path $logsFolder -Filter "*.csv" -ErrorAction SilentlyContinue

if (-not $csvFiles -or $csvFiles.Count -lt 2) {
    Write-Host "[ERRO] Necessita de pelo menos 2 logs CSV para comparacao!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Execute os testes:" -ForegroundColor Yellow
    Write-Host "  TESTE 1: Hardware Conectado → Salvar como ProcMon_CoRe_Conectado.CSV" -ForegroundColor White
    Write-Host "  TESTE 2: Hardware Desconectado → Salvar como ProcMon_CoRe_Desconectado.CSV" -ForegroundColor White
    exit 1
}

Write-Host "Arquivos CSV disponiveis:" -ForegroundColor Green
Write-Host ""
for ($i = 0; $i -lt $csvFiles.Count; $i++) {
    Write-Host "  [$i] $($csvFiles[$i].Name)" -ForegroundColor Cyan
}
Write-Host ""

Write-Host "Escolha o log de HARDWARE CONECTADO (numero): " -NoNewline -ForegroundColor Yellow
$idx1 = [int](Read-Host)
Write-Host "Escolha o log de HARDWARE DESCONECTADO (numero): " -NoNewline -ForegroundColor Yellow
$idx2 = [int](Read-Host)

if ($idx1 -lt 0 -or $idx1 -ge $csvFiles.Count -or $idx2 -lt 0 -or $idx2 -ge $csvFiles.Count) {
    Write-Host "[ERRO] Indices invalidos!" -ForegroundColor Red
    exit 1
}

$logConectado = $csvFiles[$idx1].FullName
$logDesconectado = $csvFiles[$idx2].FullName

Write-Host ""
Write-Host "[INFO] Carregando logs..." -ForegroundColor Yellow
$eventsConectado = Import-Csv -Path $logConectado -Encoding UTF8
$eventsDesconectado = Import-Csv -Path $logDesconectado -Encoding UTF8

Write-Host "[OK] Conectado: $($eventsConectado.Count) eventos" -ForegroundColor Green
Write-Host "[OK] Desconectado: $($eventsDesconectado.Count) eventos" -ForegroundColor Green
Write-Host ""

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " COMPARACAO DE DIFERENCAS" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# === COMPARACAO 1: DLLs carregadas APENAS quando conectado ===
Write-Host "[COMPARACAO 1] DLLs carregadas APENAS com hardware conectado" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$dllsConectado = $eventsConectado | Where-Object { $_.Operation -match "Load Image" } | Select-Object -ExpandProperty Path
$dllsDesconectado = $eventsDesconectado | Where-Object { $_.Operation -match "Load Image" } | Select-Object -ExpandProperty Path

$dllsExclusivas = $dllsConectado | Where-Object { $_ -notin $dllsDesconectado }

if ($dllsExclusivas) {
    Write-Host "[DESCOBERTA] DLLs carregadas APENAS quando conectado:" -ForegroundColor Green
    $dllsExclusivas | Select-Object -Unique | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Yellow
    }
}
else {
    Write-Host "[INFO] Mesmas DLLs carregadas em ambos os cenarios" -ForegroundColor Gray
}

Write-Host ""

# === COMPARACAO 2: Registry keys APENAS quando conectado ===
Write-Host "[COMPARACAO 2] Registry keys acessadas APENAS com hardware conectado" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$regConectado = $eventsConectado | Where-Object { $_.Operation -match "Reg" } | Select-Object -ExpandProperty Path
$regDesconectado = $eventsDesconectado | Where-Object { $_.Operation -match "Reg" } | Select-Object -ExpandProperty Path

$regExclusivas = $regConectado | Where-Object { $_ -notin $regDesconectado }

if ($regExclusivas) {
    Write-Host "[DESCOBERTA] Registry keys EXCLUSIVAS quando conectado:" -ForegroundColor Green
    $regExclusivas | Select-Object -Unique -First 20 | ForEach-Object {
        Write-Host "  - $_" -ForegroundColor Yellow
    }
    if ($regExclusivas.Count -gt 20) {
        Write-Host "  ... e mais $($regExclusivas.Count - 20) keys" -ForegroundColor Gray
    }
}
else {
    Write-Host "[INFO] Mesmas registry keys em ambos os cenarios" -ForegroundColor Gray
}

Write-Host ""

# === COMPARACAO 3: Operacoes SUCCESS vs FAILURE ===
Write-Host "[COMPARACAO 3] Operacoes com resultados diferentes" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

# Agrupar por Operation+Path e comparar Results
$opsConectado = $eventsConectado | Group-Object { "$($_.Operation)|$($_.Path)" }
$opsDesconectado = $eventsDesconectado | Group-Object { "$($_.Operation)|$($_.Path)" }

$diferencasResultado = @()

foreach ($opC in $opsConectado) {
    $key = $opC.Name
    $opD = $opsDesconectado | Where-Object { $_.Name -eq $key }

    if ($opD) {
        $resultC = ($opC.Group | Select-Object -First 1).Result
        $resultD = ($opD.Group | Select-Object -First 1).Result

        if ($resultC -ne $resultD) {
            $parts = $key -split '\|'
            $diferencasResultado += [PSCustomObject]@{
                Operation = $parts[0]
                Path = $parts[1]
                ResultConectado = $resultC
                ResultDesconectado = $resultD
            }
        }
    }
}

if ($diferencasResultado) {
    Write-Host "[DESCOBERTA CRITICA] Operacoes com resultados diferentes:" -ForegroundColor Red
    Write-Host ""
    $diferencasResultado | Select-Object -First 30 | ForEach-Object {
        Write-Host "  [$($_.Operation)]" -ForegroundColor Cyan
        Write-Host "    Path: $($_.Path)" -ForegroundColor White
        Write-Host "    Conectado: $($_.ResultConectado)" -ForegroundColor Green
        Write-Host "    Desconectado: $($_.ResultDesconectado)" -ForegroundColor Yellow
        Write-Host ""
    }

    if ($diferencasResultado.Count -gt 30) {
        Write-Host "  ... e mais $($diferencasResultado.Count - 30) diferencas" -ForegroundColor Gray
    }
}
else {
    Write-Host "[INFO] Nenhuma diferenca significativa em resultados" -ForegroundColor Gray
}

Write-Host ""

# === COMPARACAO 4: USB VID:PID ===
Write-Host "[COMPARACAO 4] Dispositivos USB detectados" -ForegroundColor Cyan
Write-Host "----------------------------------------------------" -ForegroundColor Gray

$usbConectado = $eventsConectado | Where-Object { $_.Path -match "VID_[0-9A-F]{4}&PID_[0-9A-F]{4}" }
$usbDesconectado = $eventsDesconectado | Where-Object { $_.Path -match "VID_[0-9A-F]{4}&PID_[0-9A-F]{4}" }

if ($usbConectado) {
    Write-Host "[CONECTADO] VID:PID detectados:" -ForegroundColor Green
    $usbConectado | ForEach-Object {
        if ($_.Path -match "(VID_[0-9A-F]{4}&PID_[0-9A-F]{4})") {
            Write-Host "  - $($matches[1])" -ForegroundColor Cyan
        }
    } | Select-Object -Unique
}

if ($usbDesconectado) {
    Write-Host "[DESCONECTADO] VID:PID detectados:" -ForegroundColor Yellow
    $usbDesconectado | ForEach-Object {
        if ($_.Path -match "(VID_[0-9A-F]{4}&PID_[0-9A-F]{4})") {
            Write-Host "  - $($matches[1])" -ForegroundColor Cyan
        }
    } | Select-Object -Unique
}

Write-Host ""
Write-Host "=====================================================" -ForegroundColor Green
Write-Host " CONCLUSOES" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host ""

Write-Host "Analise os itens marcados como [DESCOBERTA CRITICA]" -ForegroundColor Yellow
Write-Host "Estes indicam o metodo que o CoRe usa para validacao!" -ForegroundColor Yellow
Write-Host ""
Write-Host "Procurar por:" -ForegroundColor Cyan
Write-Host "  - Registry keys USB especificas" -ForegroundColor White
Write-Host "  - Operacoes SUCCESS vs FAILURE em CreateFile/DeviceIoControl" -ForegroundColor White
Write-Host "  - VID:PID do TiePie HS3" -ForegroundColor White
Write-Host ""
