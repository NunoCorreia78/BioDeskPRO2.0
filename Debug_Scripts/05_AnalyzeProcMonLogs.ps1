# Script 5: Analisar logs CSV do Process Monitor
# Procura padroes de validacao, emissao e chamadas de funcoes

param(
    [string]$LogPath = "",
    [switch]$All
)

$ErrorActionPreference = "Continue"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Analise de Logs Process Monitor - Inergetix CoRe" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Pasta de logs
$logsFolder = "$PSScriptRoot\..\Logs\ProcessMonitor"

# Se nao especificou arquivo, listar disponiveis
if ([string]::IsNullOrEmpty($LogPath)) {
    Write-Host "[INFO] Procurando logs CSV em: $logsFolder" -ForegroundColor Yellow
    Write-Host ""

    if (-not (Test-Path $logsFolder)) {
        Write-Host "[ERRO] Pasta de logs nao encontrada!" -ForegroundColor Red
        Write-Host "Certifique-se de ter exportado os logs do Process Monitor em formato CSV." -ForegroundColor Yellow
        exit 1
    }

    $csvFiles = Get-ChildItem -Path $logsFolder -Filter "*.csv" | Sort-Object LastWriteTime -Descending

    if ($csvFiles.Count -eq 0) {
        Write-Host "[ERRO] Nenhum arquivo CSV encontrado em $logsFolder" -ForegroundColor Red
        Write-Host ""
        Write-Host "Exportar logs do Process Monitor:" -ForegroundColor Yellow
        Write-Host "  1. No Process Monitor: File → Save" -ForegroundColor White
        Write-Host "  2. Format: CSV" -ForegroundColor White
        Write-Host "  3. Salvar em: $logsFolder" -ForegroundColor White
        exit 1
    }

    Write-Host "Arquivos CSV disponiveis:" -ForegroundColor Green
    Write-Host ""
    for ($i = 0; $i -lt $csvFiles.Count; $i++) {
        $file = $csvFiles[$i]
        $tamanho = "{0:N0}" -f $file.Length
        $data = $file.LastWriteTime.ToString("dd/MM/yyyy HH:mm:ss")
        Write-Host "  [$i] $($file.Name)" -ForegroundColor Cyan
        Write-Host "      Tamanho: $tamanho bytes | Modificado: $data" -ForegroundColor Gray
    }
    Write-Host ""

    if (-not $All) {
        Write-Host "Escolha um arquivo (numero) ou 'A' para analisar todos: " -NoNewline -ForegroundColor Yellow
        $escolha = Read-Host

        if ($escolha -eq "A" -or $escolha -eq "a") {
            $All = $true
        }
        else {
            $index = [int]$escolha
            if ($index -ge 0 -and $index -lt $csvFiles.Count) {
                $LogPath = $csvFiles[$index].FullName
            }
            else {
                Write-Host "[ERRO] Escolha invalida!" -ForegroundColor Red
                exit 1
            }
        }
    }
}

# Funcao para analisar um log
function Analyze-ProcMonLog {
    param([string]$FilePath)

    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " ANALISANDO: $([System.IO.Path]::GetFileName($FilePath))" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""

    # Importar CSV
    Write-Host "[INFO] Carregando CSV..." -ForegroundColor Yellow
    try {
        $events = Import-Csv -Path $FilePath -Encoding UTF8
        Write-Host "[OK] $($events.Count) eventos carregados" -ForegroundColor Green
    }
    catch {
        Write-Host "[ERRO] Falha ao carregar CSV: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    if ($events.Count -eq 0) {
        Write-Host "[AVISO] Arquivo CSV vazio!" -ForegroundColor Yellow
        return
    }

    Write-Host ""

    # === ANALISE 1: DLLs Carregadas ===
    Write-Host "[ANALISE 1] DLLs Carregadas" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------" -ForegroundColor Gray

    $dllLoads = $events | Where-Object {
        $_.Operation -match "Load Image" -and $_.Path -match "\.dll$"
    }

    $hs3Dll = $dllLoads | Where-Object { $_.Path -match "hs3\.dll" }
    if ($hs3Dll) {
        Write-Host "[ENCONTRADO] hs3.dll carregada!" -ForegroundColor Green
        Write-Host "  Path: $($hs3Dll[0].Path)" -ForegroundColor White
        Write-Host "  Timestamp: $($hs3Dll[0].'Time of Day')" -ForegroundColor Gray
        Write-Host "  Result: $($hs3Dll[0].Result)" -ForegroundColor Gray
    }
    else {
        Write-Host "[NAO ENCONTRADO] hs3.dll nao foi carregada neste log" -ForegroundColor Yellow
    }

    # Outras DLLs relevantes
    $relevantDlls = $dllLoads | Where-Object {
        $_.Path -match "tiepie|usb|setup|device|kernel32|advapi32"
    }
    if ($relevantDlls) {
        Write-Host ""
        Write-Host "Outras DLLs relevantes:" -ForegroundColor Cyan
        $relevantDlls | Select-Object -First 10 Path, Result | ForEach-Object {
            Write-Host "  - $($_.Path)" -ForegroundColor White
        }
    }

    Write-Host ""

    # === ANALISE 2: Registry Access ===
    Write-Host "[ANALISE 2] Acessos ao Registry" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------" -ForegroundColor Gray

    $regOps = $events | Where-Object {
        $_.Operation -match "Reg(Query|Open|Read)" -and
        $_.Path -match "usb|device|hardware|tiepie|hs3"
    }

    if ($regOps) {
        Write-Host "[ENCONTRADO] $($regOps.Count) acessos ao registry relacionados" -ForegroundColor Green
        $regOps | Select-Object -First 20 Path, Operation, Result | ForEach-Object {
            Write-Host "  [$($_.Operation)] $($_.Path)" -ForegroundColor White
            if ($_.Result -ne "SUCCESS") {
                Write-Host "    Result: $($_.Result)" -ForegroundColor Yellow
            }
        }
    }
    else {
        Write-Host "[NAO ENCONTRADO] Nenhum acesso relevante ao registry" -ForegroundColor Gray
    }

    Write-Host ""

    # === ANALISE 3: File Operations ===
    Write-Host "[ANALISE 3] Operacoes de Arquivo" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------" -ForegroundColor Gray

    $fileOps = $events | Where-Object {
        ($_.Operation -match "CreateFile|ReadFile|WriteFile|QueryInformation") -and
        ($_.Path -match "hs3|tiepie|config|device" -or $_.Path -match "\.ini$|\.cfg$|\.xml$")
    }

    if ($fileOps) {
        Write-Host "[ENCONTRADO] $($fileOps.Count) operacoes de arquivo relevantes" -ForegroundColor Green
        $fileOps | Select-Object -First 20 Path, Operation, Result | ForEach-Object {
            Write-Host "  [$($_.Operation)] $($_.Path)" -ForegroundColor White
        }
    }
    else {
        Write-Host "[NAO ENCONTRADO] Nenhuma operacao relevante de arquivo" -ForegroundColor Gray
    }

    Write-Host ""

    # === ANALISE 4: Sequencia Temporal ===
    Write-Host "[ANALISE 4] Sequencia Temporal de Eventos" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------" -ForegroundColor Gray

    # Eventos criticos em ordem
    $criticalEvents = $events | Where-Object {
        $_.Path -match "hs3\.dll" -or
        $_.Path -match "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB" -or
        $_.Operation -match "Load Image" -and $_.Path -match "tiepie"
    } | Select-Object -First 30 'Time of Day', Operation, Path, Result

    if ($criticalEvents) {
        Write-Host "[SEQUENCIA] Primeiros 30 eventos criticos:" -ForegroundColor Green
        $criticalEvents | ForEach-Object {
            $time = $_.'Time of Day'
            Write-Host "  [$time] $($_.Operation)" -ForegroundColor Cyan
            Write-Host "    $($_.Path)" -ForegroundColor White
            if ($_.Result -ne "SUCCESS") {
                Write-Host "    Result: $($_.Result)" -ForegroundColor Yellow
            }
        }
    }

    Write-Host ""

    # === ANALISE 5: Padroes USB ===
    Write-Host "[ANALISE 5] Deteccao de Dispositivos USB" -ForegroundColor Cyan
    Write-Host "----------------------------------------------------" -ForegroundColor Gray

    $usbEvents = $events | Where-Object {
        $_.Path -match "USB\\VID_|\\Device\\|SetupAPI|USBSTOR"
    }

    if ($usbEvents) {
        Write-Host "[ENCONTRADO] $($usbEvents.Count) eventos relacionados com USB" -ForegroundColor Green

        # Procurar VID:PID
        $vidPidPattern = $usbEvents | Where-Object { $_.Path -match "VID_[0-9A-F]{4}&PID_[0-9A-F]{4}" }
        if ($vidPidPattern) {
            Write-Host ""
            Write-Host "VID:PID detectados:" -ForegroundColor Yellow
            $vidPidPattern | ForEach-Object {
                if ($_.Path -match "(VID_[0-9A-F]{4}&PID_[0-9A-F]{4})") {
                    $vidPid = $matches[1]
                    Write-Host "  - $vidPid" -ForegroundColor Cyan
                    Write-Host "    Path completo: $($_.Path)" -ForegroundColor Gray
                }
            }
        }
    }
    else {
        Write-Host "[NAO ENCONTRADO] Nenhum evento USB detectado" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host " FIM DA ANALISE" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host ""
}

# Analisar todos ou um especifico
if ($All) {
    $csvFiles = Get-ChildItem -Path $logsFolder -Filter "*.csv"
    foreach ($file in $csvFiles) {
        Analyze-ProcMonLog -FilePath $file.FullName
    }
}
elseif (-not [string]::IsNullOrEmpty($LogPath)) {
    Analyze-ProcMonLog -FilePath $LogPath
}

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " PROXIMO PASSO" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Comparar logs de diferentes cenarios:" -ForegroundColor Yellow
Write-Host "  .\06_CompareLogs.ps1" -ForegroundColor White
Write-Host ""
Write-Host "Gerar relatorio completo:" -ForegroundColor Yellow
Write-Host "  .\07_GenerateReport.ps1" -ForegroundColor White
Write-Host ""
