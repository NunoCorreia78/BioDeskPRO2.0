# BioDeskPro2 - Smart Build Script
# Previne file lock errors parando processos automaticamente

param(
    [switch]$Run,
    [switch]$Test,
    [switch]$Clean
)

function Write-Step {
    param([string]$Message, [string]$Color = "Cyan")
    Write-Host "`n$Message" -ForegroundColor $Color
}

function Stop-BioDeskProcesses {
    Write-Step "Verificando processos BioDesk em execucao..." "Yellow"

    $processes = Get-Process -Name "BioDesk.App" -ErrorAction SilentlyContinue

    if ($processes) {
        Write-Host "Encontrados $($processes.Count) processo(s) BioDesk:" -ForegroundColor Red
        foreach ($proc in $processes) {
            Write-Host "  - PID $($proc.Id): $($proc.ProcessName)" -ForegroundColor Yellow
            try {
                Stop-Process -Id $proc.Id -Force
                Write-Host "    Processo $($proc.Id) terminado com sucesso" -ForegroundColor Green
            }
            catch {
                Write-Host "    Erro ao terminar processo $($proc.Id): $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        Start-Sleep -Milliseconds 1000
    }
    else {
        Write-Host "Nenhum processo BioDesk em execucao" -ForegroundColor Green
    }
}

function Test-FileInUse {
    param([string]$FilePath)

    if (-not (Test-Path $FilePath)) { return $false }

    try {
        $file = [System.IO.File]::Open($FilePath, 'Open', 'Write')
        $file.Close()
        return $false
    }
    catch {
        return $true
    }
}

# Funcao principal
Write-Step "BioDeskPro2 Smart Build" "Magenta"
Write-Host "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray

# Parar processos existentes
Stop-BioDeskProcesses

# Verificar se executavel esta bloqueado
$exePath = "src\BioDesk.App\bin\Debug\net8.0-windows\BioDesk.App.exe"
if (Test-Path $exePath) {
    if (Test-FileInUse $exePath) {
        Write-Host "Ficheiro ainda bloqueado, aguardando..." -ForegroundColor Yellow
        Start-Sleep -Seconds 2

        if (Test-FileInUse $exePath) {
            Write-Host "Ficheiro ainda bloqueado apos 2s. Pode haver processos ocultos." -ForegroundColor Red
            Write-Host "Tentando forcar desbloqueio..." -ForegroundColor Yellow

            # Tentar matar todos os processos .NET relacionados
            Get-Process | Where-Object { $_.ProcessName -like "*dotnet*" -or $_.ProcessName -like "*BioDesk*" } |
                ForEach-Object {
                    Write-Host "Stopping .NET process: $($_.ProcessName) (PID: $($_.Id))" -ForegroundColor Yellow
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                }
        }
    }
}

# Executar acao solicitada
if ($Clean) {
    Write-Step "Limpeza completa..." "Blue"
    & dotnet clean
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Step "Restaurando pacotes..." "Blue"
& dotnet restore
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Step "Compilando projeto..." "Blue"
& dotnet build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($Test) {
    Write-Step "Executando testes..." "Blue"
    & dotnet test src/BioDesk.Tests
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

if ($Run) {
    Write-Step "Executando aplicacao..." "Green"
    & dotnet run --project src/BioDesk.App
}

Write-Step "Operacao concluida com sucesso!" "Green"
