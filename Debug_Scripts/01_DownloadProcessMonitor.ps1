# Script 1: Download e Instalacao do Process Monitor
# Automatiza download da ferramenta Sysinternals

$ErrorActionPreference = "Stop"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Download Process Monitor (Sysinternals)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Definir pasta de destino
$toolsFolder = "C:\Users\$env:USERNAME\Documents\SysinternalsTools"
$procmonZip = "$toolsFolder\ProcessMonitor.zip"
$procmonExe = "$toolsFolder\Procmon.exe"

# Criar pasta se nao existir
if (-not (Test-Path $toolsFolder)) {
    Write-Host "[INFO] Criando pasta de ferramentas: $toolsFolder" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $toolsFolder -Force | Out-Null
}

# Verificar se ja existe
if (Test-Path $procmonExe) {
    Write-Host "[OK] Process Monitor ja instalado!" -ForegroundColor Green
    Write-Host "     Localizacao: $procmonExe" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Deseja re-baixar? (S/N): " -NoNewline -ForegroundColor Yellow
    $resposta = Read-Host
    if ($resposta -ne "S" -and $resposta -ne "s") {
        Write-Host "[INFO] Usando instalacao existente." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Para executar Process Monitor:" -ForegroundColor Green
        Write-Host "  cd `"$toolsFolder`"" -ForegroundColor White
        Write-Host "  .\Procmon.exe" -ForegroundColor White
        exit 0
    }
}

# Download
Write-Host "[INFO] Baixando Process Monitor..." -ForegroundColor Yellow
$downloadUrl = "https://download.sysinternals.com/files/ProcessMonitor.zip"

try {
    # PowerShell 3.0+ - Invoke-WebRequest com barra de progresso
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $downloadUrl -OutFile $procmonZip -UseBasicParsing
    $ProgressPreference = 'Continue'
    Write-Host "[OK] Download completo!" -ForegroundColor Green
}
catch {
    Write-Host "[ERRO] Falha no download: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Por favor, baixe manualmente de:" -ForegroundColor Yellow
    Write-Host "  $downloadUrl" -ForegroundColor White
    exit 1
}

# Extrair ZIP
Write-Host "[INFO] Extraindo arquivos..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $procmonZip -DestinationPath $toolsFolder -Force
    Write-Host "[OK] Extracao completa!" -ForegroundColor Green
}
catch {
    Write-Host "[ERRO] Falha na extracao: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Limpar ZIP
Remove-Item $procmonZip -Force -ErrorAction SilentlyContinue

# Verificar instalacao
if (Test-Path $procmonExe) {
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host " INSTALACAO COMPLETA!" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Process Monitor instalado em:" -ForegroundColor Cyan
    Write-Host "  $procmonExe" -ForegroundColor White
    Write-Host ""
    Write-Host "Outros arquivos:" -ForegroundColor Cyan
    Get-ChildItem $toolsFolder | ForEach-Object {
        Write-Host "  - $($_.Name)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " PROXIMO PASSO" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Execute o script de localizacao do Inergetix CoRe:" -ForegroundColor Yellow
    Write-Host "  .\02_FindInergetixCore.ps1" -ForegroundColor White
    Write-Host ""
}
else {
    Write-Host "[ERRO] Arquivo Procmon.exe nao encontrado apos extracao!" -ForegroundColor Red
    exit 1
}
