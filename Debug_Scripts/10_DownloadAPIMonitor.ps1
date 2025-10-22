# Script 10: Download e instalacao do API Monitor
# Ferramenta avancada para capturar chamadas de funcoes DLL

$ErrorActionPreference = "Stop"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Download API Monitor v2" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[INFO] API Monitor e uma ferramenta avancada que captura:" -ForegroundColor Yellow
Write-Host "  - Chamadas de funcoes DLL" -ForegroundColor White
Write-Host "  - Parametros passados" -ForegroundColor White
Write-Host "  - Return values" -ForegroundColor White
Write-Host "  - Sequencia de execucao" -ForegroundColor White
Write-Host ""

# Pasta de destino
$toolsFolder = "C:\Users\$env:USERNAME\Documents\APIMonitor"
$zipFile = "$toolsFolder\apimonitor-x86-x64.zip"
$exePath = "$toolsFolder\apimonitor-x64.exe"

# Criar pasta
if (-not (Test-Path $toolsFolder)) {
    Write-Host "[INFO] Criando pasta: $toolsFolder" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $toolsFolder -Force | Out-Null
}

# Verificar se ja existe
if (Test-Path $exePath) {
    Write-Host "[OK] API Monitor ja instalado!" -ForegroundColor Green
    Write-Host "     Localizacao: $exePath" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Deseja re-baixar? (S/N): " -NoNewline -ForegroundColor Yellow
    $resposta = Read-Host
    if ($resposta -ne "S" -and $resposta -ne "s") {
        Write-Host "[INFO] Usando instalacao existente." -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Para executar API Monitor:" -ForegroundColor Green
        Write-Host "  cd `"$toolsFolder`"" -ForegroundColor White
        Write-Host "  .\apimonitor-x64.exe" -ForegroundColor White
        Write-Host ""
        Write-Host "Proximo passo:" -ForegroundColor Cyan
        Write-Host "  .\11_ConfigureAPIMonitor.ps1" -ForegroundColor White
        exit 0
    }
}

# Download
Write-Host "[INFO] Baixando API Monitor..." -ForegroundColor Yellow
Write-Host "       URL: http://www.rohitab.com/downloads" -ForegroundColor Gray
Write-Host ""

# URL direta (pode mudar - verificar site se falhar)
$downloadUrl = "http://www.rohitab.com/download/api-monitor-v2r13-x86-x64.zip"

try {
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile -UseBasicParsing -TimeoutSec 60
    $ProgressPreference = 'Continue'
    Write-Host "[OK] Download completo!" -ForegroundColor Green
}
catch {
    Write-Host "[ERRO] Falha no download: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Download manual:" -ForegroundColor Yellow
    Write-Host "  1. Abrir: http://www.rohitab.com/apimonitor" -ForegroundColor White
    Write-Host "  2. Baixar: API Monitor v2 (32-bit + 64-bit)" -ForegroundColor White
    Write-Host "  3. Extrair para: $toolsFolder" -ForegroundColor White
    Write-Host ""
    Write-Host "Deseja abrir o site agora? (S/N): " -NoNewline -ForegroundColor Yellow
    $abrir = Read-Host
    if ($abrir -eq "S" -or $abrir -eq "s") {
        Start-Process "http://www.rohitab.com/apimonitor"
    }
    exit 1
}

# Extrair ZIP
Write-Host "[INFO] Extraindo arquivos..." -ForegroundColor Yellow
try {
    Expand-Archive -Path $zipFile -DestinationPath $toolsFolder -Force
    Write-Host "[OK] Extracao completa!" -ForegroundColor Green
}
catch {
    Write-Host "[ERRO] Falha na extracao: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# Limpar ZIP
Remove-Item $zipFile -Force -ErrorAction SilentlyContinue

# Verificar instalacao
$exeFiles = Get-ChildItem -Path $toolsFolder -Filter "apimonitor*.exe" -Recurse
if ($exeFiles) {
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host " INSTALACAO COMPLETA!" -ForegroundColor Green
    Write-Host "=====================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "API Monitor instalado em:" -ForegroundColor Cyan
    foreach ($exe in $exeFiles) {
        Write-Host "  - $($exe.Name)" -ForegroundColor White
        Write-Host "    $($exe.FullName)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " PROXIMO PASSO" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Execute o script de configuracao:" -ForegroundColor Yellow
    Write-Host "  .\11_ConfigureAPIMonitor.ps1" -ForegroundColor White
    Write-Host ""
}
else {
    Write-Host "[ERRO] Executavel nao encontrado apos extracao!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Verifique manualmente:" -ForegroundColor Yellow
    Write-Host "  $toolsFolder" -ForegroundColor White
    exit 1
}
