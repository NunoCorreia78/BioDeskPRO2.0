# Script 4: Configurar e lancar Process Monitor para monitorizacao do CoRe
# Cria configuracao de filtros e inicia captura

$ErrorActionPreference = "Stop"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Configuracao Process Monitor para Inergetix CoRe" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Carregar configuracao do CoRe
$configPath = "$PSScriptRoot\InergetixCoreConfig.json"
if (-not (Test-Path $configPath)) {
    Write-Host "[ERRO] Configuracao do CoRe nao encontrada!" -ForegroundColor Red
    Write-Host "Execute primeiro: .\02_FindInergetixCore.ps1" -ForegroundColor Yellow
    exit 1
}

$config = Get-Content $configPath | ConvertFrom-Json
Write-Host "[INFO] Configuracao carregada:" -ForegroundColor Green
Write-Host "  Executavel CoRe: $($config.CoreExecutable)" -ForegroundColor Gray
Write-Host "  hs3.dll: $($config.HS3DllPath)" -ForegroundColor Gray
Write-Host ""

# Verificar Process Monitor
$procmonPath = "C:\Users\$env:USERNAME\Documents\SysinternalsTools\Procmon.exe"
if (-not (Test-Path $procmonPath)) {
    Write-Host "[ERRO] Process Monitor nao encontrado!" -ForegroundColor Red
    Write-Host "Execute primeiro: .\01_DownloadProcessMonitor.ps1" -ForegroundColor Yellow
    exit 1
}

# Criar pasta para logs
$logsFolder = "$PSScriptRoot\..\Logs\ProcessMonitor"
if (-not (Test-Path $logsFolder)) {
    New-Item -ItemType Directory -Path $logsFolder -Force | Out-Null
    Write-Host "[INFO] Pasta de logs criada: $logsFolder" -ForegroundColor Yellow
}

# Obter nome do processo (sem extensao)
$coreProcessName = [System.IO.Path]::GetFileNameWithoutExtension($config.CoreExecutable)
Write-Host "[INFO] Nome do processo CoRe: $coreProcessName.exe" -ForegroundColor Cyan
Write-Host ""

# Criar arquivo de configuracao de filtros para Process Monitor (PMC)
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$pmcConfigPath = "$logsFolder\ProcMon_CoRe_Config_$timestamp.pmc"
$logOutputPath = "$logsFolder\ProcMon_CoRe_Log_$timestamp.PML"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " INSTRUCOES DE USO" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "O Process Monitor sera lancado AGORA." -ForegroundColor Yellow
Write-Host ""
Write-Host "PASSOS A SEGUIR:" -ForegroundColor Green
Write-Host ""
Write-Host "1. Na janela do Process Monitor:" -ForegroundColor White
Write-Host "   - Filter → Filter → Add filters:" -ForegroundColor Gray
Write-Host "       * Process Name | is | $coreProcessName.exe | Include" -ForegroundColor Cyan
Write-Host "       * Path | contains | hs3.dll | Include" -ForegroundColor Cyan
Write-Host "       * Operation | is | Load Image | Include" -ForegroundColor Cyan
Write-Host "   - Apply → OK" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Iniciar captura:" -ForegroundColor White
Write-Host "   - Capture → Capture Events (Ctrl+E)" -ForegroundColor Gray
Write-Host ""
Write-Host "3. ESCOLHER CENARIO DE TESTE:" -ForegroundColor Yellow
Write-Host ""
Write-Host "   TESTE 1: Hardware Conectado" -ForegroundColor Cyan
Write-Host "   -------------------------" -ForegroundColor Gray
Write-Host "   a) Conectar HS3 ao USB" -ForegroundColor White
Write-Host "   b) Lancar Inergetix CoRe" -ForegroundColor White
Write-Host "   c) Aguardar mensagem 'HS3 Conectado'" -ForegroundColor White
Write-Host "   d) Parar captura (Ctrl+E)" -ForegroundColor White
Write-Host "   e) File → Save → Salvar como: ProcMon_CoRe_Conectado.PML" -ForegroundColor White
Write-Host ""
Write-Host "   TESTE 2: Hardware Desconectado" -ForegroundColor Cyan
Write-Host "   -----------------------------" -ForegroundColor Gray
Write-Host "   a) Fechar CoRe" -ForegroundColor White
Write-Host "   b) Desconectar HS3 do USB" -ForegroundColor White
Write-Host "   c) Edit → Clear Display (Ctrl+X)" -ForegroundColor White
Write-Host "   d) Iniciar nova captura (Ctrl+E)" -ForegroundColor White
Write-Host "   e) Lancar Inergetix CoRe" -ForegroundColor White
Write-Host "   f) Observar erro/aviso" -ForegroundColor White
Write-Host "   g) Parar captura (Ctrl+E)" -ForegroundColor White
Write-Host "   h) File → Save → Salvar como: ProcMon_CoRe_Desconectado.PML" -ForegroundColor White
Write-Host ""
Write-Host "   TESTE 3: Emissao de Frequencia" -ForegroundColor Cyan
Write-Host "   -----------------------------" -ForegroundColor Gray
Write-Host "   a) HS3 conectado, CoRe aberto" -ForegroundColor White
Write-Host "   b) Edit → Clear Display (Ctrl+X)" -ForegroundColor White
Write-Host "   c) Iniciar captura (Ctrl+E)" -ForegroundColor White
Write-Host "   d) No CoRe: Configurar emissao (ex: 1Hz, 10V)" -ForegroundColor White
Write-Host "   e) Iniciar emissao" -ForegroundColor White
Write-Host "   f) Aguardar 5 segundos" -ForegroundColor White
Write-Host "   g) Parar emissao" -ForegroundColor White
Write-Host "   h) Parar captura (Ctrl+E)" -ForegroundColor White
Write-Host "   i) File → Save → Salvar como: ProcMon_CoRe_Emissao.PML" -ForegroundColor White
Write-Host ""
Write-Host "4. EXPORTAR CSV para analise:" -ForegroundColor Yellow
Write-Host "   - File → Save → Format: CSV → Salvar" -ForegroundColor Gray
Write-Host ""
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Salvar logs em:" -ForegroundColor Green
Write-Host "  $logsFolder" -ForegroundColor White
Write-Host ""
Write-Host "Pressione ENTER para lancar Process Monitor..." -ForegroundColor Yellow
Read-Host

# Lancar Process Monitor como Administrador
Write-Host "[INFO] Lancando Process Monitor..." -ForegroundColor Cyan
try {
    Start-Process $procmonPath -Verb RunAs
    Write-Host "[OK] Process Monitor lancado!" -ForegroundColor Green
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " MONITORIZACAO EM PROGRESSO" -ForegroundColor Cyan
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Siga as instrucoes acima para capturar logs." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Apos salvar os logs CSV, execute:" -ForegroundColor Green
    Write-Host "  .\05_AnalyzeProcMonLogs.ps1" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "[ERRO] Falha ao lancar Process Monitor: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Tente executar manualmente:" -ForegroundColor Yellow
    Write-Host "  $procmonPath" -ForegroundColor White
}
