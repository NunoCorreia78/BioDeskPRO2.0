# Script 11: Configurar API Monitor para monitorar hs3.dll
# Cria definicao custom para funcoes da DLL

$ErrorActionPreference = "Stop"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Configuracao API Monitor - hs3.dll" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

# Carregar config do CoRe
$configPath = "$PSScriptRoot\InergetixCoreConfig.json"
if (-not (Test-Path $configPath)) {
    Write-Host "[ERRO] Configuracao do CoRe nao encontrada!" -ForegroundColor Red
    Write-Host "Execute: .\02_FindInergetixCore.ps1" -ForegroundColor Yellow
    exit 1
}

$config = Get-Content $configPath | ConvertFrom-Json
$hs3DllPath = $config.HS3DllPath

Write-Host "[INFO] hs3.dll localizada:" -ForegroundColor Green
Write-Host "  $hs3DllPath" -ForegroundColor White
Write-Host ""

# Verificar API Monitor (32-bit para Inergetix CoRe)
$apiMonitorPath = "C:\Users\$env:USERNAME\Documents\APIMonitor\apimonitor-x86.exe"
if (-not (Test-Path $apiMonitorPath)) {
    Write-Host "[ERRO] API Monitor nao encontrado!" -ForegroundColor Red
    Write-Host "Execute: .\10_DownloadAPIMonitor.ps1" -ForegroundColor Yellow
    exit 1
}

Write-Host "[INFO] Usando API Monitor 32-bit (x86) para CoRe" -ForegroundColor Cyan

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " INSTRUCOES DE USO - API Monitor" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "O API Monitor sera lancado AGORA." -ForegroundColor Yellow
Write-Host ""
Write-Host "CONFIGURACAO (10 minutos):" -ForegroundColor Green
Write-Host ""

Write-Host "1. Na janela API Monitor:" -ForegroundColor White
Write-Host "   - Monitor → Monitor New Process..." -ForegroundColor Gray
Write-Host "   - Browse → Selecionar:" -ForegroundColor Gray
Write-Host "     C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\InergetixCoRe.exe" -ForegroundColor Cyan
Write-Host ""

Write-Host "2. Configurar filtros de API (IMPORTANTE!):" -ForegroundColor White
Write-Host "   - API Filter (painel esquerdo - precisa SCROLL DOWN!):" -ForegroundColor Gray
Write-Host "     [ ] Desmarcar TUDO (Ctrl+A → Clicar checkbox qualquer)" -ForegroundColor Yellow
Write-Host "     [x] Marcar APENAS estas 3 categorias:" -ForegroundColor Green
Write-Host ""
Write-Host "         → 📁 File Management (SCROLL UP - topo da lista)" -ForegroundColor Cyan
Write-Host "            [x] CreateFile" -ForegroundColor Gray
Write-Host "            [x] ReadFile" -ForegroundColor Gray
Write-Host "            [x] WriteFile" -ForegroundColor Gray
Write-Host ""
Write-Host "         → 🔌 Devices (meio da lista)" -ForegroundColor Cyan
Write-Host "            [x] DeviceIoControl" -ForegroundColor Gray
Write-Host ""
Write-Host "         → 📚 Library Management (SCROLL DOWN - meio/baixo)" -ForegroundColor Cyan
Write-Host "            [x] LoadLibrary" -ForegroundColor Gray
Write-Host "            [x] LoadLibraryEx" -ForegroundColor Gray
Write-Host "            [x] GetProcAddress" -ForegroundColor Gray
Write-Host "            [x] FreeLibrary" -ForegroundColor Gray
Write-Host ""
Write-Host "   ATENCAO: A lista tem SCROLL! Precisa rolar para ver todas!" -ForegroundColor Yellow
Write-Host ""

Write-Host "3. Adicionar hook para hs3.dll:" -ForegroundColor White
Write-Host "   - Options → Edit API Definitions..." -ForegroundColor Gray
Write-Host "   - New → Module Definition" -ForegroundColor Gray
Write-Host "   - Name: hs3.dll" -ForegroundColor Cyan
Write-Host "   - Module Path: $hs3DllPath" -ForegroundColor Cyan
Write-Host "   - Add Functions (funcoes conhecidas):" -ForegroundColor Gray
Write-Host "       * InitInstrument" -ForegroundColor Yellow
Write-Host "       * SetFuncGenFrequency" -ForegroundColor Yellow
Write-Host "       * SetFuncGenAmplitude" -ForegroundColor Yellow
Write-Host "       * EmitFrequency" -ForegroundColor Yellow
Write-Host "       * CloseInstrument" -ForegroundColor Yellow
Write-Host "   - Save" -ForegroundColor Gray
Write-Host ""

Write-Host "4. TESTE 1: COM Equipamento" -ForegroundColor White
Write-Host "   a) HS3 conectado ao USB" -ForegroundColor Gray
Write-Host "   b) Monitor → Start Monitoring (F5)" -ForegroundColor Gray
Write-Host "   c) No CoRe: Navegar ate detectar HS3" -ForegroundColor Gray
Write-Host "   d) Observar chamadas de funcoes no painel direito" -ForegroundColor Gray
Write-Host "   e) Monitor → Stop Monitoring (F5)" -ForegroundColor Gray
Write-Host "   f) File → Save → ApiMonitor_COM.apm" -ForegroundColor Cyan
Write-Host ""

Write-Host "5. TESTE 2: SEM Equipamento" -ForegroundColor White
Write-Host "   a) Fechar CoRe" -ForegroundColor Gray
Write-Host "   b) Desconectar HS3" -ForegroundColor Gray
Write-Host "   c) Edit → Clear All (limpar eventos)" -ForegroundColor Gray
Write-Host "   d) Monitor → Start Monitoring (F5)" -ForegroundColor Gray
Write-Host "   e) Processo vai lancar automaticamente" -ForegroundColor Gray
Write-Host "   f) Observar erro/aviso" -ForegroundColor Gray
Write-Host "   g) Monitor → Stop Monitoring (F5)" -ForegroundColor Gray
Write-Host "   h) File → Save → ApiMonitor_SEM.apm" -ForegroundColor Cyan
Write-Host ""

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " O QUE PROCURAR" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "No painel de eventos (Summary), procurar:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. FUNCOES CHAMADAS APENAS COM EQUIPAMENTO:" -ForegroundColor Cyan
Write-Host "   - Funcoes de hs3.dll chamadas so quando conectado" -ForegroundColor White
Write-Host "   - Ex: ValidateConnection(), CheckDevice(), etc." -ForegroundColor Gray
Write-Host ""

Write-Host "2. RETURN VALUES DIFERENTES:" -ForegroundColor Cyan
Write-Host "   - InitInstrument(): Return 1 (COM) vs 0 (SEM)?" -ForegroundColor White
Write-Host "   - Alguma funcao retorna codigo erro especifico?" -ForegroundColor White
Write-Host ""

Write-Host "3. SEQUENCIA DE CHAMADAS:" -ForegroundColor Cyan
Write-Host "   - Ordem das funcoes chamadas" -ForegroundColor White
Write-Host "   - Funcoes que faltam quando SEM equipamento" -ForegroundColor White
Write-Host ""

Write-Host "4. PARAMETROS PASSADOS:" -ForegroundColor Cyan
Write-Host "   - Valores diferentes entre COM e SEM" -ForegroundColor White
Write-Host "   - Handles, ponteiros, flags" -ForegroundColor White
Write-Host ""

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Salvar capturas em:" -ForegroundColor Green
Write-Host "  C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts\" -ForegroundColor White
Write-Host ""

Write-Host "Pressione ENTER para lancar API Monitor..." -ForegroundColor Yellow
Read-Host

# Lancar API Monitor
Write-Host "[INFO] Lancando API Monitor..." -ForegroundColor Cyan
try {
    Start-Process $apiMonitorPath
    Write-Host "[OK] API Monitor lancado!" -ForegroundColor Green
    Write-Host ""
    Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host " MONITORIZACAO EM PROGRESSO" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Siga as instrucoes acima para configurar e capturar." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Apos salvar as capturas .apm, execute:" -ForegroundColor Green
    Write-Host "  .\12_AnalyzeAPIMonitorResults.ps1" -ForegroundColor White
    Write-Host ""
}
catch {
    Write-Host "[ERRO] Falha ao lancar API Monitor: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host ""
    Write-Host "Tente executar manualmente:" -ForegroundColor Yellow
    Write-Host "  $apiMonitorPath" -ForegroundColor White
}
