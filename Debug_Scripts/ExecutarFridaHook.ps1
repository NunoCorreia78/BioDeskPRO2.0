# ExecutarFridaHook.ps1
# Wrapper para executar Frida hook no CoRe

$pythonScriptsPath = "$env:LOCALAPPDATA\Packages\PythonSoftwareFoundation.Python.3.12_qbz5n2kfra8p0\LocalCache\local-packages\Python312\Scripts"

Write-Host "=== EXECUTANDO FRIDA HOOK ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "INSTRUCOES:" -ForegroundColor Yellow
Write-Host "1. ANTES de executar este script, abre o CoRe System" -ForegroundColor White
Write-Host "2. Quando vires mensagem 'Hooks ativos!', vai ao CoRe" -ForegroundColor White
Write-Host "3. Executa: Programadas -> Adenovirus -> Comecar" -ForegroundColor White
Write-Host "4. Observa output em tempo real aqui" -ForegroundColor White
Write-Host "5. CTRL+C para parar captura" -ForegroundColor White
Write-Host ""

# Verificar se CoRe esta a correr
$coreProcess = Get-Process -Name "InergetixCoRe" -ErrorAction SilentlyContinue

if (-not $coreProcess) {
    Write-Host "AVISO: CoRe nao esta a correr!" -ForegroundColor Yellow
    Write-Host "Abre o Inergetix-CoRe 5.0 primeiro e depois executa este script novamente." -ForegroundColor White
    Write-Host ""
    Read-Host "Pressiona ENTER para sair"
    exit 0
}

Write-Host "CoRe detectado! PID: $($coreProcess.Id)" -ForegroundColor Green
Write-Host ""
Write-Host "Iniciando hook..." -ForegroundColor White
Write-Host ""

# Executar frida
& python -c "import sys; from frida_tools.cli import main; sys.exit(main())" -n InergetixCoRe.exe -l .\hook_libtiepie.js

Write-Host ""
Write-Host "Captura finalizada!" -ForegroundColor Green
