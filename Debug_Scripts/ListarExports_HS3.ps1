# ====================================================================
# Script: Listar Exports da hs3.dll (Inergetix Wrapper)
# ====================================================================
# Objetivo: Descobrir as funções exportadas pela hs3.dll para
#           corrigir as assinaturas P/Invoke em HS3Native.cs
# ====================================================================

param(
    [string]$DllPath = ".\src\BioDesk.App\hs3.dll"
)

Write-Host "🔍 Analisando exports da hs3.dll..." -ForegroundColor Cyan
Write-Host "DLL: $DllPath" -ForegroundColor Gray
Write-Host ""

if (-not (Test-Path $DllPath)) {
    Write-Host "❌ ERRO: hs3.dll não encontrada em $DllPath" -ForegroundColor Red
    Write-Host "Execute este script da raiz do projeto BioDeskPro2" -ForegroundColor Yellow
    exit 1
}

# Usar dumpbin do Visual Studio (se disponível)
$dumpbin = "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*\bin\Hostx64\x86\dumpbin.exe"
$dumpbinPath = Get-ChildItem $dumpbin -ErrorAction SilentlyContinue | Select-Object -First 1

if ($dumpbinPath) {
    Write-Host "✅ Usando dumpbin.exe: $($dumpbinPath.FullName)" -ForegroundColor Green
    Write-Host ""

    & $dumpbinPath /EXPORTS $DllPath

} else {
    Write-Host "⚠️ dumpbin.exe não encontrado (Visual Studio C++ tools)" -ForegroundColor Yellow
    Write-Host "Alternativa: Use 'python -m pefile <dll>' ou Dependencies.exe" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Instalação rápida pefile:" -ForegroundColor Cyan
    Write-Host "  pip install pefile" -ForegroundColor Gray
    Write-Host "  python -c 'import pefile; pe=pefile.PE(r\"$DllPath\"); print(\"\\n\".join([f\"{e.ordinal:3d} {e.name.decode()}\" for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name]))'" -ForegroundColor Gray
}

Write-Host ""
Write-Host "📋 EXPORTS ESPERADOS (Inergetix API):" -ForegroundColor Cyan
Write-Host "  InitInstrument          - Inicializa hardware" -ForegroundColor Gray
Write-Host "  ExitInstrument          - Finaliza hardware" -ForegroundColor Gray
Write-Host "  GetSerialNumber         - Número de série" -ForegroundColor Gray
Write-Host "  SetFuncGenFrequency     - Configura frequência" -ForegroundColor Gray
Write-Host "  SetFuncGenAmplitude     - Configura amplitude" -ForegroundColor Gray
Write-Host "  SetFuncGenSignalType    - Tipo de onda" -ForegroundColor Gray
Write-Host "  StartFuncGen            - Inicia emissão" -ForegroundColor Gray
Write-Host "  StopFuncGen             - Para emissão" -ForegroundColor Gray
Write-Host "  SetFuncGenOutput        - Ativa/desativa saída" -ForegroundColor Gray
Write-Host ""
Write-Host "🔗 Referência SDK TiePie (NÃO aplicável a esta DLL):" -ForegroundColor Yellow
Write-Host "  LibInit, LibExit, LstUpdate, LstOpenDevice, etc." -ForegroundColor DarkGray
