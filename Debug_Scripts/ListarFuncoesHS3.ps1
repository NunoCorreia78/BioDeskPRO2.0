# Script para listar TODAS as funções exportadas da hs3.dll
# Usa técnica de reflection sem precisar de dumpbin

$dllPath = "c:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\src\BioDesk.App\hs3.dll"

Write-Host "=== ANALISANDO hs3.dll ===" -ForegroundColor Cyan
Write-Host "Path: $dllPath" -ForegroundColor Gray
Write-Host ""

# Verificar se existe
if (-not (Test-Path $dllPath)) {
    Write-Host "ERRO: DLL não encontrada!" -ForegroundColor Red
    exit 1
}

# Obter informações básicas
$dll = Get-Item $dllPath
Write-Host "Tamanho: $($dll.Length) bytes" -ForegroundColor Yellow
Write-Host "Data: $($dll.LastWriteTime)" -ForegroundColor Yellow
Write-Host ""

# Tentar usar GetProcAddress via P/Invoke
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class DllExplorer {
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FreeLibrary(IntPtr hModule);
}
"@

# Carregar DLL
$handle = [DllExplorer]::LoadLibrary($dllPath)

if ($handle -eq [IntPtr]::Zero) {
    Write-Host "ERRO: Não foi possível carregar a DLL!" -ForegroundColor Red
    exit 1
}

Write-Host "DLL carregada com sucesso! Handle: $handle" -ForegroundColor Green
Write-Host ""

# Lista de funções conhecidas para testar
$knownFunctions = @(
    "InitInstrument",
    "ExitInstrument",
    "GetSerialNumber",
    "SetFuncGenFrequency",
    "GetFuncGenFrequency",
    "SetFuncGenAmplitude",
    "GetFuncGenAmplitude",
    "SetFuncGenSignalType",
    "GetFuncGenSignalType",
    "SetFuncGenOutputOn",
    "GetFuncGenOutputOn",
    "SetFuncGenEnable",
    "GetFuncGenEnable",
    "GetFunctionGenStatus",
    # Funções SUSPEITAS que podem validar conexão:
    "IsConnected",
    "IsDeviceConnected",
    "CheckConnection",
    "GetDeviceStatus",
    "GetConnectionStatus",
    "EnumerateDevices",
    "GetDeviceCount",
    "DevicePresent",
    "HardwareConnected",
    "USBConnected",
    "ValidateConnection",
    "TestConnection"
)

Write-Host "=== TESTANDO FUNÇÕES CONHECIDAS ===" -ForegroundColor Cyan
$found = @()
$notFound = @()

foreach ($funcName in $knownFunctions) {
    $addr = [DllExplorer]::GetProcAddress($handle, $funcName)
    if ($addr -ne [IntPtr]::Zero) {
        Write-Host "[✓] $funcName" -ForegroundColor Green
        $found += $funcName
    } else {
        Write-Host "[✗] $funcName" -ForegroundColor DarkGray
        $notFound += $funcName
    }
}

Write-Host ""
Write-Host "=== RESUMO ===" -ForegroundColor Cyan
Write-Host "Encontradas: $($found.Count)" -ForegroundColor Green
Write-Host "Não encontradas: $($notFound.Count)" -ForegroundColor Red

# Descarregar DLL
[DllExplorer]::FreeLibrary($handle) | Out-Null

Write-Host ""
Write-Host "=== PRÓXIMO PASSO ===" -ForegroundColor Yellow
Write-Host "Se encontrou funções suspeitas de validação, testá-las no código C#!"
