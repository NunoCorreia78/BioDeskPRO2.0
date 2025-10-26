# Test-HS3SymbolicLinks.ps1
# Script para testar nomes comuns de symbolic links do TiePie HS3
# Usa CreateFile Win32 API para validar cada path

Write-Host "=== TESTE SYMBOLIC LINKS TIEPIE HS3 ===" -ForegroundColor Cyan
Write-Host "Data: $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')`n" -ForegroundColor Gray

# Adicionar P/Invoke CreateFile
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public class Kernel32 {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    public const uint GENERIC_READ = 0x80000000;
    public const uint GENERIC_WRITE = 0x40000000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint FILE_SHARE_WRITE = 0x00000002;
    public const uint OPEN_EXISTING = 3;
}
"@

# Lista de nomes comuns para testar
$deviceNames = @(
    "\\.\HS3",
    "\\.\HS3_0",
    "\\.\HS3-0",
    "\\.\TiePie_HS3",
    "\\.\TiePieHS3",
    "\\.\TIEPIESCOPE",
    "\\.\TiePieScope",
    "\\.\HS3r",
    "\\.\HS3R",
    "\\.\TIEPIE0",
    "\\.\TIEPIE1",
    "\\.\HANDYSCOPE",
    "\\.\HandyScope",
    "\\.\HS3_USB",
    "\\.\TIEPIE_USB"
)

$foundDevices = @()

foreach ($deviceName in $deviceNames) {
    Write-Host "Testando: $deviceName ... " -NoNewline

    try {
        $handle = [Kernel32]::CreateFile(
            $deviceName,
            [Kernel32]::GENERIC_READ -bor [Kernel32]::GENERIC_WRITE,
            [Kernel32]::FILE_SHARE_READ -bor [Kernel32]::FILE_SHARE_WRITE,
            [IntPtr]::Zero,
            [Kernel32]::OPEN_EXISTING,
            0,
            [IntPtr]::Zero
        )

        if (-not $handle.IsInvalid) {
            Write-Host "✅ SUCESSO!" -ForegroundColor Green
            $foundDevices += $deviceName
            $handle.Close()
        }
        else {
            $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Host "❌ Erro $lastError" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "❌ Exception: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host "`n=== RESULTADOS ===" -ForegroundColor Cyan

if ($foundDevices.Count -gt 0) {
    Write-Host "✅ DISPOSITIVOS ENCONTRADOS ($($foundDevices.Count)):" -ForegroundColor Green
    foreach ($device in $foundDevices) {
        Write-Host "   • $device" -ForegroundColor Green
    }

    Write-Host "`n📋 PRÓXIMO PASSO:" -ForegroundColor Yellow
    Write-Host "   Atualizar HS3DeviceDiscovery.cs para usar:" -ForegroundColor Yellow
    Write-Host "   devicePath = `"$($foundDevices[0])`";" -ForegroundColor Cyan
}
else {
    Write-Host "❌ NENHUM DISPOSITIVO ENCONTRADO" -ForegroundColor Red
    Write-Host "`n📋 PRÓXIMO PASSO:" -ForegroundColor Yellow
    Write-Host "   Instalar LibUsbDotNet (solução alternativa)" -ForegroundColor Yellow
}

Write-Host "`n=== FIM TESTE ===" -ForegroundColor Cyan
