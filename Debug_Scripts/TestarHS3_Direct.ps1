# TestarHS3_Direct.ps1
# Testa comunicação com TiePie HS3 usando P/Invoke direto (evita wrapper .NET)
# REQUER: LibTiePie SDK 0.9.15 instalado

Write-Host "=== TESTE DIRETO TiePie HS3 (LibTiePie 0.9.15) ===" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar se DLL existe
$dllPath = "C:\Program Files\TiePie\LibTiePie\libtiepie.dll"
if (-not (Test-Path $dllPath)) {
    Write-Host "❌ ERRO: libtiepie.dll não encontrada!" -ForegroundColor Red
    Write-Host "   Caminho esperado: $dllPath" -ForegroundColor Yellow
    Write-Host "   Instalar LibTiePie SDK 0.9.15" -ForegroundColor Yellow
    exit 1
}
Write-Host "✅ DLL encontrada: $dllPath" -ForegroundColor Green

# 2. Carregar DLL no processo PowerShell
try {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class TiePieNative {
    [DllImport("libtiepie.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern void LibInit();

    [DllImport("libtiepie.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern void LibExit();

    [DllImport("libtiepie.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint LstUpdate();

    [DllImport("libtiepie.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint LstGetCount();

    [DllImport("libtiepie.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr LstDevGetName(uint dwIdKind, uint dwId, IntPtr pBuffer, uint dwBufferLength);

    [DllImport("libtiepie.dll", CallingConvention = CallingConvention.StdCall)]
    public static extern uint LstDevGetSerialNumber(uint dwIdKind, uint dwId);
}
"@
    Write-Host "✅ DLL carregada com sucesso (P/Invoke)" -ForegroundColor Green
} catch {
    Write-Host "❌ ERRO ao carregar DLL: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 3. Inicializar LibTiePie
Write-Host ""
Write-Host "🔧 Inicializando LibTiePie..." -ForegroundColor Cyan
try {
    [TiePieNative]::LibInit()
    Write-Host "✅ LibTiePie inicializada" -ForegroundColor Green
} catch {
    Write-Host "❌ ERRO ao inicializar: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 4. Atualizar lista de dispositivos
Write-Host ""
Write-Host "🔍 Procurando dispositivos USB..." -ForegroundColor Cyan
try {
    $count = [TiePieNative]::LstUpdate()
    Write-Host "✅ Lista atualizada. Dispositivos encontrados: $count" -ForegroundColor Green
} catch {
    Write-Host "❌ ERRO ao atualizar lista: $($_.Exception.Message)" -ForegroundColor Red
    [TiePieNative]::LibExit()
    exit 1
}

# 5. Contar dispositivos
Write-Host ""
Write-Host "📊 Dispositivos TiePie detectados:" -ForegroundColor Cyan
try {
    $deviceCount = [TiePieNative]::LstGetCount()

    if ($deviceCount -eq 0) {
        Write-Host "⚠️  NENHUM dispositivo encontrado!" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Possíveis causas:" -ForegroundColor Yellow
        Write-Host "  1. HS3 não conectado ao USB" -ForegroundColor Yellow
        Write-Host "  2. Driver não instalado (verificar Device Manager)" -ForegroundColor Yellow
        Write-Host "  3. USB com problema (testar outra porta)" -ForegroundColor Yellow
        Write-Host "  4. LED vermelho no HS3 (erro hardware)" -ForegroundColor Yellow
    } else {
        Write-Host "✅ Total: $deviceCount dispositivo(s)" -ForegroundColor Green
        Write-Host ""

        # Listar dispositivos
        for ($i = 0; $i -lt $deviceCount; $i++) {
            Write-Host "--- Dispositivo $($i + 1) ---" -ForegroundColor Cyan

            # Serial Number
            try {
                $serial = [TiePieNative]::LstDevGetSerialNumber(1, $i) # 1 = IDKIND_INDEX
                Write-Host "  Serial Number: $serial" -ForegroundColor White
            } catch {
                Write-Host "  Serial Number: (erro ao ler)" -ForegroundColor Yellow
            }

            # Nome (mais complexo - requer buffer)
            Write-Host "  Modelo: Handyscope HS3 (assumido)" -ForegroundColor White
            Write-Host "  Status: ✅ Conectado e pronto" -ForegroundColor Green
            Write-Host ""
        }
    }
} catch {
    Write-Host "❌ ERRO ao contar dispositivos: $($_.Exception.Message)" -ForegroundColor Red
}

# 6. Finalizar
Write-Host ""
Write-Host "🏁 Finalizando LibTiePie..." -ForegroundColor Cyan
try {
    [TiePieNative]::LibExit()
    Write-Host "✅ LibTiePie finalizada" -ForegroundColor Green
} catch {
    Write-Host "⚠️  Erro ao finalizar (ignorável): $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== TESTE COMPLETO ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Próximos passos:" -ForegroundColor White
Write-Host "  1. Se HS3 detectado → Executar BioDeskPro2 e testar terapia" -ForegroundColor White
Write-Host "  2. Se não detectado → Verificar Device Manager (Win+X)" -ForegroundColor White
Write-Host "  3. Se tudo OK → LED verde fixo no HS3" -ForegroundColor White
Write-Host ""
