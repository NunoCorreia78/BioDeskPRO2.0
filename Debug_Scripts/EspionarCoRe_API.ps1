# EspionarCoRe_API.ps1
# Monitoriza chamadas LibTiePie enquanto CoRe executa
# REQUER: API Monitor (https://api-monitor.com) ou Process Monitor

Write-Host "=== ESPIONAGEM API LibTiePie (CoRe System) ===" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar se Process Monitor está instalado
$procmonPath = "C:\Program Files\SysinternalsSuite\Procmon64.exe"
if (Test-Path $procmonPath) {
    Write-Host "✅ Process Monitor encontrado" -ForegroundColor Green
    $useProcmon = $true
} else {
    Write-Host "⚠️  Process Monitor não encontrado" -ForegroundColor Yellow
    Write-Host "   Download: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon" -ForegroundColor Yellow
    $useProcmon = $false
}

# 2. Criar filtro para capturar apenas CoRe
Write-Host ""
Write-Host "📋 Configuração do filtro:" -ForegroundColor Cyan
Write-Host "   Processo: CoReSystem*.exe" -ForegroundColor White
Write-Host "   DLL: libtiepie.dll" -ForegroundColor White
Write-Host "   Operações: Load Image, Read/Write File, RegOpenKey" -ForegroundColor White

# 3. Instruções de uso
Write-Host ""
Write-Host "=== INSTRUÇÕES ===" -ForegroundColor Yellow
Write-Host ""
Write-Host "MÉTODO 1: Process Monitor (Sysinternals)" -ForegroundColor Cyan
Write-Host "  1. Baixar: https://download.sysinternals.com/files/ProcessMonitor.zip" -ForegroundColor White
Write-Host "  2. Extrair e executar como Admin: Procmon64.exe" -ForegroundColor White
Write-Host "  3. Filtrar processo (Ctrl+L):" -ForegroundColor White
Write-Host "     - Process Name -> is -> CoReSystem.exe -> Include" -ForegroundColor Gray
Write-Host "     - Path -> contains -> libtiepie -> Include" -ForegroundColor Gray
Write-Host "  4. Iniciar captura (Ctrl+E)" -ForegroundColor White
Write-Host "  5. Executar CoRe e rodar terapia" -ForegroundColor White
Write-Host "  6. Parar captura (Ctrl+E)" -ForegroundColor White
Write-Host "  7. Salvar log: File -> Save -> CSV" -ForegroundColor White
Write-Host ""

Write-Host "MÉTODO 2: API Monitor (mais detalhado)" -ForegroundColor Cyan
Write-Host "  1. Baixar: http://www.rohitab.com/apimonitor" -ForegroundColor White
Write-Host "  2. Instalar e executar API Monitor x64" -ForegroundColor White
Write-Host "  3. Monitor API -> TiePie Engineering -> libtiepie.dll" -ForegroundColor White
Write-Host "  4. File -> Monitor New Process -> CoReSystem.exe" -ForegroundColor White
Write-Host "  5. Executar terapia no CoRe" -ForegroundColor White
Write-Host "  6. API Monitor mostrará TODAS as chamadas em tempo real!" -ForegroundColor White
Write-Host ""

Write-Host "MÉTODO 3: Script de Hook (avançado - vou criar agora)" -ForegroundColor Cyan
Write-Host ""

# 4. Criar script de hook usando Detours (se disponível)
$hookScript = @"
// HookLibTiePie.cpp
// Intercepta chamadas GenSetFrequency, GenSetAmplitude, GenStart, GenStop
// Compilar com: cl /LD HookLibTiePie.cpp /Fe:HookLibTiePie.dll

#include <windows.h>
#include <stdio.h>
#include <detours.h>

// Protótipos originais LibTiePie
typedef void (*GenSetFrequency_t)(void* handle, double frequency);
typedef void (*GenSetAmplitude_t)(void* handle, double amplitude);
typedef void (*GenStart_t)(void* handle);
typedef void (*GenStop_t)(void* handle);

// Ponteiros para funções originais
GenSetFrequency_t Original_GenSetFrequency = NULL;
GenSetAmplitude_t Original_GenSetAmplitude = NULL;
GenStart_t Original_GenStart = NULL;
GenStop_t Original_GenStop = NULL;

// Log file
FILE* logFile = NULL;

// Função hook: GenSetFrequency
void Hook_GenSetFrequency(void* handle, double frequency) {
    if (logFile) {
        fprintf(logFile, "[GenSetFrequency] Handle=%p, Freq=%.2f Hz\n", handle, frequency);
        fflush(logFile);
    }
    Original_GenSetFrequency(handle, frequency);
}

// Função hook: GenSetAmplitude
void Hook_GenSetAmplitude(void* handle, double amplitude) {
    if (logFile) {
        fprintf(logFile, "[GenSetAmplitude] Handle=%p, Vpp=%.2f V\n", handle, amplitude);
        fflush(logFile);
    }
    Original_GenSetAmplitude(handle, amplitude);
}

// Função hook: GenStart
void Hook_GenStart(void* handle) {
    if (logFile) {
        fprintf(logFile, "[GenStart] Handle=%p - INICIANDO EMISSÃO\n", handle);
        fflush(logFile);
    }
    Original_GenStart(handle);
}

// Função hook: GenStop
void Hook_GenStop(void* handle) {
    if (logFile) {
        fprintf(logFile, "[GenStop] Handle=%p - PARANDO EMISSÃO\n", handle);
        fflush(logFile);
    }
    Original_GenStop(handle);
}

// DLL Entry Point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Abrir log file
        logFile = fopen("C:\\Temp\\CoRe_LibTiePie_Log.txt", "a");
        if (logFile) {
            fprintf(logFile, "\n\n=== NOVA SESSÃO ===\n");
        }

        // Attach hooks
        HMODULE libtiepie = GetModuleHandleA("libtiepie.dll");
        if (libtiepie) {
            Original_GenSetFrequency = (GenSetFrequency_t)GetProcAddress(libtiepie, "GenSetFrequency");
            Original_GenSetAmplitude = (GenSetAmplitude_t)GetProcAddress(libtiepie, "GenSetAmplitude");
            Original_GenStart = (GenStart_t)GetProcAddress(libtiepie, "GenStart");
            Original_GenStop = (GenStop_t)GetProcAddress(libtiepie, "GenStop");

            DetourTransactionBegin();
            DetourUpdateThread(GetCurrentThread());
            DetourAttach(&(PVOID&)Original_GenSetFrequency, Hook_GenSetFrequency);
            DetourAttach(&(PVOID&)Original_GenSetAmplitude, Hook_GenSetAmplitude);
            DetourAttach(&(PVOID&)Original_GenStart, Hook_GenStart);
            DetourAttach(&(PVOID&)Original_GenStop, Hook_GenStop);
            DetourTransactionCommit();
        }
    } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        if (logFile) {
            fclose(logFile);
        }
    }
    return TRUE;
}
"@

$hookScriptPath = "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts\HookLibTiePie.cpp"
Set-Content -Path $hookScriptPath -Value $hookScript -Encoding UTF8
Write-Host "✅ Script de hook criado: $hookScriptPath" -ForegroundColor Green
Write-Host "   (Requer compilação com Visual Studio + Detours)" -ForegroundColor Yellow

# 5. Criar parser de logs do Process Monitor
Write-Host ""
Write-Host "=== CRIAR PARSER DE LOGS ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Após capturar log do Process Monitor (CSV), executar:" -ForegroundColor White
Write-Host "  .\AnalisarLogCoRe.ps1 -LogPath 'C:\Temp\procmon_log.csv'" -ForegroundColor Gray
Write-Host ""

Write-Host "=== PRÓXIMOS PASSOS ===" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. Escolher método de monitorização (Process Monitor recomendado)" -ForegroundColor White
Write-Host "2. Configurar filtros para CoReSystem.exe" -ForegroundColor White
Write-Host "3. Iniciar captura" -ForegroundColor White
Write-Host "4. Executar CoRe → Terapia → Frequências ressonantes" -ForegroundColor White
Write-Host "5. Parar captura e analisar log" -ForegroundColor White
Write-Host ""
Write-Host "🎯 Objetivos da análise:" -ForegroundColor Cyan
Write-Host "   - Identificar ordem de chamadas LibTiePie" -ForegroundColor White
Write-Host "   - Capturar parâmetros reais (Hz, Vpp, Duty)" -ForegroundColor White
Write-Host "   - Descobrir arquivos .TXT de frequências" -ForegroundColor White
Write-Host "   - Entender timing entre frequências" -ForegroundColor White
Write-Host ""
