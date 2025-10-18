# InstalarFrida_HookCoRe.ps1
# Instala Frida e cria script de hook para libtiepie.dll

Write-Host "=== INSTALACAO FRIDA + HOOK LibTiePie ===" -ForegroundColor Cyan
Write-Host ""

# 1. Verificar se Python esta instalado
Write-Host "Verificando Python..." -ForegroundColor White
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python encontrado: $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "Python NAO encontrado! Instalando..." -ForegroundColor Yellow
    winget install Python.Python.3.12 -e --silent
    Write-Host "Python instalado! Reinicie PowerShell e execute novamente." -ForegroundColor Green
    exit 0
}

Write-Host ""

# 2. Instalar Frida
Write-Host "Instalando Frida..." -ForegroundColor White
pip install frida-tools --quiet --disable-pip-version-check

if ($LASTEXITCODE -eq 0) {
    Write-Host "Frida instalado com sucesso!" -ForegroundColor Green
} else {
    Write-Host "ERRO ao instalar Frida!" -ForegroundColor Red
    exit 1
}

Write-Host ""

# 3. Criar script de hook JavaScript
Write-Host "Criando script de hook para libtiepie.dll..." -ForegroundColor White

$fridaScript = @'
// hook_libtiepie.js
// Hook para capturar chamadas LibTiePie com parametros reais

console.log("[*] Carregando hook libtiepie.dll...");

// Encontrar modulo libtiepie.dll
var libtiepie = null;
Process.enumerateModules().forEach(function(module) {
    if (module.name.toLowerCase().indexOf("libtiepie") !== -1) {
        libtiepie = module;
        console.log("[+] libtiepie.dll encontrado: " + module.path);
    }
});

if (!libtiepie) {
    console.log("[-] libtiepie.dll NAO encontrado!");
} else {
    console.log("[*] Base address: " + libtiepie.base);

    // Lista de funcoes a interceptar
    var functionsToHook = [
        "LibInit",
        "LibExit",
        "LstUpdate",
        "LstGetCount",
        "LstOpenDevice",
        "GenSetFrequency",
        "GenGetFrequency",
        "GenSetAmplitude",
        "GenGetAmplitude",
        "GenSetSignalType",
        "GenGetSignalType",
        "GenSetFrequencyMode",
        "GenStart",
        "GenStop",
        "GenSetOutputOn",
        "GenGetOutputOn",
        "DevOpen",
        "DevClose"
    ];

    // Tentar hookar cada funcao
    functionsToHook.forEach(function(funcName) {
        try {
            var funcAddr = Module.findExportByName(libtiepie.name, funcName);
            if (funcAddr) {
                Interceptor.attach(funcAddr, {
                    onEnter: function(args) {
                        var timestamp = new Date().toISOString();

                        if (funcName === "GenSetFrequency") {
                            var handle = args[0];
                            var freq = args[1].readDouble();
                            console.log("[" + timestamp + "] GenSetFrequency(handle=" + handle + ", freq=" + freq.toFixed(2) + " Hz)");
                        }
                        else if (funcName === "GenSetAmplitude") {
                            var handle = args[0];
                            var amp = args[1].readDouble();
                            console.log("[" + timestamp + "] GenSetAmplitude(handle=" + handle + ", amplitude=" + amp.toFixed(2) + " V)");
                        }
                        else if (funcName === "GenSetSignalType") {
                            var handle = args[0];
                            var sigType = args[1].toInt32();
                            var sigName = ["Sine", "Triangle", "Square", "DC", "Noise", "Arbitrary", "Pulse"][sigType] || "Unknown";
                            console.log("[" + timestamp + "] GenSetSignalType(handle=" + handle + ", type=" + sigName + ")");
                        }
                        else if (funcName === "GenStart") {
                            var handle = args[0];
                            console.log("[" + timestamp + "] GenStart(handle=" + handle + ") >>> EMISSAO INICIADA <<<");
                        }
                        else if (funcName === "GenStop") {
                            var handle = args[0];
                            console.log("[" + timestamp + "] GenStop(handle=" + handle + ") >>> EMISSAO PARADA <<<");
                        }
                        else if (funcName === "GenSetOutputOn") {
                            var handle = args[0];
                            var enabled = args[1].toInt32();
                            console.log("[" + timestamp + "] GenSetOutputOn(handle=" + handle + ", enabled=" + (enabled ? "TRUE" : "FALSE") + ")");
                        }
                        else if (funcName === "LstOpenDevice") {
                            var deviceType = args[0].toInt32();
                            var serialNumber = args[1].toInt32();
                            console.log("[" + timestamp + "] LstOpenDevice(type=" + deviceType + ", serial=" + serialNumber + ")");
                        }
                        else {
                            console.log("[" + timestamp + "] " + funcName + "()");
                        }
                    },
                    onLeave: function(retval) {
                        if (funcName === "GenSetFrequency" || funcName === "GenSetAmplitude" || funcName === "GenGetFrequency" || funcName === "GenGetAmplitude") {
                            var returnValue = retval.readDouble();
                            console.log("  -> Return: " + returnValue.toFixed(2));
                        }
                    }
                });
                console.log("[+] Hook instalado: " + funcName);
            }
        } catch (e) {
            // Funcao nao existe, ignora
        }
    });

    console.log("[*] Hooks ativos! Aguardando chamadas...");
    console.log("");
}
'@

$fridaScript | Out-File -FilePath ".\hook_libtiepie.js" -Encoding UTF8
Write-Host "Script criado: hook_libtiepie.js" -ForegroundColor Green

Write-Host ""
Write-Host "=== INSTALACAO COMPLETA ===" -ForegroundColor Green
Write-Host ""
Write-Host "COMO USAR:" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Abrir CoRe System normalmente" -ForegroundColor White
Write-Host ""
Write-Host "2. Executar hook (noutra janela PowerShell):" -ForegroundColor White
Write-Host "   frida -n InergetixCoRe.exe -l .\hook_libtiepie.js" -ForegroundColor Yellow
Write-Host ""
Write-Host "3. No CoRe: Programadas -> Adenovirus -> Comecar" -ForegroundColor White
Write-Host ""
Write-Host "4. Ver output em tempo real com:" -ForegroundColor White
Write-Host "   - Frequencias exatas (Hz)" -ForegroundColor Gray
Write-Host "   - Amplitudes (V)" -ForegroundColor Gray
Write-Host "   - Tipo de onda (Sine/Square/etc)" -ForegroundColor Gray
Write-Host "   - Timestamps precisos" -ForegroundColor Gray
Write-Host ""
Write-Host "5. Salvar output:" -ForegroundColor White
Write-Host "   frida -n InergetixCoRe.exe -l .\hook_libtiepie.js > C:\Temp\frida_core_capture.txt" -ForegroundColor Yellow
Write-Host ""
