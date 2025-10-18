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
