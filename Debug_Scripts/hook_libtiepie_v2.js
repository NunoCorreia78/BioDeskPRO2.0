// hook_libtiepie_v2.js
// Hook agressivo - enumera e hooka TUDO da libtiepie.dll

console.log("[*] === HOOK LibTiePie v2 (Enumeracao Completa) ===");
console.log("");

// 1. Enumerar TODOS os modulos carregados
console.log("[*] Modulos carregados:");
var libtiepieModule = null;

Process.enumerateModules().forEach(function(module) {
    if (module.name.toLowerCase().indexOf("tiepie") !== -1) {
        console.log("[+] ENCONTRADO: " + module.name + " @ " + module.base);
        console.log("    Path: " + module.path);
        libtiepieModule = module;
    }
});

console.log("");

if (!libtiepieModule) {
    console.log("[-] ERRO: Nenhum modulo TiePie encontrado!");
    console.log("[*] Lista completa de modulos:");
    Process.enumerateModules().forEach(function(m) {
        console.log("    - " + m.name);
    });
} else {
    console.log("[*] Enumerando exports de " + libtiepieModule.name + "...");
    console.log("");

    var exportCount = 0;
    var hookedCount = 0;

    // Enumerar TODAS as funcoes exportadas
    var exports = Module.enumerateExports(libtiepieModule.name);

    exports.forEach(function(exp) {
        exportCount++;

        // Hookar apenas funcoes que comecam com Gen, Lst, Dev, Lib, Scp
        var shouldHook = exp.name.startsWith("Gen") ||
                        exp.name.startsWith("Lst") ||
                        exp.name.startsWith("Dev") ||
                        exp.name.startsWith("Lib") ||
                        exp.name.startsWith("Scp");

        if (shouldHook && exp.type === "function") {
            try {
                Interceptor.attach(exp.address, {
                    onEnter: function(args) {
                        var timestamp = new Date().toISOString();
                        var argsStr = "";

                        // Tentar ler primeiros 4 argumentos
                        try {
                            for (var i = 0; i < 4; i++) {
                                if (args[i]) {
                                    argsStr += "arg" + i + "=" + args[i] + ", ";
                                }
                            }
                        } catch(e) {}

                        console.log("[" + timestamp + "] " + exp.name + "(" + argsStr + ")");

                        // Guardar nome da funcao para onLeave
                        this.funcName = exp.name;
                    },
                    onLeave: function(retval) {
                        // Mostrar valor de retorno se for numero
                        try {
                            if (this.funcName.indexOf("Get") !== -1 || this.funcName.indexOf("Set") !== -1) {
                                console.log("  -> Return: " + retval);
                            }
                        } catch(e) {}
                    }
                });
                hookedCount++;
                console.log("[+] Hook: " + exp.name);
            } catch(e) {
                console.log("[-] Falhou hook: " + exp.name + " - " + e.message);
            }
        }
    });

    console.log("");
    console.log("[*] Total exports: " + exportCount);
    console.log("[*] Total hooks instalados: " + hookedCount);
    console.log("");
    console.log("========================================");
    console.log("PRONTO! Aguardando chamadas API...");
    console.log("========================================");
    console.log("");
}
