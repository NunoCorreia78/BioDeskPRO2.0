# ExecutarFridaHook_Direct.ps1
# Executa Frida hook diretamente via Python script

Write-Host "=== EXECUTANDO FRIDA HOOK (Direto) ===" -ForegroundColor Cyan
Write-Host ""

# Verificar se CoRe esta a correr
$coreProcess = Get-Process -Name "InergetixCoRe" -ErrorAction SilentlyContinue

if (-not $coreProcess) {
    Write-Host "AVISO: CoRe nao esta a correr!" -ForegroundColor Yellow
    Write-Host "Abre o Inergetix-CoRe 5.0 primeiro." -ForegroundColor White
    exit 0
}

Write-Host "CoRe detectado! PID: $($coreProcess.Id)" -ForegroundColor Green
Write-Host ""

# Criar script Python temporario
$pythonScript = @'
import frida
import sys
import time

# Ler script JavaScript
with open("hook_libtiepie.js", "r", encoding="utf-8") as f:
    js_code = f.read()

print("[*] Conectando ao processo InergetixCoRe.exe...")

try:
    session = frida.attach("InergetixCoRe.exe")
    print("[+] Conectado!")

    print("[*] Injetando script...")
    script = session.create_script(js_code)

    def on_message(message, data):
        if message['type'] == 'send':
            print(message['payload'])
        elif message['type'] == 'error':
            print(f"[ERROR] {message['stack']}")

    script.on('message', on_message)
    script.load()
    print("[+] Script carregado!")
    print("")
    print("=" * 60)
    print("AGORA: No CoRe, vai a Programadas -> Adenovirus -> Comecar")
    print("=" * 60)
    print("")

    # Manter script ativo
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("")
        print("[*] Captura interrompida pelo usuario")

except frida.ProcessNotFoundError:
    print("[-] ERRO: Processo InergetixCoRe.exe nao encontrado!")
    sys.exit(1)
except Exception as e:
    print(f"[-] ERRO: {e}")
    sys.exit(1)
'@

$pythonScript | Out-File -FilePath ".\frida_runner.py" -Encoding UTF8

Write-Host "Iniciando hook..." -ForegroundColor White
Write-Host ""

# Executar
python .\frida_runner.py

Write-Host ""
Write-Host "Captura finalizada!" -ForegroundColor Green
