# ExecutarFridaHook_V2.ps1
# Hook v2 com enumeracao completa

Write-Host "=== FRIDA HOOK V2 (Enumeracao Completa) ===" -ForegroundColor Cyan
Write-Host ""

# Verificar CoRe
$coreProcess = Get-Process -Name "InergetixCoRe" -ErrorAction SilentlyContinue

if (-not $coreProcess) {
    Write-Host "CoRe nao esta a correr! Abre primeiro." -ForegroundColor Yellow
    exit 0
}

Write-Host "CoRe detectado! PID: $($coreProcess.Id)" -ForegroundColor Green
Write-Host ""

# Script Python NOVO com hook v2
$pythonScript = @'
import frida
import sys
import time

# Ler script v2
with open("hook_libtiepie_v2.js", "r", encoding="utf-8") as f:
    js_code = f.read()

print("[*] Conectando ao CoRe...")

try:
    session = frida.attach("InergetixCoRe.exe")
    print("[+] Conectado!")

    script = session.create_script(js_code)

    def on_message(message, data):
        if message['type'] == 'send':
            print(message['payload'])
        elif message['type'] == 'error':
            print(f"[ERROR] {message['stack']}")

    script.on('message', on_message)
    script.load()

    print("")
    print("=" * 70)
    print("AGORA: Executa terapia no CoRe (Programadas -> Adenovirus -> Comecar)")
    print("=" * 70)
    print("")

    while True:
        time.sleep(0.1)

except KeyboardInterrupt:
    print("\n[*] Captura parada")
except Exception as e:
    print(f"[-] ERRO: {e}")
    sys.exit(1)
'@

$pythonScript | Out-File -FilePath ".\frida_runner_v2.py" -Encoding UTF8

Write-Host "Executando hook v2..." -ForegroundColor White
Write-Host ""

python .\frida_runner_v2.py

Write-Host ""
Write-Host "Finalizado!" -ForegroundColor Green
