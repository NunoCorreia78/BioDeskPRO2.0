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
