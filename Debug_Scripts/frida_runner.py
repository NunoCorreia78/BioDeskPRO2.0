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
