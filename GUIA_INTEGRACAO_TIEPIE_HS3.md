# 🔌 Guia de Integração TiePie Handyscope HS3

**Data:** 16 de Outubro de 2025
**Hardware Detetado:** TiePie Handyscope HS3
**VID/PID:** 0x0E36 / 0x0008
**Status:** Código preparado, aguarda escolha de driver

---

## 📊 Hardware Identificado

```
Modelo: TiePie Handyscope HS3
VID: 0x0E36 (3638 decimal) - TiePie Engineering
PID: 0x0008 (8 decimal) - HS3 final (após renumeração)
PID: 0x0009 (9 decimal) - HS3 antes de renumeração (ignorar)

Comunicação: USB Bulk Transfer
Class atual: TiePie instruments (driver proprietário instalado)
```

---

## 🎯 3 Opções de Implementação

### **Opção 1: LibUSB + WinUSB (RECOMENDADO)**

✅ **Vantagens:**
- Usa driver genérico Windows (WinUSB)
- NÃO conflita com Inergetix CoRe (podem coexistir)
- Controlo total do hardware
- Reversível (pode voltar ao driver TiePie)

❌ **Desvantagens:**
- Precisa trocar driver com Zadig (5 minutos)
- Protocolo não documentado (precisa engenharia reversa)

**Passos:**

1. **Instalar NuGet LibUsbDotNet:**
   ```bash
   cd src/BioDesk.Services
   dotnet add package LibUsbDotNet --version 3.0.102
   ```

2. **Trocar Driver com Zadig:**
   - Baixar: https://zadig.akeo.ie/
   - Executar Zadig (Administrator)
   - Options → List All Devices ✅
   - Selecionar: **"Handyscope HS3"**
   - Driver: **WinUSB (v6.1.7600.16385)** ou superior
   - Clicar: **Replace Driver**
   - Aguardar: ~30 segundos
   - Reiniciar dispositivo (desligar/ligar USB)

3. **Ativar no DI (App.xaml.cs):**
   ```csharp
   // Linha ~350 (onde está DummyTiePieHardwareService)
   services.AddSingleton<ITiePieHardwareService, LibUsbTiePieHardwareService>();
   ```

4. **Build e Testar:**
   ```bash
   dotnet build
   dotnet run --project src/BioDesk.App
   ```

5. **Verificar Logs:**
   ```
   ✅ TiePie encontrado: Handyscope HS3
   ✅ Endpoints USB abertos
   🎉 TiePie inicializado via LibUSB!
   ```

**⚠️ Reverter Driver (se precisares Inergetix CoRe):**
- Gestor de Dispositivos → Handyscope HS3 → Propriedades
- Driver → Atualizar Driver → Procurar Automaticamente
- Windows reinstala driver TiePie original

---

### **Opção 2: SDK TiePie Oficial (LibTiePie)**

✅ **Vantagens:**
- Protocolo oficial e documentado
- Suporte técnico TiePie
- Exemplos em C#: https://github.com/TiePie/libtiepie-examples

❌ **Desvantagens:**
- **CONFLITA com Inergetix CoRe** (não podem correr simultaneamente!)
- Precisa instalar SDK completo (~50MB)
- Mais pesado

**Passos:**

1. **Desinstalar driver atual** (Gestor de Dispositivos)

2. **Baixar SDK TiePie:**
   - Site: https://www.tiepie.com/en/libtiepie-sdk
   - Download: LibTiePie SDK 0.9.x (Windows 64-bit)
   - Instalar: `LibTiePie_SDK_0.9.17.msi`

3. **Instalar NuGet:**
   ```bash
   cd src/BioDesk.Services
   dotnet add package TiePie.Engineering.LibTiePie --version 0.9.17
   ```

4. **Criar `OfficialTiePieHardwareService.cs`** (baseado em exemplos GitHub)

5. **Ativar no DI:**
   ```csharp
   services.AddSingleton<ITiePieHardwareService, OfficialTiePieHardwareService>();
   ```

**⚠️ IMPORTANTE:** Inergetix CoRe **VAI PARAR** de funcionar! (usa mesmo driver)

---

### **Opção 3: Coexistência (Dual Boot)**

✅ **Vantagens:**
- Usa os 2 sistemas (BioDeskPro2 + Inergetix CoRe)
- Sem conflitos

❌ **Desvantagens:**
- NÃO podem correr **ao mesmo tempo**
- Precisa fechar um antes de abrir outro
- BioDeskPro2 fica em modo dummy quando CoRe está ativo

**Passos:**

1. **Manter driver TiePie atual** (não alterar)

2. **Deteção Automática no BioDeskPro2:**
   ```csharp
   // Verificar se CoRe está a correr
   var coreProcess = Process.GetProcessesByName("Inergetix");

   if (coreProcess.Any())
   {
       _logger.LogWarning("⚠️ Inergetix CoRe ativo - modo dummy");
       return new DummyTiePieHardwareService();
   }
   else
   {
       _logger.LogInformation("✅ CoRe inativo - usar hardware real");
       return new LibUsbTiePieHardwareService(); // Com Zadig WinUSB
   }
   ```

3. **Workflow:**
   - Usar Inergetix CoRe → Fechar → Abrir BioDeskPro2 (hardware real)
   - Usar BioDeskPro2 → Fechar → Abrir Inergetix CoRe

---

## 🔍 Descobrir Protocolo USB (Engenharia Reversa)

Para **Opção 1** (LibUSB), precisas descobrir comandos:

### **Ferramenta: Wireshark + USBPcap**

1. **Instalar Wireshark:**
   - Download: https://www.wireshark.org/download.html
   - Durante instalação: ✅ USBPcap

2. **Capturar Tráfego USB:**
   ```
   - Abrir Wireshark
   - Capture → USBPcap1 (ou USBPcap2)
   - Start Capture
   - Abrir Inergetix CoRe
   - Emitir 7.83 Hz a 5V por 10 segundos
   - Stop Capture
   ```

3. **Filtrar Pacotes:**
   ```
   usb.idVendor == 0x0e36 && usb.idProduct == 0x0008
   ```

4. **Analisar URB_BULK_OUT:**
   - Clicar em pacote → USB URB → Leftover Capture Data
   - Ver bytes enviados (hex): `10 A3 4F 40 00 ...`
   - Mapear para comandos:
     ```
     Byte 0: Comando (0x10 = Set Frequency?)
     Bytes 1-4: Valor float (7.83 Hz)
     ```

5. **Atualizar LibUsbTiePieHardwareService.cs:**
   ```csharp
   private const byte CMD_SET_FREQUENCY = 0x10; // ✅ Descoberto via Wireshark
   ```

---

## 📋 Checklist de Decisão

**Escolhe a opção certa para ti:**

- [ ] **Só vou usar BioDeskPro2** (substituir CoRe completamente)
  → **Opção 1** (LibUSB + Zadig) ou **Opção 2** (SDK Oficial)

- [ ] **Quero usar os 2 programas** (mas não ao mesmo tempo)
  → **Opção 3** (Coexistência com deteção automática)

- [ ] **Preciso dos 2 A CORRER simultaneamente**
  → ❌ **Impossível** (USB não suporta acesso partilhado)
  → Comprar 2º TiePie HS3 (1 para cada programa)

---

## 🎯 Recomendação Final

**Para o teu caso (tens Inergetix CoRe e queres BioDeskPro2):**

1. **Curto Prazo (Desenvolvimento/Testes):**
   - Manter modo **Dummy** (simulação)
   - Testar todas as funcionalidades sem hardware
   - Validar UI, lógica, persistência

2. **Médio Prazo (Integração Real):**
   - **Opção 1**: LibUSB + Zadig (mais controlo)
   - Capturar protocolo com Wireshark
   - Implementar comandos reais

3. **Longo Prazo (Produção):**
   - Decidir: BioDeskPro2 **OU** Inergetix CoRe?
   - Se ambos: comprar 2º hardware TiePie

---

## 📞 Próximos Passos

**O que precisas fazer AGORA:**

1. ✅ Decidir qual opção (1, 2 ou 3)
2. ⏳ Instalar biblioteca adequada (LibUSB ou SDK)
3. ⏳ Se Opção 1: Zadig + WinUSB
4. ⏳ Build + Testar inicialização
5. ⏳ Se funcionar: Capturar protocolo com Wireshark
6. ⏳ Atualizar comandos no código
7. ⏳ Testar emissão REAL de 7.83 Hz

---

## ⚠️ Segurança - Testes com Hardware Real

**SEMPRE começar com:**

1. **Voltagem BAIXA**: 1-2V (não 5V!)
2. **Duração CURTA**: 5 segundos (não 5 minutos!)
3. **Frequência SEGURA**: 7.83 Hz (ressonância Schumann)
4. **Monitorizar Corrente**: < 10 mA
5. **Botão Emergency Stop**: Implementar antes de testar!

**NUNCA:**
- ❌ Testar em pessoas sem validação completa
- ❌ Usar voltagens > 12V (queima tecidos)
- ❌ Deixar a correr sem supervisão
- ❌ Testar em pessoas com pacemaker

---

**Ficheiros Atualizados:**
- ✅ `HidTiePieHardwareService.cs` - VID/PID corretos
- ✅ `LibUsbTiePieHardwareService.cs` - VID/PID corretos
- ✅ Este guia completo

**Decisão:** Qual opção escolhes? (1, 2 ou 3) 😊
