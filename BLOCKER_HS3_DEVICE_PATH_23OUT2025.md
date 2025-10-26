# 🔴 BLOCKER CRÍTICO: TiePie HS3 Device Path Resolution

**Data**: 23/10/2025
**Status**: ❌ BLOQUEADO - CreateFile falha com Error 2 (FILE_NOT_FOUND)
**Impacto**: Impossível testar protocolo USB com hardware real

---

## 🎯 Problema

O dispositivo TiePie Handyscope HS3 está **fisicamente conectado e reconhecido pelo Windows**, mas **CreateFile() falha** ao tentar abrir o device handle para comunicação USB.

### Erro Atual
```
Win32 Error: O sistema não conseguiu localizar o ficheiro especificado. (2)
Device path tentado: \\?\usb#vid_0e36&pid_0008#8&14447dc6&0&1#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}
```

---

## 🔍 Investigação Realizada

### 1. Hardware Confirmado Conectado
```powershell
Get-PnpDevice | Where-Object {$_.InstanceId -like "*VID_0E36*"}
# Resultado: 1 dispositivo com Status=OK
InstanceId: USB\VID_0E36&PID_0008\6&24C7B282&0&1
FriendlyName: Handyscope HS3
Class: TiePie instruments
ClassGuid: {AF43275C-FB24-4371-BAF8-2BA656FB33E6}
Driver: HS3r (kernel-mode driver)
```

### 2. Tentativas de GUID Corrigido
- **GUID Original (INCORRETO)**: `{f58af81e-4cdc-4d3f-b11e-0a89e4683972}`
- **GUID Device Class (TESTADO)**: `{AF43275C-FB24-4371-BAF8-2BA656FB33E6}`
- **Resultado**: Ambos falham com ERROR_FILE_NOT_FOUND (código 2)

### 3. Driver Kernel-Mode Identificado
O HS3 usa `HS3r.sys` (TiePie Engineering driver proprietário), **NÃO** WinUSB.

```
DEVPKEY_Device_Service: HS3r
DEVPKEY_Device_DriverProvider: TiePie engineering
DEVPKEY_Device_DriverVersion: 6.0.6.0
DEVPKEY_Device_DriverDate: 26/02/2010
```

### 4. Tentativas de Device Path Alternativas (PLANEJADAS)
Paths a testar (nenhum testado ainda porque falta tool):
- `\\.\HS3`
- `\\.\HS30`
- `\\.\HS3_0`
- `\\.\TIEPIESCOPE`
- `\\.\HS3r`
- `\\.\Global\HS3`

---

## 🧠 Análise Técnica

### Por Que SetupDiGetClassDevs Falha?
O driver `HS3r` é **kernel-mode custom**, não expõe device interfaces via:
- SetupDiGetClassDevs com `DIGCF_DEVICEINTERFACE`
- GUIDs de interface padrão (USB, HID, WinUSB)

### Por Que CreateFile Falha?
Kernel drivers customizados expõem **symbolic links** específicos (e.g., `\\.\DeviceName`), não device paths USB genéricos. Sem saber o nome do symbolic link exposto pelo `HS3r.sys`, CreateFile sempre retorna ERROR_FILE_NOT_FOUND.

---

## ✅ Soluções Possíveis

### Opção 1: Usar SDK Oficial TiePie (RECOMENDADO)
**Prós**:
- Suportado oficialmente
- Funciona com driver existente
- Não quebra software TiePie original

**Contras**:
- Requer contacto com TiePie Engineering
- Pode ter licença restritiva
- DLL pode ser .NET Framework (não .NET Core)

**Ação**:
1. Email enviado: 22/10/2025 (`EMAIL_TIEPIE_SDK_REQUEST_22OUT2025.md`)
2. Aguardar resposta (SLA desconhecido)

### Opção 2: Engenharia Reversa do Driver HS3r.sys
**Prós**:
- Descobriríamos symbolic link correto
- Entenderíamos protocolo completo

**Contras**:
- Legalmente duvidoso (EULA pode proibir)
- Complexo (requer IDA Pro, WinDbg, etc.)
- Tempo estimado: 20-40 horas

**Ação**: ❌ NÃO RECOMENDADO (razões legais)

### Opção 3: Substituir Driver por WinUSB
**Prós**:
- CreateFile funcionaria imediatamente
- Controle total do protocolo USB

**Contras**:
- **QUEBRA** software TiePie original
- Requer reinstalação manual (Zadig tool)
- Pode tornar device inutilizável para TiePieScope.exe

**Ação**: ❌ NÃO RECOMENDADO (destrutivo)

### Opção 4: Usar LibUsb-Win32 (Wrapper)
**Prós**:
- Biblioteca open-source madura
- Funciona em paralelo com driver existente (às vezes)

**Contras**:
- Pode ter conflitos com `HS3r.sys`
- Requer LibUsbDotNet NuGet package
- Compatibilidade incerta

**Ação**: ⚠️ FALLBACK se SDK não disponível

---

## 📋 Próximos Passos (PRIORITÁRIO)

### Imediato (enquanto aguarda SDK)
1. ✅ Documentar blocker (este ficheiro)
2. ⏳ Aguardar resposta TiePie Engineering
3. 🔄 Continuar desenvolvimento de componentes independentes:
   - HS3FunctionGenerator.cs (API high-level)
   - HS3FirmwareLoader.cs (Intel HEX parser)
   - Testes unitários (sem hardware)

### Se SDK Disponível (Cenário Ideal)
1. Integrar TiePie SDK (.DLL)
2. Criar wrapper `HS3SdkProtocol.cs`
3. Validar com hardware real
4. Implementar function generator completo

### Se SDK NÃO Disponível (Cenário Pessimista)
1. Testar LibUsb-Win32 como alternativa
2. Se LibUsb falhar: reverter para mock/simulator
3. Documentar limitações no README.md
4. Aguardar aquisição de SDK ou novo hardware

---

## 🔬 Informação de Debug (para TiePie Support)

### Environment
- **OS**: Windows 11 Pro (Build 22631)
- **SDK**: .NET 8.0.403
- **Hardware**: TiePie Handyscope HS3 (VID_0E36 & PID_0008)
- **Driver**: HS3r v6.0.6.0 (26/02/2010)

### Device Manager Properties
```
InstanceId: USB\VID_0E36&PID_0008\6&24C7B282&0&1
Status: OK
Location: Port_#0001.Hub_#0004
PDO Name: \Device\USBPDO-13
```

### P/Invoke Attempt
```csharp
SafeFileHandle handle = CreateFile(
    @"\\?\usb#vid_0e36&pid_0008#6&24c7b282&0&1#{AF43275C-FB24-4371-BAF8-2BA656FB33E6}",
    GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    IntPtr.Zero,
    OPEN_EXISTING,
    0, // FILE_FLAG_OVERLAPPED = 0
    IntPtr.Zero
);
// Result: IsInvalid=true, GetLastWin32Error()=2
```

### Question for TiePie:
> What is the correct **symbolic link name** (e.g., `\\.\HS3`) or **device interface GUID** to open the HS3 via CreateFile in C#? Is there an official SDK/.NET wrapper available?

---

## 📚 Referências
- **API Monitor Logs**: `ApiMonitor_COM_Equipamento.csv` (IOCTL 0x222000, 0x222051, 0x22204E capturados)
- **Email TiePie**: `EMAIL_TIEPIE_SDK_REQUEST_22OUT2025.md`
- **Protocolo Análise**: `PROTOCOLO_HS3_COMPLETO_23OUT2025.md`
- **Código Implementado**: `src/BioDesk.Services/Hardware/TiePie/Protocol/HS3DeviceProtocol.cs`

---

**ÚLTIMA ATUALIZAÇÃO**: 23/10/2025 20:30
**PRÓXIMA AÇÃO**: Aguardar resposta TiePie Engineering (ETA desconhecido)
