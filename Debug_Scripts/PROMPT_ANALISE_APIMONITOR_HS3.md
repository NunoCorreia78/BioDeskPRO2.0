# 🎯 PROMPT DE ANÁLISE - Captura API Monitor HS3.dll

## 📊 **CONTEXTO**
Foi capturado um log detalhado (19047 entradas) do API Monitor durante a inicialização e operação do software **Inergetix-CoRe 5.0** com o equipamento TiePie HS3 conectado.

**Ficheiro analisado**: `ApiMonitor_COM_Equipamento.txt`  
**Thread principal**: Thread 7  
**Período capturado**: ~450ms (10:39:26.003 PM - 10:39:26.468 PM)  

---

## 🔍 **OBJETIVO DA ANÁLISE**

Analisar o comportamento da DLL `hs3.dll` (TiePie Handyscope HS3) para:

1. **Identificar protocolo de comunicação USB**
2. **Mapear IOCTL codes relevantes** (DeviceIoControl)
3. **Compreender sequência de inicialização** do dispositivo
4. **Extrair padrões para replicação em C#/.NET**

---

## 📋 **DADOS CAPTURADOS**

### **A. APIs detectadas (por ordem de relevância)**

#### **1. DeviceIoControl - Comunicação USB (104 chamadas)**
```
IOCTL Codes identificados:
- 2236416 (0x222000) → Get device info (1024 bytes buffer)
- 2236505 (0x222059) → Device configuration/query (10 bytes in, 8 bytes out)
- 2236497 (0x222051) → Read/Write operations (4 bytes in, 8 bytes out)
- 2236494 (0x22204E) → Status/Control commands (variável: 1-64 bytes out)

Handle device: 0x00000f3c (fixo em todas as chamadas)
```

**Padrões observados:**
- **Sequência Read-Write alternada**: IOCTL 2236497 (read) → IOCTL 2236494 (write/status)
- **Buffers típicos**: 4 bytes input, 2-64 bytes output
- **Latências**: 0.05ms - 2.6ms por operação

---

#### **2. ReadFile - Firmware loading (1792 chamadas)**
```
Handle: 0x00000fc0 (ficheiro hs3f12.hex)
Buffer: 128 bytes por leitura
Padrão: Leituras sequenciais (20μs cada)
Total estimado: ~229 KB firmware
```

**Sequência firmware:**
1. `FindFirstFileA("C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\hs3f12.hex")`
2. 1792× `ReadFile(128 bytes)` - streaming de firmware para o dispositivo
3. Sem erros detectados (todos `TRUE`)

---

#### **3. Inicialização (3 chamadas)**
```
RegisterDeviceNotificationA(DEVICE_NOTIFY_WINDOW_HANDLE) → 0x07e02f80 (success)
SysAllocStringLen("\\?\usb#vid_0e36&pid_0008#...") → Device path USB
SysFreeString(NULL) → Cleanup
```

**Device path extraído:**
```
\\?\usb#vid_0e36&pid_0008#8&14447dc6&0&1#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}
```
- **VID**: 0x0E36 (TiePie engineering)
- **PID**: 0x0008 (Handyscope HS3)
- **GUID**: `{f58af81e-4cdc-4d3f-b11e-0a89e4683972}` (device interface class)

---

## 🎯 **TAREFAS DE ANÁLISE PARA O AGENTE**

### **1. Reverse-engineer IOCTL codes**
```csharp
// TAREFA: Mapear IOCTL codes para funções C#
const uint IOCTL_GET_DEVICE_INFO = 0x222000;   // 2236416
const uint IOCTL_CONFIG_QUERY = 0x222059;      // 2236505
const uint IOCTL_READ_OPERATION = 0x222051;    // 2236497
const uint IOCTL_STATUS_CONTROL = 0x22204E;    // 2236494

// PERGUNTA: Qual é a estrutura dos buffers de entrada/saída?
// - Analisar endereços de memória (0x00afcde0, 0x217811b4, etc.)
// - Deduzir estrutura de dados baseado em tamanhos (4 in, 8 out)
```

---

### **2. Mapear sequência de inicialização**
```
TIMELINE (primeiros 100ms):

[0ms] RegisterDeviceNotificationA → Registo de eventos USB
[0ms] SysAllocStringLen → Obter device path
[0ms] DeviceIoControl(IOCTL_GET_DEVICE_INFO) → Query capacidades
[3ms] DeviceIoControl(IOCTL_CONFIG_QUERY) → Configurar sampling rate?
[6ms] LOOP: 
      - DeviceIoControl(IOCTL_READ_OPERATION) → Read status
      - DeviceIoControl(IOCTL_STATUS_CONTROL) → Write command
      [Repetir 100× com delays 15ms]

[403ms] FindFirstFileA(hs3f12.hex) → Localizar firmware
[403ms-468ms] 1792× ReadFile(128 bytes) → Upload firmware para FPGA
```

**PERGUNTA CRÍTICA**: 
- O firmware é carregado **sempre** ou só quando necessário?
- Existe checksum/versão no protocolo?

---

### **3. Identificar padrões de comando-resposta**

**Exemplo da captura (linhas 19052-19053):**
```
WRITE: DeviceIoControl(0x00000f3c, 2236497, 0x00afcde0, 4, 0x217811b4, 8, ...)
       Input: 4 bytes @ 0x00afcde0
       Output: 8 bytes @ 0x217811b4
       
READ:  DeviceIoControl(0x00000f3c, 2236497, 0x00afce38, 4, 0x217811b4, 8, ...)
       [Mesmo output buffer 0x217811b4]
```

**Hipótese**: Buffer de output é **partilhado** → possível estrutura de estado global?

---

### **4. Analisar delays e timing crítico**

**Delays observados:**
```
19055 → 0.29ms (config query)
19051 → 0.57ms (long operation)
19071 → 2.54ms (bulk transfer 64 bytes)
19073 → 2.55ms (bulk transfer 64 bytes)
```

**PERGUNTA**: 
- São delays de **hardware** (USB latency) ou **software** (polling)?
- Precisamos manter estes delays em C#?

---

### **5. Extrair estruturas de dados implícitas**

**Buffer sizes pattern:**
```
1 byte  → Status flags (19055)
2 bytes → Short value/error code (19091, 19093)
4 bytes → Integer/float parameter (19059, 19113)
6 bytes → Complex structure (19087, 19089)
10 bytes → Extended data (19061)
16 bytes → Device info struct (19097-19100)
48 bytes → Bulk data transfer (19063, 19065, 19067)
64 bytes → Max packet size (19071, 19073, 19075)
```

**TAREFA**: Criar estruturas C# correspondentes:
```csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HS3DeviceInfo {
    // 16 bytes total
    public ushort VendorId;
    public ushort ProductId;
    public uint SerialNumber;
    public byte FirmwareVersion;
    public byte HardwareRevision;
    // ... (deduzir resto)
}
```

---

## 🚀 **ENTREGÁVEIS ESPERADOS**

### **1. Documento técnico**
- **`ANALISE_IOCTL_HS3_DETALHADA.md`**
  - Tabela completa de IOCTL codes
  - Descrição funcional de cada comando
  - Estruturas de dados inferidas
  - Diagramas de sequência (Mermaid)

### **2. Código C# proof-of-concept**
```csharp
// HS3DeviceProtocol.cs
public class HS3DeviceProtocol {
    private const uint IOCTL_GET_INFO = 0x222000;
    
    [DllImport("kernel32.dll")]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped
    );
    
    public DeviceInfo GetDeviceInfo() {
        // Implementar baseado em análise
    }
}
```

### **3. Plano de testes**
- Lista de cenários para validar comunicação
- Comparação binária com logs originais
- Testes de stress (1000 operações sequenciais)

---

## ⚠️ **PONTOS DE ATENÇÃO**

### **🔴 Crítico**
1. **Endereços de memória são relativos** - não podem ser hardcoded
2. **Firmware path é absoluto** - precisa ser configurável
3. **Handle 0x00000f3c é dinâmico** - obter via CreateFile
4. **Thread safety** - todas as operações são single-threaded (Thread 7)

### **🟡 Importante**
- Latências USB podem variar entre PCs
- Buffer sizes devem ser respeitados (overflow = crash)
- IOCTL order matters (não paralelizar)

### **🟢 Nice-to-have**
- Retry logic para falhas USB
- Logging detalhado para debug
- Fallback para modo simulação (sem hardware)

---

## 📌 **PRÓXIMOS PASSOS SUGERIDOS**

1. **Analisar ficheiro `hs3f12.hex`**
   - Formato: Intel HEX ou binário?
   - Tamanho vs. número de `ReadFile` calls (229KB?)
   - Checksum embebido?

2. **Comparar com documentação TiePie**
   - SDK oficial tem structs públicas?
   - Header files `.h` com `#define IOCTL_...`?

3. **Criar wrapper C# minimalista**
   - Testar apenas `GetDeviceInfo()`
   - Validar se device responde
   - Comparar bytes recebidos com captura

4. **Integrar com BioDeskPro2**
   - Adaptar para padrão `IFrequencyEmitterService`
   - Implementar dispose pattern
   - Adicionar telemetria/logging

---

## 💡 **PERGUNTAS PARA INVESTIGAÇÃO**

1. **Por que 1792 leituras de 128 bytes?**
   - 1792 × 128 = 229,376 bytes (224KB)
   - Firmware HS3 tipicamente tem 256KB FPGA
   - Faltam ~32KB? → Verificar ficheiro real

2. **Buffers de output reutilizados?**
   - `0x217811b4` aparece 12× consecutivas
   - É cache? Estado device?
   - Precisa de lock em C#?

3. **Delays são polling ou async?**
   - API Monitor mostra tempo **bloqueante**
   - Alternativa: usar overlapped I/O em C#?

4. **Device path é estável?**
   - `#8&14447dc6&0&1` → muda com USB port?
   - Precisa de discovery dinâmico?

---

## 🎓 **REFERÊNCIAS ÚTEIS**

- **TiePie SDK**: [libtiepie documentation](https://www.tiepie.com/libtiepie-sdk)
- **IOCTL codes**: [Windows DDK - CTL_CODE macro](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/defining-i-o-control-codes)
- **USB device paths**: [SetupDiGetDeviceInterfaceDetail](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetaila)

---

**Data de análise**: 19 outubro 2025  
**Versão do ficheiro**: ApiMonitor_COM_Equipamento.txt (19047 linhas)  
**Status**: ✅ Pronto para análise detalhada
