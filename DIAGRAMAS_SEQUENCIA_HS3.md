# 🔄 Diagramas de Sequência - Protocolo HS3 USB

## 📋 Índice
1. [Sequência Completa de Inicialização](#sequência-completa-de-inicialização)
2. [Padrão Read-Write Loop](#padrão-read-write-loop)
3. [Firmware Loading](#firmware-loading)
4. [Tratamento de Erros](#tratamento-de-erros)

---

## Sequência Completa de Inicialização

```mermaid
sequenceDiagram
    participant App as BioDeskPro2
    participant Protocol as HS3DeviceProtocol
    participant WinAPI as Win32 API
    participant USB as TiePie HS3 Device

    Note over App,USB: Fase 0: Discovery (0ms)
    App->>Protocol: OpenDevice(devicePath)
    Protocol->>WinAPI: CreateFile(devicePath, GENERIC_READ|WRITE)
    WinAPI->>USB: Open USB endpoint
    USB-->>WinAPI: Handle 0x00000f3c
    WinAPI-->>Protocol: SafeFileHandle
    Protocol-->>App: true (success)

    Note over App,USB: Fase 1: Device Info (0-3ms)
    App->>Protocol: GetDeviceCapabilities()
    Protocol->>WinAPI: DeviceIoControl(0x222000, 0→1024B)
    WinAPI->>USB: IOCTL_GET_DEVICE_INFO
    USB-->>WinAPI: 1024 bytes (capabilities)
    WinAPI-->>Protocol: HS3DeviceCapabilities
    Protocol-->>App: {VID: 0x0E36, PID: 0x0008, Serial, FW, HW}

    Note over App,USB: Fase 2: Configuração (3-6ms)
    App->>Protocol: ConfigureDevice(configData)
    Protocol->>WinAPI: DeviceIoControl(0x222059, 10→8B)
    WinAPI->>USB: IOCTL_CONFIG_QUERY
    USB-->>WinAPI: 8 bytes (config response)
    WinAPI-->>Protocol: Config ACK
    Protocol-->>App: true (configured)

    Note over App,USB: Fase 3: Read-Write Loop (6-400ms)
    loop 33 vezes
        App->>Protocol: SendCommand(cmd, out response)
        
        Note over Protocol,USB: Sub-fase 3a: READ
        Protocol->>WinAPI: DeviceIoControl(0x222051, 4→8B)
        WinAPI->>USB: IOCTL_READ_OPERATION
        USB-->>WinAPI: 8 bytes (status/value)
        WinAPI-->>Protocol: HS3Response8
        
        Note over Protocol,USB: Sub-fase 3b: WRITE
        Protocol->>WinAPI: DeviceIoControl(0x22204E, 4→1-64B)
        WinAPI->>USB: IOCTL_WRITE_OPERATION
        USB-->>WinAPI: 1-64 bytes (command ACK)
        WinAPI-->>Protocol: Write response
        
        Protocol-->>App: true + response data
    end

    Note over App,USB: Fase 4: Firmware Loading (403-468ms)
    App->>Protocol: LoadFirmware("hs3f12.hex")
    Protocol->>WinAPI: FindFirstFileA("hs3f12.hex")
    WinAPI-->>Protocol: File handle
    
    loop 1948 vezes
        Protocol->>WinAPI: ReadFile(128 bytes)
        WinAPI-->>Protocol: Firmware chunk
        Protocol->>USB: Upload chunk (via IOCTL?)
        USB-->>Protocol: Upload ACK
    end
    
    Protocol-->>App: Firmware loaded (243.5 KB)
```

---

## Padrão Read-Write Loop

Este é o padrão mais comum observado no log (66 das 80 chamadas DeviceIoControl).

```mermaid
sequenceDiagram
    participant App as Aplicação
    participant Protocol as HS3DeviceProtocol
    participant Device as TiePie HS3

    Note over App,Device: Exemplo: Configurar Frequência

    App->>Protocol: SendCommand(SET_FREQUENCY, ...)
    
    rect rgb(200, 230, 255)
        Note over Protocol,Device: FASE 1: READ - Query Status
        Protocol->>Device: IOCTL 0x222051 (READ_OPERATION)
        Note right of Protocol: Input: 4 bytes (command code)
        Note right of Protocol: Output: 8 bytes (expected)
        Device-->>Protocol: HS3Response8 {current_frequency}
        Note left of Device: Latência: ~0.1ms
    end
    
    rect rgb(255, 230, 200)
        Note over Protocol,Device: FASE 2: WRITE - Send Command
        Protocol->>Device: IOCTL 0x22204E (WRITE_OPERATION)
        Note right of Protocol: Input: 4 bytes (command code)
        Note right of Protocol: Output: 1-64 bytes (variable)
        Device-->>Protocol: Status byte {0x00 = OK}
        Note left of Device: Latência: ~0.3ms (1B) ou ~2.5ms (64B)
    end
    
    Protocol-->>App: true + response
    
    Note over App,Device: Total: ~0.4ms (operações simples)<br/>ou ~2.6ms (bulk transfers 64B)
```

### Observações sobre Latências

- **Operações simples (1-8 bytes)**: 0.05-0.3ms
- **Bulk transfers (48 bytes)**: 0.3-0.4ms  
- **Bulk transfers (64 bytes - USB packet max)**: **2.5-2.6ms** ⚠️ **LATÊNCIA CRÍTICA**

**Implicação**: Batching de comandos pode melhorar throughput para operações sequenciais.

---

## Firmware Loading

```mermaid
sequenceDiagram
    participant App as BioDeskPro2
    participant Loader as HS3FirmwareLoader
    participant FS as File System
    participant Device as TiePie HS3 FPGA

    App->>Loader: LoadFirmwareAsync()
    
    Note over Loader,FS: Localizar Firmware
    Loader->>FS: FindFirstFileA("hs3f12.hex")
    alt Ficheiro encontrado
        FS-->>Loader: File handle + info
    else Ficheiro não encontrado
        FS-->>Loader: ERROR_FILE_NOT_FOUND
        Loader-->>App: false (firmware not found)
    end
    
    Note over Loader,Device: Streaming de Firmware (1948 chunks)
    
    Loader->>FS: Open("hs3f12.hex")
    FS-->>Loader: Stream handle
    
    loop 1948 vezes (128 bytes cada)
        Loader->>FS: ReadFile(128 bytes)
        FS-->>Loader: Firmware chunk
        Note right of Loader: Latência: ~20-40μs
        
        Loader->>Device: Upload chunk (IOCTL?)
        Note right of Loader: Comando desconhecido<br/>Hipótese: IOCTL 0x22204E<br/>com comando especial
        Device-->>Loader: Upload ACK
        
        opt A cada 100 chunks
            Loader->>App: Progress update (X%)
        end
    end
    
    Loader->>FS: CloseHandle()
    
    Note over Device: FPGA reconfigura com novo firmware
    Note over Device: Tempo: ~65ms total
    
    Loader-->>App: true (success) + stats
    Note left of App: Total: 249,344 bytes (243.5 KB)<br/>Throughput: ~3.75 MB/s
```

### Questões em Aberto

1. **Qual IOCTL é usado para upload de firmware?**
   - Hipótese 1: IOCTL_WRITE_OPERATION (0x22204E) com comando específico
   - Hipótese 2: IOCTL não capturado pelo API Monitor (bulk transfer direto)

2. **Formato do ficheiro hs3f12.hex**
   - Intel HEX format?
   - Raw binary?
   - Precisa parsing antes de upload?

3. **Verificação de integridade**
   - Existe checksum?
   - Device valida firmware antes de aceitar?

---

## Tratamento de Erros

```mermaid
sequenceDiagram
    participant App as Aplicação
    participant Protocol as HS3DeviceProtocol
    participant Device as TiePie HS3

    Note over App,Device: Cenário 1: Device Não Conectado
    
    App->>Protocol: OpenDevice(devicePath)
    Protocol->>Device: CreateFile(...)
    Device--xProtocol: ERROR_FILE_NOT_FOUND (2)
    Protocol-->>App: false + log error
    App->>App: Mostrar mensagem<br/>"Device HS3 não conectado"

    Note over App,Device: Cenário 2: Device Busy

    App->>Protocol: SendCommand(cmd)
    Protocol->>Device: IOCTL_READ_OPERATION
    Device-->>Protocol: HS3Response8
    Protocol->>Device: IOCTL_WRITE_OPERATION
    Device-->>Protocol: Status {0x01 = BUSY}
    
    alt Retry habilitado
        loop Até 3 tentativas
            Protocol->>Protocol: Wait(50ms)
            Protocol->>Device: IOCTL_WRITE_OPERATION (retry)
            alt Device ready
                Device-->>Protocol: Status {0x00 = OK}
                Protocol-->>App: true (success após retry)
            else Still busy
                Device-->>Protocol: Status {0x01 = BUSY}
            end
        end
    else Retry desabilitado
        Protocol-->>App: false + log warning
    end

    Note over App,Device: Cenário 3: USB Timeout

    App->>Protocol: SendCommand(cmd)
    Protocol->>Device: IOCTL_READ_OPERATION
    Note right of Device: Device não responde<br/>USB timeout (5s default)
    Device--xProtocol: ERROR_TIMEOUT (1460)
    Protocol-->>App: false + log error
    App->>App: Tentar reabrir device

    Note over App,Device: Cenário 4: Invalid IOCTL

    App->>Protocol: SendCommand(unknownCmd)
    Protocol->>Device: IOCTL_READ_OPERATION
    Device--xProtocol: ERROR_INVALID_FUNCTION (1)
    Protocol-->>App: false + log error
```

### Códigos de Erro Comuns

| Código Win32 | Nome | Descrição | Ação Sugerida |
|--------------|------|-----------|---------------|
| 2 | ERROR_FILE_NOT_FOUND | Device não encontrado | Verificar conexão USB |
| 5 | ERROR_ACCESS_DENIED | Acesso negado | Verificar permissões/driver |
| 6 | ERROR_INVALID_HANDLE | Handle inválido | Reabrir device |
| 1 | ERROR_INVALID_FUNCTION | IOCTL não suportado | Verificar código IOCTL |
| 1460 | ERROR_TIMEOUT | Timeout na operação | Aumentar timeout ou reset device |
| 31 | ERROR_GEN_FAILURE | Falha geral do device | Reset USB hub |

---

## Fluxo de Estado do Device

```mermaid
stateDiagram-v2
    [*] --> Disconnected
    
    Disconnected --> Opening : OpenDevice()
    Opening --> Connected : CreateFile success
    Opening --> Disconnected : CreateFile failed
    
    Connected --> GettingInfo : GetDeviceCapabilities()
    GettingInfo --> InfoObtained : IOCTL 0x222000 success
    GettingInfo --> Error : IOCTL failed
    
    InfoObtained --> Configuring : ConfigureDevice()
    Configuring --> Ready : IOCTL 0x222059 success
    Configuring --> Error : IOCTL failed
    
    Ready --> Operating : SendCommand()
    Operating --> Ready : Command success
    Operating --> Busy : Device busy (retry)
    Operating --> Error : Command failed
    
    Busy --> Ready : Retry success
    Busy --> Error : Max retries exceeded
    
    Ready --> LoadingFirmware : LoadFirmware()
    LoadingFirmware --> Ready : Upload success
    LoadingFirmware --> Error : Upload failed
    
    Error --> Disconnected : CloseDevice()
    Ready --> Disconnected : CloseDevice()
    Operating --> Disconnected : USB disconnected
    
    Error --> [*]
    Disconnected --> [*]
```

---

## Timeline Real da Captura (Primeiros 100ms)

```mermaid
gantt
    title Operações HS3 - Timeline API Monitor (10:39:26.003 - 10:39:26.105)
    dateFormat SSS
    axisFormat %L ms
    
    section Inicialização
    RegisterDeviceNotification   :milestone, 000, 0ms
    SysAllocStringLen (USB path) :milestone, 000, 0ms
    
    section Device Info
    IOCTL 0x222000 (1024B)       :crit, 000, 003
    
    section Configuração
    IOCTL 0x222059 (10→8B)       :active, 003, 006
    
    section Read-Write Loop
    READ 0x222051 (1)            :007, 008
    READ 0x222051 (2)            :008, 009
    READ 0x222051 (3)            :009, 010
    WRITE 0x22204E (1)           :011, 012
    READ 0x222051 (4)            :012, 013
    WRITE 0x22204E (2)           :013, 014
    READ 0x222051 (5)            :014, 015
    WRITE 0x22204E (3)           :026, 027
    READ 0x222051 (6)            :027, 028
    WRITE 0x22204E (4)           :042, 043
    READ 0x222051 (7)            :043, 044
    WRITE 0x22204E (5) 48B       :058, 059
    READ 0x222051 (8)            :059, 060
    WRITE 0x22204E (6) 48B       :075, 076
    READ 0x222051 (9)            :076, 077
    WRITE 0x22204E (7) 48B       :090, 091
    READ 0x222051 (10)           :091, 092
    WRITE 0x22204E (8) 48B       :105, 106
    WRITE 0x22204E (9) 64B       :crit, 105, 108
```

**Legenda**:
- 🔴 Crítico (crit): Operações que determinam sucesso da inicialização
- 🟢 Ativo (active): Operações de configuração
- ⚪ Normal: Operações regulares de read-write

---

## Implementação de Retry Logic

```mermaid
flowchart TD
    Start([SendCommand]) --> Lock{Acquire<br/>Device Lock}
    Lock -->|Locked| CheckDevice{Device<br/>Open?}
    CheckDevice -->|No| ErrorNoDevice[Log Error:<br/>Device not open]
    ErrorNoDevice --> ReturnFalse1([Return false])
    
    CheckDevice -->|Yes| Read[IOCTL_READ_OPERATION<br/>Command → Response]
    Read --> ReadSuccess{Read<br/>Success?}
    ReadSuccess -->|No| ReadError[Log Error:<br/>Read failed]
    ReadError --> ReturnFalse2([Return false])
    
    ReadSuccess -->|Yes| Write[IOCTL_WRITE_OPERATION<br/>Command + Data]
    Write --> WriteSuccess{Write<br/>Success?}
    WriteSuccess -->|No| WriteError[Log Error:<br/>Write failed]
    WriteError --> Retry{Retry<br/>Count < 3?}
    
    Retry -->|Yes| Wait[Wait 50ms]
    Wait --> Write
    Retry -->|No| MaxRetries[Log Error:<br/>Max retries]
    MaxRetries --> ReturnFalse3([Return false])
    
    WriteSuccess -->|Yes| CheckStatus{Parse<br/>Status}
    CheckStatus -->|0x00 OK| Success[Log Success]
    CheckStatus -->|0x01 Busy| RetryBusy{Retry<br/>Count < 3?}
    CheckStatus -->|0xFF Error| DeviceError[Log Device Error]
    
    RetryBusy -->|Yes| Wait
    RetryBusy -->|No| MaxRetries
    DeviceError --> ReturnFalse4([Return false])
    
    Success --> UnlockSuccess[Release Lock]
    UnlockSuccess --> ReturnTrue([Return true])
    
    ReturnFalse1 --> End([End])
    ReturnFalse2 --> End
    ReturnFalse3 --> End
    ReturnFalse4 --> End
    ReturnTrue --> End
```

---

**Documentação criada por**: Copilot Coding Agent  
**Data**: 19 outubro 2025  
**Versão**: 1.0  
**Baseado em**: ApiMonitor_COM_Equipamento.txt (2034 linhas, 1948 ReadFile, 80 DeviceIoControl)
