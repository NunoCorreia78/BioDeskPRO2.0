# Guia Completo: Protocolo USB TiePie Handyscope HS3

**Data**: 20 de outubro de 2025
**Versão**: 1.0
**Status**: Pronto para validação com hardware físico

---

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Arquitetura Protocol Layer](#arquitetura-protocol-layer)
3. [Validação com Hardware Físico](#validação-com-hardware-físico)
4. [Descoberta de IOCTL e Comandos](#descoberta-de-ioctl-e-comandos)
5. [Troubleshooting](#troubleshooting)
6. [Referências](#referências)

---

## 🎯 Visão Geral

### O Que Foi Implementado

O BioDeskPro2 implementa **comunicação USB direta** com o osciloscópio TiePie Handyscope HS3 através de **DeviceIoControl** (Win32 API), eliminando a dependência da biblioteca proprietária `hs3.dll`.

### Fonte dos Dados

Toda a implementação foi baseada em **reverse-engineering** via **API Monitor** capturando a comunicação do software **Inergetix CoRe 5.0** com o hardware:

- **2034 linhas de log** (API Monitor)
- **465ms de operação** capturada
- **33 ciclos READ→WRITE** observados
- **4 IOCTL codes** identificados

### Status Atual

| Componente                 | Status         | Notas                                      |
|----------------------------|----------------|--------------------------------------------|
| **HS3Protocol.cs**         | ✅ Completo     | Constantes e estruturas validadas          |
| **HS3DeviceDiscovery.cs**  | ✅ Completo     | SetupDi APIs funcionais                    |
| **HS3DeviceProtocol.cs**   | ✅ Completo     | DeviceIoControl + Dispose CA1063           |
| **HS3ProtocolTests.cs**    | ✅ Completo     | 9 testes prontos (skipped sem hardware)    |
| **TiePieHS3Service.cs**    | ⚠️ Parcial     | InitializeAsync OK, EmitFrequency pendente |
| **HS3Commands**            | ⚠️ Hipotético  | Códigos inferidos, requerem validação      |

**⚠️ IMPORTANTE**: Os códigos de comando em `HS3Commands` são **hipotéticos** e marcados com comentários `// TO VALIDATE WITH HARDWARE`. Foram inferidos dos padrões observados nos logs mas **não foram testados** com hardware real.

---

## 🏗️ Arquitetura Protocol Layer

### Estrutura de Ficheiros

```
src/BioDesk.Services/Hardware/TiePie/
├── Protocol/
│   ├── HS3Protocol.cs          (360 linhas) - Constantes + Estruturas
│   ├── HS3DeviceDiscovery.cs   (380 linhas) - SetupDi USB Discovery
│   └── HS3DeviceProtocol.cs    (550 linhas) - DeviceIoControl Communication
├── TiePieHS3Service.cs         (200 linhas) - Service Layer Integration
└── DummyTiePieHardwareService.cs (fallback simulado)

src/BioDesk.Tests/Hardware/TiePie/
└── Protocol/
    └── HS3ProtocolTests.cs     (370 linhas) - Integration Tests
```

### 1. HS3Protocol.cs - Constantes e Estruturas

#### IOCTL Codes (Validados via API Monitor)

```csharp
// Device Information (1024 bytes output)
public const uint IOCTL_GET_DEVICE_INFO = 0x222000;

// Configuration Query (10 bytes input → 8 bytes output)
public const uint IOCTL_CONFIG_QUERY = 0x222059;

// Read Operation (4 bytes input → 8 bytes output)
public const uint IOCTL_READ_OPERATION = 0x222051;

// Write Operation (4 bytes input → 1-64 bytes output)
public const uint IOCTL_WRITE_OPERATION = 0x22204E;
```

#### USB Identifiers (Validados em Device Manager)

```csharp
public const ushort USB_VENDOR_ID = 0x0E36;   // TiePie Engineering
public const ushort USB_PRODUCT_ID = 0x0008;  // Handyscope HS3

public static readonly Guid DEVICE_INTERFACE_GUID =
    new Guid("{f58af81e-4cdc-4d3f-b11e-0a89e4683972}");
```

#### Estruturas de Dados (StructLayout Sequential)

**HS3DeviceCapabilities** (1024 bytes):
```csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HS3DeviceCapabilities
{
    public ushort VendorId;           // 0x0E36
    public ushort ProductId;          // 0x0008
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
    public byte[] SerialNumber;       // String ASCII
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] FirmwareVersion;    // Ex: "12.01.2023"
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 974)]
    public byte[] Reserved;           // Padding para 1024 bytes
}
```

**HS3Response8** (8 bytes - union-like):
```csharp
[StructLayout(LayoutKind.Explicit, Pack = 1)]
public struct HS3Response8
{
    [FieldOffset(0)] public byte StatusByte;
    [FieldOffset(0)] public uint Status4Bytes;
    [FieldOffset(0)] public ulong All8Bytes;
}
```

**HS3ConfigData** (10 bytes):
```csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HS3ConfigData
{
    public byte ConfigType;       // Tipo de configuração
    public byte Reserved1;
    public ushort Parameter1;     // Parâmetro 1 (ex: sample rate)
    public ushort Parameter2;     // Parâmetro 2 (ex: buffer size)
    public uint Reserved2;
}
```

**HS3BulkData64** (64 bytes máximo):
```csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HS3BulkData64
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] Data;
}
```

#### Timing Constants (Observados em API Monitor)

```csharp
public const int BULK_TRANSFER_64_BYTES_MS = 2;     // 2.5ms arredondado
public const int DEVICE_TIMEOUT_MS = 5000;          // Timeout padrão
public const int READ_WRITE_CYCLE_DELAY_MS = 1;     // Delay entre READ e WRITE
```

#### HS3Commands (⚠️ HIPOTÉTICOS - Requerem Validação)

```csharp
// TO VALIDATE WITH HARDWARE: Estes códigos foram inferidos dos padrões
// observados nos logs do API Monitor mas NÃO foram testados com hardware real.
public static class HS3Commands
{
    // Device control
    public const uint CMD_RESET = 0x00000001;        // Reset device
    public const uint CMD_INITIALIZE = 0x00000002;   // Initialize
    public const uint CMD_SHUTDOWN = 0x00000003;     // Shutdown

    // Configuration
    public const uint CMD_SET_SAMPLE_RATE = 0x00000010;
    public const uint CMD_SET_BUFFER_SIZE = 0x00000011;
    public const uint CMD_SET_TRIGGER = 0x00000012;

    // Data acquisition
    public const uint CMD_START_ACQUISITION = 0x00000020;
    public const uint CMD_STOP_ACQUISITION = 0x00000021;
    public const uint CMD_READ_BUFFER = 0x00000022;

    // Status
    public const uint CMD_GET_STATUS = 0x00000030;
    public const uint CMD_GET_ERROR = 0x00000031;

    // Frequency generation (BioDeskPro2 specific)
    public const uint CMD_SET_FREQUENCY = 0x00000040;
    public const uint CMD_SET_AMPLITUDE = 0x00000041;
    public const uint CMD_START_OUTPUT = 0x00000042;
    public const uint CMD_STOP_OUTPUT = 0x00000043;
}
```

### 2. HS3DeviceDiscovery.cs - Descoberta USB

#### SetupDi APIs (P/Invoke)

```csharp
// Enumerar dispositivos por GUID
[DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
static extern IntPtr SetupDiGetClassDevs(
    ref Guid ClassGuid,
    IntPtr Enumerator,
    IntPtr hwndParent,
    uint Flags);

// Enumerar interfaces de dispositivo
[DllImport("setupapi.dll", SetLastError = true)]
static extern bool SetupDiEnumDeviceInterfaces(
    IntPtr DeviceInfoSet,
    IntPtr DeviceInfoData,
    ref Guid InterfaceClassGuid,
    uint MemberIndex,
    ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData);

// Obter detalhes da interface (tamanho)
[DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
static extern bool SetupDiGetDeviceInterfaceDetail(
    IntPtr DeviceInfoSet,
    ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
    IntPtr DeviceInterfaceDetailData,
    uint DeviceInterfaceDetailDataSize,
    out uint RequiredSize,
    IntPtr DeviceInfoData);

// Obter detalhes da interface (dados)
[DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Auto)]
static extern bool SetupDiGetDeviceInterfaceDetail(
    IntPtr DeviceInfoSet,
    ref SP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
    ref SP_DEVICE_INTERFACE_DETAIL_DATA DeviceInterfaceDetailData,
    uint DeviceInterfaceDetailDataSize,
    out uint RequiredSize,
    IntPtr DeviceInfoData);

// Destruir lista de dispositivos
[DllImport("setupapi.dll", SetLastError = true)]
static extern bool SetupDiDestroyDeviceInfoList(IntPtr DeviceInfoSet);
```

#### Estruturas SetupDi

```csharp
[StructLayout(LayoutKind.Sequential)]
struct SP_DEVICE_INTERFACE_DATA
{
    public uint cbSize;
    public Guid InterfaceClassGuid;
    public uint Flags;
    public IntPtr Reserved;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
struct SP_DEVICE_INTERFACE_DETAIL_DATA
{
    public uint cbSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string DevicePath;
}

[StructLayout(LayoutKind.Sequential)]
struct SP_DEVINFO_DATA
{
    public uint cbSize;
    public Guid ClassGuid;
    public uint DevInst;
    public IntPtr Reserved;
}
```

#### Métodos Públicos

```csharp
/// <summary>
/// Encontra todos os dispositivos TiePie HS3 conectados
/// </summary>
public List<string> FindHS3Devices();

/// <summary>
/// Encontra o primeiro dispositivo TiePie HS3 (mais comum)
/// </summary>
public string? FindFirstHS3Device();

/// <summary>
/// Valida se um device path é realmente um TiePie HS3 (VID_0E36&PID_0008)
/// </summary>
private bool IsHS3Device(string devicePath);
```

#### Padrão de Device Path

```
\\?\usb#vid_0e36&pid_0008#serialnumber#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}
```

### 3. HS3DeviceProtocol.cs - Comunicação USB

#### Win32 APIs (P/Invoke)

```csharp
// Abrir handle para dispositivo
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
static extern SafeFileHandle CreateFile(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    IntPtr hTemplateFile);

// Enviar IOCTL para dispositivo
[DllImport("kernel32.dll", SetLastError = true)]
static extern bool DeviceIoControl(
    SafeFileHandle hDevice,
    uint dwIoControlCode,
    IntPtr lpInBuffer,
    uint nInBufferSize,
    IntPtr lpOutBuffer,
    uint nOutBufferSize,
    out uint lpBytesReturned,
    IntPtr lpOverlapped);
```

#### Gestão de Buffers Pinned (GCHandle)

```csharp
// 3 buffers pinned para evitar realocações GC durante P/Invoke
private byte[] _readBuffer = new byte[8];
private byte[] _writeBuffer = new byte[64];
private byte[] _deviceInfoBuffer = new byte[1024];

private GCHandle _readBufferHandle;
private GCHandle _writeBufferHandle;
private GCHandle _deviceInfoBufferHandle;

// Pin buffers no construtor
public HS3DeviceProtocol(ILogger<HS3DeviceProtocol> logger)
{
    _logger = logger;
    _readBufferHandle = GCHandle.Alloc(_readBuffer, GCHandleType.Pinned);
    _writeBufferHandle = GCHandle.Alloc(_writeBuffer, GCHandleType.Pinned);
    _deviceInfoBufferHandle = GCHandle.Alloc(_deviceInfoBuffer, GCHandleType.Pinned);
}
```

#### Thread-Safety (Critical Section)

```csharp
private readonly object _deviceLock = new object();

public bool ReadOperation(uint commandCode, out HS3Response8 response)
{
    lock (_deviceLock)  // SEMPRE proteger acesso ao dispositivo
    {
        // ... DeviceIoControl call ...
    }
}
```

#### API Pública (Métodos Principais)

```csharp
/// <summary>
/// Abre conexão com dispositivo USB (CreateFile)
/// </summary>
public bool OpenDevice(string devicePath);

/// <summary>
/// Obtém capacidades do dispositivo (IOCTL 0x222000)
/// Valida VID=0x0E36 e PID=0x0008
/// </summary>
public bool GetDeviceCapabilities(out HS3DeviceCapabilities capabilities);

/// <summary>
/// Configura dispositivo (IOCTL 0x222059)
/// </summary>
public bool ConfigureDevice(HS3ConfigData? configData = null);

/// <summary>
/// Lê 8 bytes de resposta (IOCTL 0x222051)
/// </summary>
public bool ReadOperation(uint commandCode, out HS3Response8 response);

/// <summary>
/// Escreve comando e lê resposta variável (IOCTL 0x22204E)
/// </summary>
public bool WriteOperation(uint commandCode, int expectedSize, out byte[] response);

/// <summary>
/// Fecha dispositivo e libera recursos (CA1063-compliant)
/// </summary>
public void Dispose();
```

#### Dispose Pattern (CA1063-Compliant)

```csharp
public void Dispose()
{
    Dispose(true);
    GC.SuppressFinalize(this);
}

protected virtual void Dispose(bool disposing)
{
    if (!_disposed)
    {
        if (disposing)
        {
            // Managed resources
            _deviceHandle?.Dispose();
        }

        // Unmanaged resources (GCHandle)
        if (_readBufferHandle.IsAllocated)
            _readBufferHandle.Free();
        if (_writeBufferHandle.IsAllocated)
            _writeBufferHandle.Free();
        if (_deviceInfoBufferHandle.IsAllocated)
            _deviceInfoBufferHandle.Free();

        _disposed = true;
    }
}
```

### 4. TiePieHS3Service.cs - Service Layer

#### Dependency Injection

```csharp
public class TiePieHS3Service : ITiePieHardwareService, IDisposable
{
    private readonly ILogger<TiePieHS3Service> _logger;
    private readonly HS3DeviceDiscovery _discovery;
    private readonly HS3DeviceProtocol _protocol;

    public TiePieHS3Service(
        ILogger<TiePieHS3Service> logger,
        HS3DeviceDiscovery discovery,
        HS3DeviceProtocol protocol)
    {
        _logger = logger;
        _discovery = discovery;
        _protocol = protocol;
    }
}
```

#### Sequência de Inicialização (InitializeAsync)

```csharp
public async Task<bool> InitializeAsync()
{
    try
    {
        // 1. Descoberta automática
        var devicePath = _discovery.FindFirstHS3Device();
        if (devicePath == null)
        {
            _logger.LogWarning("Nenhum dispositivo TiePie HS3 encontrado");
            return false;
        }

        // 2. Abrir dispositivo
        if (!_protocol.OpenDevice(devicePath))
        {
            _logger.LogError("Falha ao abrir dispositivo: {Path}", devicePath);
            return false;
        }

        // 3. Obter capacidades e validar VID/PID
        if (!_protocol.GetDeviceCapabilities(out var capabilities))
        {
            _logger.LogError("Falha ao obter capacidades do dispositivo");
            return false;
        }

        if (capabilities.VendorId != HS3Protocol.USB_VENDOR_ID ||
            capabilities.ProductId != HS3Protocol.USB_PRODUCT_ID)
        {
            _logger.LogError("VID/PID inválidos: {VID:X4}/{PID:X4}",
                capabilities.VendorId, capabilities.ProductId);
            return false;
        }

        // 4. Configurar dispositivo
        if (!_protocol.ConfigureDevice())
        {
            _logger.LogError("Falha ao configurar dispositivo");
            return false;
        }

        _logger.LogInformation("TiePie HS3 inicializado com sucesso");
        return true;
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Erro durante inicialização do TiePie HS3");
        return false;
    }
}
```

#### EmitFrequencyAsync (⚠️ Pendente Validação)

```csharp
public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeV, TimeSpan duration)
{
    // TODO: Implementar quando comandos forem validados com hardware
    _logger.LogWarning("EmitFrequencyAsync ainda não implementado - aguardando validação com hardware");
    return false;
}
```

---

## 🔬 Validação com Hardware Físico

### Pré-requisitos

1. **Hardware**:
   - TiePie Handyscope HS3 conectado via USB
   - Cabo USB de qualidade (evitar hubs)
   - Porta USB 2.0 ou superior

2. **Software**:
   - Windows 10/11
   - .NET 8 SDK instalado
   - Visual Studio Code com C# Dev Kit
   - Permissões de Administrador (recomendado)

3. **Drivers**:
   - Drivers TiePie instalados (ou usar drivers genéricos Windows)
   - Verificar em Device Manager: `VID_0E36&PID_0008`

### Checklist de Validação

#### 1️⃣ Verificar Dispositivo no Device Manager

```powershell
# Abrir Device Manager
devmgmt.msc

# Procurar por:
# - "TiePie Engineering" ou
# - "Universal Serial Bus devices" com VID_0E36&PID_0008
```

**Device Path esperado**:
```
\\?\usb#vid_0e36&pid_0008#[serial]#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}
```

#### 2️⃣ Testar Descoberta USB

```csharp
// No VS Code, abrir terminal integrado:
cd src/BioDesk.Tests
dotnet build

// Criar ficheiro de teste rápido (QuickTest.cs):
using BioDesk.Services.Hardware.TiePie.Protocol;
using Microsoft.Extensions.Logging.Abstractions;

var discovery = new HS3DeviceDiscovery(NullLogger<HS3DeviceDiscovery>.Instance);
var devices = discovery.FindHS3Devices();

if (devices.Count > 0)
{
    Console.WriteLine($"✅ Encontrados {devices.Count} dispositivo(s):");
    foreach (var path in devices)
    {
        Console.WriteLine($"   {path}");
    }
}
else
{
    Console.WriteLine("❌ Nenhum dispositivo TiePie HS3 encontrado");
}

discovery.Dispose();
```

```bash
# Executar:
dotnet script QuickTest.cs
```

**Saída esperada**:
```
✅ Encontrados 1 dispositivo(s):
   \\?\usb#vid_0e36&pid_0008#hs3001234#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}
```

#### 3️⃣ Ativar Testes de Integração

Editar `src/BioDesk.Tests/Hardware/TiePie/Protocol/HS3ProtocolTests.cs`:

```csharp
// ANTES (testes skipped):
[Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
public void Test_DeviceDiscovery_FindsHS3() { /* ... */ }

// DEPOIS (testes ativos):
[Fact]  // <-- Remover Skip attribute
public void Test_DeviceDiscovery_FindsHS3() { /* ... */ }
```

**Remover Skip de todos os 9 testes**:
1. Test_DeviceDiscovery_FindsHS3
2. Test_DeviceDiscovery_FindsMultipleDevices
3. Test_OpenDevice_WithRealHardware
4. Test_GetDeviceCapabilities_ReturnsCorrectVIDPID
5. Test_InitializationSequence_FollowsProtocol
6. Test_SendCommand_ReadWritePattern
7. Test_StressTest_1000Operations
8. Test_TimingValidation_BulkTransfer64Bytes

#### 4️⃣ Executar Testes com Hardware

```bash
# Executar TODOS os testes HS3:
dotnet test --filter FullyQualifiedName~HS3Protocol

# Executar teste específico:
dotnet test --filter FullyQualifiedName~Test_InitializationSequence_FollowsProtocol

# Executar com logging verboso:
dotnet test --filter FullyQualifiedName~HS3Protocol --logger "console;verbosity=detailed"
```

**Resultados esperados**:
```
✅ Test_DeviceDiscovery_FindsHS3 - PASSED
✅ Test_OpenDevice_WithRealHardware - PASSED
✅ Test_GetDeviceCapabilities_ReturnsCorrectVIDPID - PASSED
   VendorId: 0x0E36, ProductId: 0x0008
✅ Test_InitializationSequence_FollowsProtocol - PASSED
⚠️ Test_SendCommand_ReadWritePattern - PODE FALHAR (comandos hipotéticos)
```

#### 5️⃣ Validar Comandos Hipotéticos

Se `Test_SendCommand_ReadWritePattern` **FALHAR**:

1. **Analisar erro Win32**:
   ```csharp
   // Verificar LastWin32Error nos logs:
   ERROR_INVALID_PARAMETER (0x57) → Código IOCTL/comando inválido
   ERROR_GEN_FAILURE (0x1F)       → Dispositivo rejeitou comando
   ```

2. **Testar comandos um a um**:
   ```csharp
   // Trial-and-error seguro (não danifica hardware):
   for (uint cmd = 0x00000000; cmd <= 0x000000FF; cmd++)
   {
       var success = _protocol.ReadOperation(cmd, out var response);
       if (success && response.StatusByte != 0)
       {
           Console.WriteLine($"✅ Comando 0x{cmd:X8} respondeu: {response.StatusByte:X2}");
       }
   }
   ```

3. **Comparar com logs API Monitor**:
   - Ver PR #14 → `ANALISE_COMPLETA_HS3_API_MONITOR.md`
   - Procurar padrões `lpInBuffer` em `DeviceIoControl`

4. **Consultar firmware** (se disponível):
   ```bash
   # Descompactar hs3f12.hex com IDA Pro ou Ghidra
   # Procurar strings como "CMD_", "FREQ_", "AMP_"
   ```

#### 6️⃣ Implementar EmitFrequencyAsync

Após validar comandos corretos:

```csharp
// Em TiePieHS3Service.cs:
public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeV, TimeSpan duration)
{
    try
    {
        // 1. Configurar frequência (comando validado)
        var freqSuccess = _protocol.WriteOperation(
            HS3Commands.CMD_SET_FREQUENCY,  // <-- Validar código correto
            sizeof(double),
            out var freqResponse);

        if (!freqSuccess) return false;

        // 2. Configurar amplitude
        var ampSuccess = _protocol.WriteOperation(
            HS3Commands.CMD_SET_AMPLITUDE,
            sizeof(double),
            out var ampResponse);

        if (!ampSuccess) return false;

        // 3. Iniciar output
        var startSuccess = _protocol.ReadOperation(
            HS3Commands.CMD_START_OUTPUT,
            out var startResponse);

        if (!startSuccess) return false;

        // 4. Aguardar duração
        await Task.Delay(duration);

        // 5. Parar output
        var stopSuccess = _protocol.ReadOperation(
            HS3Commands.CMD_STOP_OUTPUT,
            out var stopResponse);

        return stopSuccess;
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "Erro ao emitir frequência");
        return false;
    }
}
```

---

## 🔍 Descoberta de IOCTL e Comandos

### Metodologia de Reverse-Engineering

#### 1. API Monitor (Já Realizado)

**Ferramenta**: [API Monitor v2](http://www.rohitab.com/apimonitor)

**Passos executados** (ver PR #14):
1. Capturar `DeviceIoControl` calls do Inergetix CoRe
2. Filtrar por VID_0E36&PID_0008
3. Identificar padrões:
   - IOCTL codes (0x222000, 0x222059, 0x222051, 0x22204E)
   - Tamanhos de buffer (4B input → 8B output para READ)
   - Sequência temporal (READ→WRITE sempre alternados)

**Resultados**: 2034 linhas de log, 33 ciclos READ→WRITE

#### 2. Firmware Reverse-Engineering (Opcional)

**Ficheiro**: `hs3f12.hex` (firmware TiePie HS3)

**Ferramentas**:
- **IDA Pro** (paid) ou **Ghidra** (free)
- **Binwalk** (análise de estrutura)

**Passos**:
```bash
# 1. Converter .hex para binário
objcopy -I ihex -O binary hs3f12.hex hs3f12.bin

# 2. Analisar strings
strings hs3f12.bin | grep -i "cmd\|freq\|amp\|trigger"

# 3. Abrir em Ghidra
# → Analyze → Search for strings → Procurar "command codes"
```

**Procurar por**:
- Tabelas de command handlers (switch/case)
- Strings de erro/debug ("Invalid command", "Frequency out of range")
- Constantes hexadecimais próximas de 0x40-0x43 (frequency commands)

#### 3. Trial-and-Error Seguro (Com Hardware)

**IMPORTANTE**: Comandos USB **não danificam hardware** (ao contrário de firmware flashing).

```csharp
// Função de brute-force segura:
public void DiscoverWorkingCommands()
{
    var workingCommands = new List<(uint code, byte response)>();

    // Testar range seguro (0x00 a 0xFF)
    for (uint cmd = 0x00; cmd <= 0xFF; cmd++)
    {
        try
        {
            // READ operation (mais seguro que WRITE)
            var success = _protocol.ReadOperation(cmd, out var response);

            if (success && response.StatusByte != 0)
            {
                workingCommands.Add((cmd, response.StatusByte));
                Console.WriteLine($"✅ 0x{cmd:X8} → Status: 0x{response.StatusByte:X2}");
            }
        }
        catch
        {
            // Ignorar erros (comando inválido é esperado)
        }

        // Delay para não sobrecarregar dispositivo
        Thread.Sleep(10);
    }

    // Analisar padrões nos comandos que funcionaram
    Console.WriteLine($"\n📊 Total de comandos válidos: {workingCommands.Count}");
}
```

**Padrões típicos**:
- Comandos de controle: `0x01-0x0F` (reset, init, shutdown)
- Comandos de config: `0x10-0x1F` (sample rate, buffer)
- Comandos de aquisição: `0x20-0x2F` (start, stop, read)
- Comandos de status: `0x30-0x3F` (get status, errors)
- **Comandos de frequência**: `0x40-0x4F` (set freq, amp, start/stop output)

#### 4. Comparação com LibTiePie SDK (Se Disponível)

**SDK oficial**: [LibTiePie](https://www.tiepie.com/libtiepie-sdk)

```c
// Exemplo de função LibTiePie:
TpDeviceHandle_t handle = LibTiePieScpOpen();
LibTiePieScpSetSampleFrequency(handle, 1000000); // 1 MHz

// Capturar com API Monitor:
// → Ver qual DeviceIoControl é chamado
// → Extrair IOCTL code e parâmetros
```

**Vantagem**: SDK oficial garante comandos corretos.

---

## 🛠️ Troubleshooting

### Erros Comuns de Win32

| Código | Nome                      | Causa Provável                           | Solução                                      |
|--------|---------------------------|------------------------------------------|----------------------------------------------|
| 0x02   | ERROR_FILE_NOT_FOUND      | Dispositivo não conectado/detectado      | Verificar Device Manager, reconectar USB     |
| 0x05   | ERROR_ACCESS_DENIED       | Permissões insuficientes                 | Executar como Administrador                  |
| 0x57   | ERROR_INVALID_PARAMETER   | IOCTL code ou buffer size incorreto      | Validar contra documentação/logs             |
| 0x1F   | ERROR_GEN_FAILURE         | Dispositivo rejeitou comando             | Comando inválido ou estado incorreto         |
| 0x79   | ERROR_SEM_TIMEOUT         | Timeout em DeviceIoControl               | Cabo defeituoso, hub USB, aumentar timeout   |
| 0xAA   | ERROR_BUSY                | Dispositivo ocupado (outra app)          | Fechar Inergetix CoRe, drivers TiePie        |

### Problemas de Descoberta USB

#### Dispositivo Não Encontrado

**Sintomas**:
```
FindHS3Devices() retorna lista vazia
```

**Diagnóstico**:
1. **Device Manager**:
   ```powershell
   devmgmt.msc
   # Procurar "Unknown device" ou "!" amarelo
   ```

2. **USBDeview** (ferramenta gratuita):
   ```powershell
   # Download: https://www.nirsoft.net/utils/usb_devices_view.html
   # Filtrar por VID=0E36
   ```

3. **Verificar GUID**:
   ```csharp
   // Testar com GUID genérico USB:
   var genericGuid = new Guid("{A5DCBF10-6530-11D2-901F-00C04FB951ED}");
   ```

**Soluções**:
- Reinstalar drivers TiePie
- Testar outra porta USB (evitar hubs)
- Verificar cabo USB (testar com outro dispositivo)
- Windows Update (drivers automáticos)

#### VID/PID Incorreto

**Sintomas**:
```
GetDeviceCapabilities retorna VID≠0x0E36 ou PID≠0x0008
```

**Diagnóstico**:
```csharp
Console.WriteLine($"VID: 0x{capabilities.VendorId:X4}");
Console.WriteLine($"PID: 0x{capabilities.ProductId:X4}");
```

**Soluções**:
- Confirmar modelo exato (HS3, não HS3 XMSG)
- Verificar firmware version (pode mudar VID/PID)
- Comparar com Device Manager

### Problemas de Comunicação

#### Timeout em DeviceIoControl

**Sintomas**:
```
DeviceIoControl retorna false, GetLastError() = 0x79 (ERROR_SEM_TIMEOUT)
```

**Diagnóstico**:
1. **Aumentar timeout**:
   ```csharp
   // Em CreateFile flags:
   FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL
   // E usar OVERLAPPED structure com timeout maior
   ```

2. **Verificar cabo**:
   - Testar com cabo USB curto (<1m)
   - Evitar extensões/hubs
   - Usar porta USB 2.0 nativa (não controlador USB 3.0)

3. **Monitor de performance**:
   ```powershell
   # Verificar taxa de transferência USB:
   Get-Counter "\USB\Bytes/sec"
   ```

**Soluções**:
- Trocar cabo USB
- Conectar direto à motherboard (porta traseira)
- Atualizar chipset drivers (USB controller)

#### READ→WRITE Pattern Quebrado

**Sintomas**:
```
Primeiro READ funciona, WRITE subsequente falha
```

**Diagnóstico**:
```csharp
// Adicionar logging detalhado:
_logger.LogDebug("READ: cmd=0x{Cmd:X8}, status=0x{Status:X2}",
    commandCode, readResponse.StatusByte);

// Verificar se statusByte indica "pronto para WRITE"
if (readResponse.StatusByte != 0x01)  // Exemplo: 0x01 = ready
{
    _logger.LogWarning("Dispositivo não está pronto para WRITE");
}
```

**Soluções**:
- Adicionar delay entre READ e WRITE (`Thread.Sleep(1)`)
- Verificar statusByte antes de WRITE
- Consultar logs API Monitor para padrão exato

### Problemas de Thread-Safety

#### Crashes Aleatórios em Multi-Threading

**Sintomas**:
```
AccessViolationException em DeviceIoControl
```

**Diagnóstico**:
```csharp
// Verificar se lock está sendo respeitado:
lock (_deviceLock)
{
    Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} entrou em critical section");
}
```

**Solução**:
- **SEMPRE** usar `lock(_deviceLock)` em TODAS as operações USB
- Não chamar métodos async dentro do lock (deadlock)
- Considerar `SemaphoreSlim` para operações async:
  ```csharp
  private readonly SemaphoreSlim _deviceSemaphore = new SemaphoreSlim(1, 1);

  public async Task<bool> ReadOperationAsync(uint commandCode)
  {
      await _deviceSemaphore.WaitAsync();
      try
      {
          // ... DeviceIoControl ...
      }
      finally
      {
          _deviceSemaphore.Release();
      }
  }
  ```

### Logging e Diagnóstico

#### Ativar Logging Verboso

**appsettings.json** (ou programaticamente):
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "BioDesk.Services.Hardware.TiePie": "Debug"  // <-- Protocol layer
    }
  }
}
```

**Logging detalhado em HS3DeviceProtocol**:
```csharp
_logger.LogDebug("DeviceIoControl: IOCTL=0x{IOCTL:X8}, In={InSize}B, Out={OutSize}B",
    dwIoControlCode, nInBufferSize, nOutBufferSize);

_logger.LogDebug("Win32 Error: {Error} ({Code})",
    Marshal.GetLastWin32Error(), new Win32Exception(Marshal.GetLastWin32Error()).Message);
```

#### Capturar Tráfego USB (Avançado)

**Ferramenta**: [USBPcap](https://desowin.org/usbpcap/) + Wireshark

```powershell
# 1. Instalar USBPcap
# 2. Capturar tráfego USB da porta do HS3
# 3. Abrir em Wireshark
# 4. Filtrar: usb.idVendor == 0x0e36 && usb.idProduct == 0x0008
# 5. Analisar URB_CONTROL (IOCTL) e URB_BULK (dados)
```

---

## 📚 Referências

### Documentação Interna

1. **README.md** - Secção "🔌 Protocolo USB TiePie HS3"
2. **PR #14** - Complete API Monitor analysis for TiePie HS3 USB protocol
   - `ANALISE_COMPLETA_HS3_API_MONITOR.md` (análise detalhada)
   - `DESCOBERTAS_PROTOCOLO_HS3_DEVICEIOCONTROL.md` (IOCTL codes)
   - `ESTRUTURAS_DADOS_HS3_DETALHADAS.md` (data structures)
   - `IMPLEMENTACAO_HS3_USB_CSHARP.md` (guia implementação C#)
   - `SUMARIO_PROTOCOLO_HS3_USB.md` (resumo executivo)
   - `HS3Protocol.cs` + `HS3DeviceProtocol.cs` (implementação inicial - substituída)

### Source Code

- `src/BioDesk.Services/Hardware/TiePie/Protocol/HS3Protocol.cs`
- `src/BioDesk.Services/Hardware/TiePie/Protocol/HS3DeviceDiscovery.cs`
- `src/BioDesk.Services/Hardware/TiePie/Protocol/HS3DeviceProtocol.cs`
- `src/BioDesk.Services/Hardware/TiePie/TiePieHS3Service.cs`
- `src/BioDesk.Tests/Hardware/TiePie/Protocol/HS3ProtocolTests.cs`

### Documentação Externa

1. **TiePie Engineering**
   - [Site oficial](https://www.tiepie.com/)
   - [LibTiePie SDK](https://www.tiepie.com/libtiepie-sdk)
   - [HS3 Product Page](https://www.tiepie.com/hs3)

2. **Win32 API**
   - [CreateFile documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)
   - [DeviceIoControl documentation](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)
   - [SetupDi API documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/setupdi)

3. **USB Protocol**
   - [USB.org specifications](https://www.usb.org/documents)
   - [USB in a NutShell](https://www.beyondlogic.org/usbnutshell/usb1.shtml)

4. **Reverse-Engineering Tools**
   - [API Monitor](http://www.rohitab.com/apimonitor)
   - [Ghidra](https://ghidra-sre.org/)
   - [USBPcap](https://desowin.org/usbpcap/)
   - [USBDeview](https://www.nirsoft.net/utils/usb_devices_view.html)

### Contactos Técnicos

- **BioDeskPro2 Developer**: Nuno Correia (NunoCorreia78)
- **TiePie Support**: support@tiepie.com
- **GitHub Issues**: https://github.com/NunoCorreia78/BioDeskPRO2.0/issues

---

## 📝 Changelog

### v1.0 (20/10/2025)
- ✅ Implementação completa protocol layer (3 classes)
- ✅ 9 testes de integração prontos (skipped sem hardware)
- ✅ TiePieHS3Service integrado com USB protocol
- ✅ Documentação completa troubleshooting + descoberta
- ⚠️ HS3Commands marcados como hipotéticos (pending validação)

---

**Última atualização**: 20 de outubro de 2025
**Status**: ✅ Pronto para validação com hardware físico
**Próximo passo**: Conectar TiePie HS3 e executar testes
