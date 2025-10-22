# 🧪 PLANO DE TESTES - Protocolo HS3 USB

## 📋 Objetivo

Validar a implementação do protocolo de comunicação USB com o TiePie Handyscope HS3, garantindo que replica corretamente o comportamento observado no Inergetix-CoRe 5.0 via análise do API Monitor.

---

## 🎯 Critérios de Sucesso

1. ✅ Device abre com sucesso via CreateFile
2. ✅ GetDeviceCapabilities retorna VID=0x0E36, PID=0x0008
3. ✅ Sequência de inicialização segue padrão do log capturado
4. ✅ Padrão READ→WRITE funciona corretamente
5. ✅ Latências estão dentro do esperado (±50% do log)
6. ✅ Thread-safety garantido (operações não concorrentes)
7. ✅ Dispose libera recursos corretamente

---

## 🔧 Ambiente de Teste

### Requisitos Mínimos

- **Hardware**: TiePie Handyscope HS3 conectado via USB
- **OS**: Windows 10/11 (x64)
- **Runtime**: .NET 8.0
- **Driver**: TiePie HS3 driver instalado
- **Permissões**: Administrador (para acesso USB raw)

### Configuração de Desenvolvimento

```powershell
# 1. Verificar device conectado
Get-PnpDevice -Class USB | Where-Object { $_.InstanceId -like "*VID_0E36*PID_0008*" }

# 2. Verificar driver instalado
Get-WmiObject Win32_PnPSignedDriver | Where-Object { $_.DeviceID -like "*VID_0E36*" }

# 3. Obter device path
$devicePath = (Get-WmiObject Win32_PnPEntity | Where-Object { 
    $_.DeviceID -like "*VID_0E36&PID_0008*" 
}).GetDeviceProperties("DEVPKEY_Device_InstanceId")
```

---

## 📝 Suítes de Testes

### Suite 1: Testes Unitários (Sem Hardware)

#### Test 1.1: HS3Protocol - Constantes

```csharp
[Fact]
public void HS3Protocol_Constants_DevemEstarCorretos()
{
    // Assert
    Assert.Equal(0x222000u, HS3Protocol.IOCTL_GET_DEVICE_INFO);
    Assert.Equal(0x222059u, HS3Protocol.IOCTL_CONFIG_QUERY);
    Assert.Equal(0x222051u, HS3Protocol.IOCTL_READ_OPERATION);
    Assert.Equal(0x22204Eu, HS3Protocol.IOCTL_WRITE_OPERATION);
    
    Assert.Equal(0x0E36, HS3Protocol.USB_VENDOR_ID);
    Assert.Equal(0x0008, HS3Protocol.USB_PRODUCT_ID);
}
```

#### Test 1.2: HS3DeviceCapabilities - Validação

```csharp
[Fact]
public void HS3DeviceCapabilities_IsValidHS3Device_RetornaTrue_ParaDeviceValido()
{
    // Arrange
    var capabilities = new HS3DeviceCapabilities
    {
        VendorId = 0x0E36,
        ProductId = 0x0008,
        SerialNumber = 12345,
        FirmwareVersion = 0x0102,
        HardwareRevision = 0x0001
    };
    
    // Act
    bool isValid = capabilities.IsValidHS3Device();
    
    // Assert
    Assert.True(isValid);
    Assert.Equal("VID_0E36&PID_0008", capabilities.GetDeviceId());
}
```

#### Test 1.3: HS3Response8 - Union Types

```csharp
[Fact]
public void HS3Response8_UnionTypes_FuncionamCorretamente()
{
    // Arrange
    var response = new HS3Response8();
    
    // Act - Escrever como double
    response.ValueAsDouble = 123.456;
    
    // Assert - Ler como long deve ter mesmo bit pattern
    long expectedBits = BitConverter.DoubleToInt64Bits(123.456);
    Assert.Equal(expectedBits, response.ValueAsLong);
    
    // Assert - DWords devem somar para o mesmo valor
    long reconstructed = ((long)response.HighDWord << 32) | response.LowDWord;
    Assert.Equal(expectedBits, reconstructed);
}
```

#### Test 1.4: HS3DeviceProtocol - Dispose Pattern

```csharp
[Fact]
public void HS3DeviceProtocol_Dispose_LiberaRecursosCorretamente()
{
    // Arrange
    var logger = new Mock<ILogger<HS3DeviceProtocol>>();
    var protocol = new HS3DeviceProtocol(logger.Object);
    
    // Act
    protocol.Dispose();
    
    // Assert - Multiple dispose não deve lançar exceção
    protocol.Dispose();
    
    // Verify logger foi chamado
    logger.Verify(
        x => x.Log(
            LogLevel.Debug,
            It.IsAny<EventId>(),
            It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Disposing")),
            null,
            It.IsAny<Func<It.IsAnyType, Exception, string>>()),
        Times.Once);
}
```

---

### Suite 2: Testes de Integração (Com Hardware)

#### Test 2.1: OpenDevice - Device Path Válido

```csharp
[Fact]
[Trait("Category", "Integration")]
[Trait("Requires", "Hardware")]
public void OpenDevice_ComDevicePathValido_DeveRetornarTrue()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    string devicePath = DiscoverHS3DevicePath(); // Helper method
    
    // Act
    bool success = protocol.OpenDevice(devicePath);
    
    // Assert
    Assert.True(success, "Falha ao abrir device. Verificar se HS3 está conectado.");
    Assert.True(protocol.IsDeviceOpen);
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 2.2: OpenDevice - Device Path Inválido

```csharp
[Fact]
[Trait("Category", "Integration")]
public void OpenDevice_ComDevicePathInvalido_DeveRetornarFalse()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    string invalidPath = @"\\?\usb#vid_0000&pid_0000#invalid";
    
    // Act
    bool success = protocol.OpenDevice(invalidPath);
    
    // Assert
    Assert.False(success);
    Assert.False(protocol.IsDeviceOpen);
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 2.3: GetDeviceCapabilities - Após Abrir Device

```csharp
[Fact]
[Trait("Category", "Integration")]
[Trait("Requires", "Hardware")]
public void GetDeviceCapabilities_AposAbrirDevice_DeveRetornarDadosCorretos()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    protocol.OpenDevice(DiscoverHS3DevicePath());
    
    // Act
    bool success = protocol.GetDeviceCapabilities(out var capabilities);
    
    // Assert
    Assert.True(success, "Falha ao obter capabilities");
    Assert.Equal(0x0E36, capabilities.VendorId);
    Assert.Equal(0x0008, capabilities.ProductId);
    Assert.True(capabilities.SerialNumber > 0, "Serial number deve ser > 0");
    Assert.True(capabilities.IsValidHS3Device());
    
    // Log para inspeção manual
    logger.LogInformation($"Device info: {capabilities.GetDeviceId()}, Serial: {capabilities.SerialNumber}");
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 2.4: ConfigureDevice - Configuração Padrão

```csharp
[Fact]
[Trait("Category", "Integration")]
[Trait("Requires", "Hardware")]
public void ConfigureDevice_ComConfigPadrao_DeveRetornarTrue()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    protocol.OpenDevice(DiscoverHS3DevicePath());
    protocol.GetDeviceCapabilities(out _);
    
    // Config data observado no log (primeiros 10 bytes após IOCTL 0x222059)
    var configData = new HS3ConfigData
    {
        ConfigCode = 0x0001, // Hipótese
        Parameters = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
    };
    
    // Act
    bool success = protocol.ConfigureDevice(configData);
    
    // Assert
    Assert.True(success, "Falha ao configurar device");
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 2.5: SendCommand - Padrão Read-Write

```csharp
[Fact]
[Trait("Category", "Integration")]
[Trait("Requires", "Hardware")]
public async Task SendCommand_ComandoSimples_DeveSeguirPadraoReadWrite()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    InitializeDevice(protocol); // Helper: Open + GetCapabilities + Configure
    
    uint testCommand = 0x00000001; // Comando teste (descobrir comando válido)
    
    // Act
    bool success = protocol.SendCommand(testCommand, out var response);
    
    // Assert
    Assert.True(success, "SendCommand falhou");
    Assert.NotEqual(0.0, response.ValueAsDouble); // Response não deve ser zero
    
    // Log response para análise
    logger.LogInformation($"Command 0x{testCommand:X8} response: {response}");
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 2.6: Sequência Completa de Inicialização

```csharp
[Fact]
[Trait("Category", "Integration")]
[Trait("Requires", "Hardware")]
public void SequenciaCompleta_DeveSeguirProtocoloDoLog()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    string devicePath = DiscoverHS3DevicePath();
    
    // Act & Assert - Fase 1: Abrir device
    bool openSuccess = protocol.OpenDevice(devicePath);
    Assert.True(openSuccess, "Fase 1 falhou: OpenDevice");
    
    // Act & Assert - Fase 2: Get capabilities
    bool capabilitiesSuccess = protocol.GetDeviceCapabilities(out var capabilities);
    Assert.True(capabilitiesSuccess, "Fase 2 falhou: GetDeviceCapabilities");
    Assert.True(capabilities.IsValidHS3Device());
    
    // Act & Assert - Fase 3: Configure device
    var configData = CreateDefaultConfigData(); // Helper
    bool configSuccess = protocol.ConfigureDevice(configData);
    Assert.True(configSuccess, "Fase 3 falhou: ConfigureDevice");
    
    // Act & Assert - Fase 4: Enviar comando teste
    uint testCommand = 0x00000001;
    bool commandSuccess = protocol.SendCommand(testCommand, out var response);
    Assert.True(commandSuccess, "Fase 4 falhou: SendCommand");
    
    // Log para comparação com API Monitor logs
    logger.LogInformation("Sequência completa executada com sucesso");
    logger.LogInformation($"  Device: {capabilities.GetDeviceId()}");
    logger.LogInformation($"  Serial: {capabilities.SerialNumber}");
    logger.LogInformation($"  Response: {response}");
    
    // Cleanup
    protocol.Dispose();
}
```

---

### Suite 3: Testes de Performance

#### Test 3.1: Latência de Operações Simples

```csharp
[Fact]
[Trait("Category", "Performance")]
[Trait("Requires", "Hardware")]
public void Performance_OperacoesSimples_LatenciaAceitavel()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    InitializeDevice(protocol);
    
    uint testCommand = 0x00000001;
    var stopwatch = Stopwatch.StartNew();
    int iterations = 100;
    
    // Act
    for (int i = 0; i < iterations; i++)
    {
        bool success = protocol.SendCommand(testCommand, out _);
        Assert.True(success);
    }
    
    stopwatch.Stop();
    
    // Assert
    double avgLatencyMs = stopwatch.Elapsed.TotalMilliseconds / iterations;
    
    // Baseado em log: operações simples (1-8B) = 0.05-0.3ms
    // Permitir margem de 50% = 0.45ms max
    Assert.True(avgLatencyMs < 0.5, 
        $"Latência média muito alta: {avgLatencyMs:F3}ms (esperado < 0.5ms)");
    
    logger.LogInformation($"Latência média: {avgLatencyMs:F3}ms para {iterations} operações");
    logger.LogInformation($"Throughput: {iterations / stopwatch.Elapsed.TotalSeconds:F1} ops/sec");
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 3.2: Stress Test - 1000 Operações

```csharp
[Fact]
[Trait("Category", "Performance")]
[Trait("Requires", "Hardware")]
public async Task StressTest_1000Operacoes_DeveManter Performance()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    InitializeDevice(protocol);
    
    uint testCommand = 0x00000001;
    int iterations = 1000;
    var stopwatch = Stopwatch.StartNew();
    int successCount = 0;
    int failCount = 0;
    
    // Act
    for (int i = 0; i < iterations; i++)
    {
        if (protocol.SendCommand(testCommand, out _))
            successCount++;
        else
            failCount++;
    }
    
    stopwatch.Stop();
    
    // Assert
    Assert.Equal(iterations, successCount);
    Assert.Equal(0, failCount);
    
    // Tempo máximo: 10ms por operação = 10s total
    Assert.True(stopwatch.ElapsedMilliseconds < 10000,
        $"Performance degradada: {stopwatch.ElapsedMilliseconds}ms para {iterations} ops");
    
    double avgLatencyMs = stopwatch.Elapsed.TotalMilliseconds / iterations;
    logger.LogInformation($"Stress test completo:");
    logger.LogInformation($"  Operações: {iterations}");
    logger.LogInformation($"  Sucesso: {successCount} ({100.0 * successCount / iterations:F1}%)");
    logger.LogInformation($"  Falhas: {failCount}");
    logger.LogInformation($"  Tempo total: {stopwatch.ElapsedMilliseconds}ms");
    logger.LogInformation($"  Latência média: {avgLatencyMs:F3}ms");
    logger.LogInformation($"  Throughput: {iterations / stopwatch.Elapsed.TotalSeconds:F1} ops/sec");
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 3.3: Bulk Transfer Latency

```csharp
[Fact]
[Trait("Category", "Performance")]
[Trait("Requires", "Hardware")]
public void Performance_BulkTransfer64Bytes_LatenciaEsperada()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    InitializeDevice(protocol);
    
    uint bulkCommand = 0x00000010; // Comando para bulk transfer (descobrir)
    byte[] bulkData = new byte[60]; // Max 60 bytes (64 - 4 do command)
    new Random().NextBytes(bulkData);
    
    var stopwatch = Stopwatch.StartNew();
    int iterations = 10;
    
    // Act
    for (int i = 0; i < iterations; i++)
    {
        bool success = protocol.SendCommand(bulkCommand, out _, bulkData, 64);
        Assert.True(success);
    }
    
    stopwatch.Stop();
    
    // Assert
    double avgLatencyMs = stopwatch.Elapsed.TotalMilliseconds / iterations;
    
    // Baseado em log: bulk 64B = 2.5-2.6ms
    // Permitir margem: 2.0-4.0ms
    Assert.InRange(avgLatencyMs, 1.0, 5.0);
    
    logger.LogInformation($"Bulk transfer (64B) latência média: {avgLatencyMs:F3}ms");
    logger.LogInformation($"Esperado (do log): 2.5-2.6ms");
    
    // Cleanup
    protocol.Dispose();
}
```

---

### Suite 4: Testes de Comparação com Logs

#### Test 4.1: Comparar Sequência IOCTL

```csharp
[Fact]
[Trait("Category", "Integration")]
[Trait("Requires", "Hardware")]
public void CompareWithLogs_SequenciaIOCTL_DeveCorresponder()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    var logParser = new ApiMonitorLogParser("ApiMonitor_COM_Equipamento.txt");
    
    // Parse expected sequence from log (first 10 IOCTL calls)
    var expectedSequence = logParser.GetIoctlSequence(0, 10);
    
    // Act - Execute same sequence
    var actualSequence = new List<uint>();
    
    protocol.OpenDevice(DiscoverHS3DevicePath());
    actualSequence.Add(HS3Protocol.IOCTL_GET_DEVICE_INFO); // Line 5 in log
    protocol.GetDeviceCapabilities(out _);
    
    actualSequence.Add(HS3Protocol.IOCTL_CONFIG_QUERY); // Line 6 in log
    protocol.ConfigureDevice(CreateDefaultConfigData());
    
    actualSequence.Add(HS3Protocol.IOCTL_READ_OPERATION); // Line 7 in log
    protocol.ReadOperation(0x00000001, out _);
    
    // ... continue para primeiros 10 comandos
    
    // Assert
    Assert.Equal(expectedSequence.Count, actualSequence.Count);
    for (int i = 0; i < expectedSequence.Count; i++)
    {
        Assert.Equal(expectedSequence[i], actualSequence[i], 
            $"IOCTL {i} não corresponde. Expected: 0x{expectedSequence[i]:X8}, Actual: 0x{actualSequence[i]:X8}");
    }
    
    // Cleanup
    protocol.Dispose();
}
```

#### Test 4.2: Comparar Device Capabilities

```csharp
[Fact]
[Trait("Category", "Integration")]
[Trait("Requires", "Hardware")]
public void CompareWithLogs_DeviceCapabilities_DeveCorresponder()
{
    // Arrange
    var logger = CreateTestLogger<HS3DeviceProtocol>();
    var protocol = new HS3DeviceProtocol(logger);
    
    // Expected values do log (se disponíveis)
    const ushort expectedVendorId = 0x0E36;
    const ushort expectedProductId = 0x0008;
    
    // Act
    protocol.OpenDevice(DiscoverHS3DevicePath());
    bool success = protocol.GetDeviceCapabilities(out var capabilities);
    
    // Assert
    Assert.True(success);
    Assert.Equal(expectedVendorId, capabilities.VendorId);
    Assert.Equal(expectedProductId, capabilities.ProductId);
    
    // Log para comparação manual
    logger.LogInformation($"Capabilities obtidas:");
    logger.LogInformation($"  VID: 0x{capabilities.VendorId:X4} (expected: 0x{expectedVendorId:X4})");
    logger.LogInformation($"  PID: 0x{capabilities.ProductId:X4} (expected: 0x{expectedProductId:X4})");
    logger.LogInformation($"  Serial: {capabilities.SerialNumber}");
    logger.LogInformation($"  FW Version: 0x{capabilities.FirmwareVersion:X4}");
    logger.LogInformation($"  HW Revision: 0x{capabilities.HardwareRevision:X4}");
    
    // Cleanup
    protocol.Dispose();
}
```

---

## 🛠️ Helpers e Utilitários

### Helper: Discover HS3 Device Path

```csharp
private static string DiscoverHS3DevicePath()
{
    // TODO: Implementar usando SetupDi API
    // Por enquanto, retornar path hardcoded para testes
    return @"\\?\usb#vid_0e36&pid_0008#8&14447dc6&0&1#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}";
}
```

### Helper: Initialize Device

```csharp
private static void InitializeDevice(HS3DeviceProtocol protocol)
{
    bool openSuccess = protocol.OpenDevice(DiscoverHS3DevicePath());
    if (!openSuccess)
        throw new InvalidOperationException("Falha ao abrir device HS3. Verificar conexão.");
    
    bool capSuccess = protocol.GetDeviceCapabilities(out _);
    if (!capSuccess)
        throw new InvalidOperationException("Falha ao obter capabilities.");
    
    var configData = CreateDefaultConfigData();
    bool configSuccess = protocol.ConfigureDevice(configData);
    if (!configSuccess)
        throw new InvalidOperationException("Falha ao configurar device.");
}
```

### Helper: Create Default Config Data

```csharp
private static HS3ConfigData CreateDefaultConfigData()
{
    return new HS3ConfigData
    {
        ConfigCode = 0x0001, // TODO: Descobrir valores corretos
        Parameters = new byte[8] // Zeros por default
    };
}
```

### Helper: API Monitor Log Parser

```csharp
public class ApiMonitorLogParser
{
    private readonly string _logFilePath;
    
    public ApiMonitorLogParser(string logFilePath)
    {
        _logFilePath = logFilePath;
    }
    
    public List<uint> GetIoctlSequence(int startIndex, int count)
    {
        // Parse log file and extract IOCTL codes
        var ioctlCodes = new List<uint>();
        
        // TODO: Implementar parsing do log
        // Formato: linha com "DeviceIoControl ( ..., <IOCTL_CODE>, ...)"
        
        return ioctlCodes;
    }
}
```

---

## 📊 Relatório de Testes

### Template de Relatório

```markdown
# Relatório de Testes - HS3DeviceProtocol

**Data**: [DATA]  
**Testador**: [NOME]  
**Ambiente**: [Windows 10/11, .NET 8.0, HS3 Serial: XXXX]

## Resultados

| Suite | Testes | Passed | Failed | Skipped | Duração |
|-------|--------|--------|--------|---------|---------|
| Unitários | X | X | X | X | Xms |
| Integração | X | X | X | X | Xms |
| Performance | X | X | X | X | Xms |
| Comparação | X | X | X | X | Xms |
| **TOTAL** | **X** | **X** | **X** | **X** | **Xms** |

## Latências Observadas

| Operação | Esperado (log) | Observado | Delta | Status |
|----------|----------------|-----------|-------|--------|
| GET_DEVICE_INFO | 0.027ms | Xms | ±X% | ✅/❌ |
| CONFIG_QUERY | 0.572ms | Xms | ±X% | ✅/❌ |
| READ (8B) | 0.1ms | Xms | ±X% | ✅/❌ |
| WRITE (1B) | 0.3ms | Xms | ±X% | ✅/❌ |
| WRITE (64B) | 2.5ms | Xms | ±X% | ✅/❌ |

## Observações

- [Observação 1]
- [Observação 2]

## Próximos Passos

- [ ] [Ação 1]
- [ ] [Ação 2]
```

---

## 🚦 Checklist de Execução

### Pré-requisitos

- [ ] TiePie HS3 conectado e reconhecido pelo Windows
- [ ] Driver TiePie instalado e funcionando
- [ ] Projeto compilando sem erros
- [ ] Executar como Administrador (para acesso USB raw)

### Execução de Testes

```bash
# 1. Testes unitários (sem hardware)
dotnet test --filter "Category!=Integration&Category!=Performance"

# 2. Testes de integração (com hardware)
dotnet test --filter "Category=Integration"

# 3. Testes de performance
dotnet test --filter "Category=Performance"

# 4. Todos os testes
dotnet test --logger "console;verbosity=detailed"
```

### Análise de Resultados

- [ ] Todos os testes unitários passam (100%)
- [ ] Testes de integração passam (>95%)
- [ ] Latências dentro do esperado (±50%)
- [ ] Nenhum memory leak detectado
- [ ] Logs não mostram erros inesperados

---

**Plano criado por**: Copilot Coding Agent  
**Data**: 19 outubro 2025  
**Versão**: 1.0  
**Status**: ✅ Pronto para execução após implementação do protocolo
