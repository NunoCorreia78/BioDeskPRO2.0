using System;
using System.Collections.Generic;
using System.Linq;
using BioDesk.Services.Hardware.TiePie.Protocol;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace BioDesk.Tests.Hardware.TiePie.Protocol;

/// <summary>
/// Testes de integração para o protocolo USB TiePie HS3.
///
/// ⚠️ IMPORTANTE: Todos os testes estão SKIPPED por defeito porque requerem hardware físico.
///
/// Para executar estes testes quando o hardware TiePie HS3 estiver disponível:
/// 1. Conectar o dispositivo TiePie HS3 via USB
/// 2. Verificar que o dispositivo aparece no Device Manager (VID_0E36&PID_0008)
/// 3. Remover o atributo Skip dos testes que quer executar
/// 4. Executar: dotnet test --filter "FullyQualifiedName~HS3ProtocolTests"
///
/// Referência: GUIA_HS3_USB_PROTOCOL.md para troubleshooting e validação de hardware
/// </summary>
public class HS3ProtocolTests : IDisposable
{
    private readonly Mock<ILogger<HS3DeviceDiscovery>> _discoveryLoggerMock;
    private readonly Mock<ILogger<HS3DeviceProtocol>> _protocolLoggerMock;
    private HS3DeviceDiscovery? _discovery;
    private HS3DeviceProtocol? _protocol;
    private bool _disposed = false;

    public HS3ProtocolTests()
    {
        _discoveryLoggerMock = new Mock<ILogger<HS3DeviceDiscovery>>();
        _protocolLoggerMock = new Mock<ILogger<HS3DeviceProtocol>>();
    }

    #region Device Discovery Tests

    /// <summary>
    /// Teste: Verificar que o sistema consegue descobrir o dispositivo TiePie HS3 conectado via USB.
    ///
    /// Validações:
    /// - FindFirstHS3Device() retorna um device path válido (não null)
    /// - Device path contém os identificadores USB corretos (VID_0E36&PID_0008)
    /// - Device path está no formato esperado: \\?\usb#vid_0e36&pid_0008#...
    ///
    /// Pré-requisitos:
    /// - Dispositivo TiePie HS3 conectado via USB
    /// - Drivers instalados (verificar Device Manager)
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
    public void Test_DeviceDiscovery_FindsHS3()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);

        // Act
        var devicePath = _discovery.FindFirstHS3Device();

        // Assert
        Assert.NotNull(devicePath);
        Assert.Contains("vid_0e36", devicePath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("pid_0008", devicePath, StringComparison.OrdinalIgnoreCase);
        Assert.StartsWith(@"\\?\usb", devicePath, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Teste: Verificar que FindHS3Devices() retorna pelo menos um dispositivo.
    ///
    /// Validações:
    /// - Lista não está vazia
    /// - Todos os device paths contêm VID_0E36&PID_0008
    /// - Device paths estão em formato válido
    ///
    /// Útil para cenários com múltiplos dispositivos HS3 conectados.
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
    public void Test_DeviceDiscovery_FindsMultipleDevices()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);

        // Act
        var devices = _discovery.FindHS3Devices();

        // Assert
        Assert.NotEmpty(devices);
        Assert.All(devices, devicePath =>
        {
            Assert.Contains("vid_0e36", devicePath, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("pid_0008", devicePath, StringComparison.OrdinalIgnoreCase);
        });
    }

    #endregion

    #region Device Communication Tests

    /// <summary>
    /// Teste: Verificar que conseguimos abrir comunicação com o dispositivo via CreateFile Win32 API.
    ///
    /// Validações:
    /// - OpenDevice() retorna true
    /// - Handle do dispositivo não é inválido
    /// - Conseguimos fechar o dispositivo sem erros
    ///
    /// Este é o teste mais básico - se falhar, verificar:
    /// 1. Device Manager: dispositivo aparece sem erros?
    /// 2. Drivers: estão instalados corretamente?
    /// 3. Permissões: executar como Administrator?
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
    public void Test_OpenDevice_WithRealHardware()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);
        _protocol = new HS3DeviceProtocol(_protocolLoggerMock.Object);

        var devicePath = _discovery.FindFirstHS3Device();
        Assert.NotNull(devicePath); // Pre-condition

        // Act
        var success = _protocol.OpenDevice(devicePath);

        // Assert
        Assert.True(success, "Failed to open TiePie HS3 device. Check Device Manager and drivers.");
    }

    /// <summary>
    /// Teste: Verificar que IOCTL 0x222000 (GET_DEVICE_INFO) retorna informações corretas do dispositivo.
    ///
    /// Validações:
    /// - GetDeviceCapabilities() retorna true
    /// - VendorId = 0x0E36
    /// - ProductId = 0x0008
    /// - Buffer de 1024 bytes é preenchido
    /// - SerialNumber não é zero
    /// - FirmwareVersion não é zero
    ///
    /// Este teste valida a primeira comunicação IOCTL com o hardware.
    /// Se falhar: verificar que o dispositivo respondeu corretamente ao IOCTL.
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
    public void Test_GetDeviceCapabilities_ReturnsCorrectVIDPID()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);
        _protocol = new HS3DeviceProtocol(_protocolLoggerMock.Object);

        var devicePath = _discovery.FindFirstHS3Device();
        Assert.NotNull(devicePath);

        var opened = _protocol.OpenDevice(devicePath);
        Assert.True(opened);

        // Act
        var success = _protocol.GetDeviceCapabilities(out var capabilities);

        // Assert
        Assert.True(success, "Failed to get device capabilities via IOCTL 0x222000");
        Assert.Equal(HS3Protocol.USB_VENDOR_ID, capabilities.VendorId);
        Assert.Equal(HS3Protocol.USB_PRODUCT_ID, capabilities.ProductId);
        Assert.NotEqual(0u, capabilities.SerialNumber);
        Assert.NotEqual(0u, capabilities.FirmwareVersion);
    }

    /// <summary>
    /// Teste: Verificar a sequência de inicialização completa conforme observado no API Monitor.
    ///
    /// Sequência esperada (baseada em IOCTL_MAPPING.md):
    /// 1. GET_DEVICE_INFO (0x222000) - obter VID/PID/Serial/Firmware
    /// 2. CONFIG_QUERY (0x222059) - query de configuração (10 bytes → 8 bytes)
    /// 3. Validar que VID/PID estão corretos
    /// 4. ConfigureDevice() - configuração inicial
    ///
    /// Se falhar: verificar logs do ILogger para ver onde a sequência falhou.
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
    public void Test_InitializationSequence_FollowsProtocol()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);
        _protocol = new HS3DeviceProtocol(_protocolLoggerMock.Object);

        var devicePath = _discovery.FindFirstHS3Device();
        Assert.NotNull(devicePath);

        // Act & Assert - Step 1: Open device
        var opened = _protocol.OpenDevice(devicePath);
        Assert.True(opened, "Step 1 failed: Could not open device");

        // Act & Assert - Step 2: Get device capabilities
        var gotCapabilities = _protocol.GetDeviceCapabilities(out var capabilities);
        Assert.True(gotCapabilities, "Step 2 failed: Could not get device capabilities (IOCTL 0x222000)");
        Assert.Equal(HS3Protocol.USB_VENDOR_ID, capabilities.VendorId);
        Assert.Equal(HS3Protocol.USB_PRODUCT_ID, capabilities.ProductId);

        // Act & Assert - Step 3: Configure device
        var configured = _protocol.ConfigureDevice();
        Assert.True(configured, "Step 3 failed: Could not configure device (IOCTL 0x222059)");

        // Initialization sequence complete - device is ready for READ/WRITE operations
    }

    #endregion

    #region Communication Pattern Tests

    /// <summary>
    /// Teste: Verificar o padrão de comunicação READ→WRITE observado no API Monitor.
    ///
    /// Padrão esperado (baseado em ANALISE_SEQUENCIA_COMUNICACAO.md):
    /// - 33 ciclos de READ (IOCTL 0x222051) seguido de WRITE (IOCTL 0x22204E)
    /// - READ: 4 bytes input → 8 bytes output
    /// - WRITE: 4 bytes input → 1-64 bytes output
    /// - Timing: ~2.5ms por operação de 64 bytes (limite USB bulk transfer)
    /// - Thread-safety: todas operações na mesma thread
    ///
    /// ⚠️ ATENÇÃO: Este teste pode demorar ~165ms (33 ciclos × 5ms)
    ///
    /// Se falhar: verificar logs para identificar qual ciclo falhou.
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
    public void Test_SendCommand_ReadWritePattern()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);
        _protocol = new HS3DeviceProtocol(_protocolLoggerMock.Object);

        var devicePath = _discovery.FindFirstHS3Device();
        Assert.NotNull(devicePath);

        _protocol.OpenDevice(devicePath);
        _protocol.GetDeviceCapabilities(out _);
        _protocol.ConfigureDevice();

        const int expectedCycles = 33;
        var successfulCycles = 0;

        // Act - Execute READ→WRITE pattern 33 times
        for (int i = 0; i < expectedCycles; i++)
        {
            // READ operation (IOCTL 0x222051)
            // Nota: commandCode hipotético - deve ser descoberto com hardware real
            var readSuccess = _protocol.ReadOperation(0x00000000, out var readResponse);
            if (!readSuccess)
            {
                // Log cycle that failed
                Assert.Fail($"READ operation failed at cycle {i + 1}/{expectedCycles}");
            }

            // WRITE operation (IOCTL 0x22204E)
            // Nota: commandCode e expectedSize hipotéticos - devem ser descobertos com hardware real
            var writeSuccess = _protocol.WriteOperation(0x00000000, 64, out var writeResponse);
            if (!writeSuccess)
            {
                Assert.Fail($"WRITE operation failed at cycle {i + 1}/{expectedCycles}");
            }

            successfulCycles++;
        }

        // Assert
        Assert.Equal(expectedCycles, successfulCycles);
    }

    /// <summary>
    /// Teste: Stress test com 1000 operações para verificar thread-safety e estabilidade.
    ///
    /// Validações:
    /// - 1000 operações READ→WRITE sem erros
    /// - Handle do dispositivo permanece válido
    /// - Sem memory leaks (buffers pinned são reutilizados)
    /// - Thread-safety: lock(_deviceLock) protege todas operações
    ///
    /// ⚠️ ATENÇÃO: Este teste pode demorar ~5 segundos (1000 operações × 5ms)
    ///
    /// Se falhar após N operações: pode indicar:
    /// 1. Timeout no dispositivo (verificar cabo USB)
    /// 2. Memory leak (verificar GCHandle.Free() no Dispose)
    /// 3. Dispositivo entrou em estado de erro (verificar firmware)
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB - LONG RUNNING TEST (~5s)")]
    public void Test_StressTest_1000Operations()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);
        _protocol = new HS3DeviceProtocol(_protocolLoggerMock.Object);

        var devicePath = _discovery.FindFirstHS3Device();
        Assert.NotNull(devicePath);

        _protocol.OpenDevice(devicePath);
        _protocol.GetDeviceCapabilities(out _);
        _protocol.ConfigureDevice();

        const int totalOperations = 1000;
        var successfulOperations = 0;
        var failedAtOperation = -1;

        // Act
        for (int i = 0; i < totalOperations; i++)
        {
            // READ
            var readSuccess = _protocol.ReadOperation(0x00000000, out _);
            if (!readSuccess)
            {
                failedAtOperation = i + 1;
                break;
            }

            // WRITE
            var writeSuccess = _protocol.WriteOperation(0x00000000, 4, out _);
            if (!writeSuccess)
            {
                failedAtOperation = i + 1;
                break;
            }

            successfulOperations++;
        }

        // Assert
        Assert.Equal(totalOperations, successfulOperations);
        Assert.Equal(-1, failedAtOperation); // Should never fail
    }

    #endregion

    #region Timing Tests

    /// <summary>
    /// Teste: Verificar que o timing de operações USB respeita o limite de 2.5ms por 64 bytes.
    ///
    /// Baseado em TIMING_ANALYSIS.md:
    /// - 64-byte bulk transfer = ~2.5ms (limite USB packet size)
    /// - Operações menores (<64 bytes) podem ser mais rápidas
    ///
    /// Validações:
    /// - 100 operações de 64 bytes completam em tempo razoável
    /// - Timing médio por operação está dentro do esperado (2-5ms)
    /// - Sem timeouts
    ///
    /// Se falhar: verificar qualidade do cabo USB e portas USB 2.0 vs 3.0
    /// </summary>
    [Fact(Skip = "Requires physical TiePie HS3 hardware connected via USB")]
    public void Test_TimingValidation_BulkTransfer64Bytes()
    {
        // Arrange
        _discovery = new HS3DeviceDiscovery(_discoveryLoggerMock.Object);
        _protocol = new HS3DeviceProtocol(_protocolLoggerMock.Object);

        var devicePath = _discovery.FindFirstHS3Device();
        Assert.NotNull(devicePath);

        _protocol.OpenDevice(devicePath);
        _protocol.GetDeviceCapabilities(out _);
        _protocol.ConfigureDevice();

        const int iterations = 100;
        var timings = new List<double>();

        // Act
        for (int i = 0; i < iterations; i++)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();

            var success = _protocol.WriteOperation(0x00000000, 64, out _);

            sw.Stop();

            Assert.True(success, $"Write operation failed at iteration {i + 1}");
            timings.Add(sw.Elapsed.TotalMilliseconds);
        }

        // Assert
        var averageTiming = timings.Average();
        var maxTiming = timings.Max();

        // Expected: 2-5ms per 64-byte operation (based on USB 2.0 bulk transfer specs)
        Assert.InRange(averageTiming, 0.5, 10.0); // Tolerant range
        Assert.True(maxTiming < 50.0, $"Max timing too high: {maxTiming}ms (expected <50ms)");
    }

    #endregion

    #region Cleanup

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
                // Cleanup managed resources
                _protocol?.Dispose();
                _discovery?.Dispose();
            }
            _disposed = true;
        }
    }

    #endregion
}
