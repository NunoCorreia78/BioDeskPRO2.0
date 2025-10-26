using System;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Hardware.TiePie.Protocol;
using BioDesk.Services.Hardware.TiePie.FunctionGenerator;
using BioDesk.Services.Hardware.TiePie.Firmware;
using BioDesk.Services.Hardware.TiePie.Discovery;

namespace BioDesk.Tests.Hardware.TiePie;

/// <summary>
/// Testes de integração do protocolo TiePie HS3
///
/// ATENÇÃO: Estes testes requerem hardware HS3 físico conectado!
/// - Conectar HS3 via USB antes de executar
/// - Verificar device path em Device Manager
/// - TER osciloscópio/multímetro pronto para validação física
/// - COMEÇAR com tensões baixas (< 2V)
///
/// Para pular testes quando hardware não disponível, usar:
/// dotnet test --filter "Category!=RequiresHardware"
/// </summary>
[Collection("HS3 Hardware Tests")]
public class HS3ProtocolTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly ILogger<HS3DeviceProtocol> _protocolLogger;
    private readonly ILogger<HS3FunctionGenerator> _generatorLogger;
    private readonly ILogger<HS3FirmwareLoader> _firmwareLogger;
    private readonly ILogger<HS3CommandDiscovery> _discoveryLogger;

    // Device path do HS3 - AJUSTAR para teu sistema!
    // Descobrir com: Device Manager → TiePie HS3 → Properties → Details → Device Path
    private const string TEST_DEVICE_PATH =
        @"\\?\usb#vid_0e36&pid_0008#8&14447dc6&0&1#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}";

    public HS3ProtocolTests(ITestOutputHelper output)
    {
        _output = output;

        // Setup loggers que escrevem para Xunit output
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddProvider(new XunitLoggerProvider(output));
            builder.SetMinimumLevel(LogLevel.Trace);
        });

        _protocolLogger = loggerFactory.CreateLogger<HS3DeviceProtocol>();
        _generatorLogger = loggerFactory.CreateLogger<HS3FunctionGenerator>();
        _firmwareLogger = loggerFactory.CreateLogger<HS3FirmwareLoader>();
        _discoveryLogger = loggerFactory.CreateLogger<HS3CommandDiscovery>();
    }

    #region Basic Protocol Tests

    [Fact]
    [Trait("Category", "RequiresHardware")]
    public void OpenDevice_ComDevicePathValido_DeveRetornarTrue()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);

        // Act
        bool success = protocol.OpenDevice(TEST_DEVICE_PATH);

        // Assert
        Assert.True(success, "Falha ao abrir device. Verificar device path e conexão USB.");
        Assert.True(protocol.IsDeviceOpen(), "Device deveria estar marcado como aberto");

        // Cleanup
        protocol.CloseDevice();
    }

    [Fact]
    [Trait("Category", "RequiresHardware")]
    public void GetDeviceCapabilities_AposAbrirDevice_DeveRetornarDadosValidos()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);

        // Act
        bool success = protocol.GetDeviceCapabilities(out HS3DeviceCapabilities caps);

        // Assert
        Assert.True(success, "GET_DEVICE_CAPABILITIES falhou");
        Assert.Equal((ushort)0x0E36, caps.VendorId); // TiePie Engineering
        Assert.Equal((ushort)0x0008, caps.ProductId); // Handyscope HS3
        Assert.NotEqual(0u, caps.SerialNumber); // Serial não deve ser zero

        _output.WriteLine($"Device Capabilities: {caps}");

        // Cleanup
        protocol.CloseDevice();
    }

    [Fact]
    [Trait("Category", "RequiresHardware")]
    public void ConfigureDevice_AposGetCapabilities_DeveRetornarTrue()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);
        protocol.GetDeviceCapabilities(out _);

        // Act
        bool success = protocol.ConfigureDevice();

        // Assert
        Assert.True(success, "CONFIGURE_DEVICE falhou");

        // Cleanup
        protocol.CloseDevice();
    }

    [Fact]
    [Trait("Category", "RequiresHardware")]
    public void InitializationSequence_DeveSeguirProtocoloCorreto()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);

        // Act & Assert - Sequência completa conforme análise API Monitor

        // 1. Abrir device
        Assert.True(protocol.OpenDevice(TEST_DEVICE_PATH), "Fase 1: Abrir device falhou");

        // 2. Get capabilities (IOCTL 0x222000)
        Assert.True(protocol.GetDeviceCapabilities(out var caps), "Fase 2: GetCapabilities falhou");
        Assert.True(caps.IsValidHS3Device(), "Fase 2: Device não é HS3 válido");

        // 3. Configure device (IOCTL 0x222059)
        Assert.True(protocol.ConfigureDevice(), "Fase 3: ConfigureDevice falhou");

        // 4. Testar padrão READ→WRITE (observado 33× nos logs)
        for (int i = 0; i < 5; i++) // Testar 5 ciclos
        {
            uint testCommand = 0x00000001; // Comando hipotético
            bool readSuccess = protocol.ReadOperation(testCommand, out HS3Response8 readResp);
            Assert.True(readSuccess || i == 0, $"READ cycle {i} falhou");

            if (readSuccess)
            {
                bool writeSuccess = protocol.WriteOperation(testCommand, 8, out byte[] writeResp);
                Assert.True(writeSuccess, $"WRITE cycle {i} falhou");
            }
        }

        // Cleanup
        protocol.CloseDevice();
    }

    #endregion

    #region Command Discovery Tests

    [Fact]
    [Trait("Category", "RequiresHardware")]
    [Trait("Category", "Slow")] // Este teste pode demorar minutos
    public async Task DiscoverCommands_Range0x01_0xFF_DeveEncontrarComandosValidos()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);
        protocol.GetDeviceCapabilities(out _);
        protocol.ConfigureDevice();

        var discovery = new HS3CommandDiscovery(_discoveryLogger, protocol);

        // Act - Descobrir comandos no range 0x01-0xFF (255 comandos)
        var results = await discovery.DiscoverCommandRangeAsync(
            startCommand: 0x00000001,
            endCommand: 0x000000FF,
            delayMs: 50);

        // Assert
        Assert.NotEmpty(results); // Devem existir ALGUNS comandos válidos
        _output.WriteLine($"Comandos descobertos: {results.Count}/255");

        foreach (var result in results)
        {
            _output.WriteLine($"  {result}");
            _output.WriteLine($"    Função inferida: {discovery.InferCommandFunction(result.CommandCode)}");
        }

        // Exportar resultados para CSV
        string csvPath = $"hs3_commands_discovered_{DateTime.Now:yyyyMMdd_HHmmss}.csv";
        await discovery.ExportToCsvAsync(csvPath);
        _output.WriteLine($"Comandos exportados para: {csvPath}");

        // Cleanup
        protocol.CloseDevice();
    }

    #endregion

    #region Function Generator Tests

    [Fact]
    [Trait("Category", "RequiresHardware")]
    [Trait("Category", "Physical")] // Requer validação com osciloscópio
    public async Task SetFrequency_Com7_83Hz_DeveEmitirRessonanciaSchumann()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);
        protocol.GetDeviceCapabilities(out _);
        protocol.ConfigureDevice();

        var generator = new HS3FunctionGenerator(_generatorLogger, protocol);

        // Act
        bool success = await generator.SetFrequencyAsync(7.83);

        // Assert
        Assert.True(success, "SET_FREQUENCY falhou");

        // Validar read-back
        double readFreq = await generator.GetFrequencyAsync();
        Assert.InRange(readFreq, 7.82, 7.84); // Tolerância 0.01 Hz

        _output.WriteLine($"✅ Frequência definida e validada: {readFreq:F6} Hz");
        _output.WriteLine("📊 VALIDAÇÃO FÍSICA: Conectar osciloscópio ao BNC e confirmar 7.83 Hz");

        // Cleanup
        await generator.EmergencyStopAsync();
        protocol.CloseDevice();
    }

    [Fact]
    [Trait("Category", "RequiresHardware")]
    [Trait("Category", "Physical")]
    public async Task ConfigureAndStart_ComParametrosBase_DeveEmitirSinal()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);
        protocol.GetDeviceCapabilities(out _);
        protocol.ConfigureDevice();

        var generator = new HS3FunctionGenerator(_generatorLogger, protocol);

        // Act - Configuração segura para teste inicial
        bool success = await generator.ConfigureAndStartAsync(
            frequencyHz: 100.0,      // 100 Hz (frequência baixa, segura)
            amplitudeVpp: 1.0,       // 1 Vpp (amplitude baixa, segura)
            waveform: WaveformType.Sine); // Sine (suave)

        // Assert
        Assert.True(success, "ConfigureAndStart falhou");

        // Verificar estado
        var state = await generator.GetStateAsync();
        Assert.InRange(state.Frequency, 99.9, 100.1);
        Assert.InRange(state.Amplitude, 0.9, 1.1);
        Assert.Equal(WaveformType.Sine, state.Waveform);
        Assert.True(state.OutputEnabled);

        _output.WriteLine($"✅ Gerador configurado: {state}");
        _output.WriteLine("📊 VALIDAÇÃO FÍSICA:");
        _output.WriteLine("   - Osciloscópio: Confirmar 100 Hz sine wave");
        _output.WriteLine("   - Multímetro AC: Confirmar ~0.35 Vrms (1 Vpp / 2.828)");

        // Manter ativo por 5 segundos para validação física
        _output.WriteLine("⏳ Emitindo por 5 segundos para validação...");
        await Task.Delay(5000);

        // Cleanup
        await generator.EmergencyStopAsync();
        protocol.CloseDevice();
    }

    [Fact]
    [Trait("Category", "RequiresHardware")]
    public async Task EmergencyStop_DeveDesligarSaidaImediatamente()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);
        protocol.GetDeviceCapabilities(out _);
        protocol.ConfigureDevice();

        var generator = new HS3FunctionGenerator(_generatorLogger, protocol);

        // Ligar output primeiro
        await generator.ConfigureAndStartAsync(100.0, 1.0);

        // Act - Emergency stop
        bool success = await generator.EmergencyStopAsync();

        // Assert
        Assert.True(success, "EMERGENCY_STOP falhou");

        // Verificar estado
        bool isOn = await generator.IsOutputEnabledAsync();
        Assert.False(isOn, "Output ainda está ON após emergency stop!");

        _output.WriteLine("✅ Emergency stop funcionou");

        // Cleanup
        protocol.CloseDevice();
    }

    #endregion

    #region Firmware Loader Tests

    [Fact]
    [Trait("Category", "RequiresHardware")]
    [Trait("Category", "Slow")]
    [Trait("Category", "Dangerous")] // Pode brick device se falhar!
    public async Task LoadFirmware_DeveEnviarhs3f12hex()
    {
        // ⚠️ ATENÇÃO: Este teste pode DANIFICAR dispositivo se firmware estiver corrupto!
        // EXECUTAR APENAS se tiveres firmware original backup

        if (!System.IO.File.Exists(@"C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\hs3f12.hex"))
        {
            _output.WriteLine("⚠️ Teste pulado: Firmware hs3f12.hex não encontrado");
            return;
        }

        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);
        protocol.GetDeviceCapabilities(out _);
        protocol.ConfigureDevice();

        var firmwareLoader = new HS3FirmwareLoader(_firmwareLogger, protocol);

        // Act
        var progress = new Progress<double>(p =>
        {
            if (p % 0.1 < 0.01) // Log a cada 10%
                _output.WriteLine($"📤 Upload firmware: {p * 100:F1}%");
        });

        bool success = await firmwareLoader.LoadFirmwareAsync(
            firmwarePath: null, // Auto-discover
            progress: progress);

        // Assert
        Assert.True(success, "Firmware load falhou");

        _output.WriteLine("✅ Firmware carregado com sucesso");
        _output.WriteLine("📊 VALIDAÇÃO: Desligar/ligar HS3 USB e verificar se ainda funciona");

        // Cleanup
        protocol.CloseDevice();
    }

    #endregion

    #region Stress Tests

    [Fact]
    [Trait("Category", "RequiresHardware")]
    [Trait("Category", "Slow")]
    public async Task FrequencySweep_1Hz_1kHz_DeveCompletarSemErros()
    {
        // Arrange
        var protocol = new HS3DeviceProtocol(_protocolLogger);
        protocol.OpenDevice(TEST_DEVICE_PATH);
        protocol.GetDeviceCapabilities(out _);
        protocol.ConfigureDevice();

        var generator = new HS3FunctionGenerator(_generatorLogger, protocol);

        // Configure amplitude e waveform
        await generator.SetAmplitudeAsync(1.0);
        await generator.SetWaveformAsync(WaveformType.Sine);
        await generator.EnableOutputAsync();

        // Act - Sweep 1 Hz → 1000 Hz
        int errorCount = 0;
        for (double freq = 1.0; freq <= 1000.0; freq *= 1.1) // Sweep logarítmico
        {
            bool success = await generator.SetFrequencyAsync(freq);
            if (!success)
            {
                errorCount++;
                _output.WriteLine($"❌ Falha em {freq:F3} Hz");
            }

            await Task.Delay(50); // 50ms por frequência
        }

        // Assert
        Assert.Equal(0, errorCount);

        _output.WriteLine($"✅ Frequency sweep completo: 1 Hz → 1 kHz sem erros");

        // Cleanup
        await generator.EmergencyStopAsync();
        protocol.CloseDevice();
    }

    #endregion

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing)
        {
            // Cleanup global (caso algum teste falhe sem cleanup)
            _output.WriteLine("🧹 Cleanup global dos testes");
        }
    }
}

#region Xunit Logger Provider

/// <summary>
/// Provider para logs do ILogger aparecerem no Xunit output
/// </summary>
public sealed class XunitLoggerProvider : ILoggerProvider
{
    private readonly ITestOutputHelper _output;

    public XunitLoggerProvider(ITestOutputHelper output)
    {
        _output = output;
    }

    public ILogger CreateLogger(string categoryName)
    {
        return new XunitLogger(_output, categoryName);
    }

    public void Dispose() { }
}

public class XunitLogger : ILogger
{
    private readonly ITestOutputHelper _output;
    private readonly string _categoryName;

    public XunitLogger(ITestOutputHelper output, string categoryName)
    {
        _output = output;
        _categoryName = categoryName;
    }

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter)
    {
        string message = formatter(state, exception);
        _output.WriteLine($"[{logLevel}] {_categoryName}: {message}");

        if (exception != null)
            _output.WriteLine($"  Exception: {exception}");
    }
}

#endregion
