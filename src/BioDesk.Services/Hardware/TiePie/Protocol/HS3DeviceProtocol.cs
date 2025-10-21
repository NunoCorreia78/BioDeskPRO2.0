using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Extensions.Logging;
using Microsoft.Win32.SafeHandles;

namespace BioDesk.Services.Hardware.TiePie.Protocol;

/// <summary>
/// Implementação do protocolo USB TiePie Handyscope HS3
/// Comunicação DIRETA via DeviceIoControl (NÃO usa hs3.dll do Inergetix)
///
/// IMPORTANTE - Padrões obrigatórios descobertos:
/// 1. Thread-safety: TODAS as operações DeviceIoControl DEVEM ser single-threaded
/// 2. Sequence: Sempre READ (0x222051) seguido de WRITE (0x22204E)
/// 3. Buffer reuse: Usar pinned buffers (GCHandle) para performance
/// 4. Timing: Respeitar timeouts (bulk transfer 64B = 2.5ms crítico)
///
/// Sequência de inicialização:
/// 1. OpenDevice(devicePath) → CreateFile
/// 2. GetDeviceCapabilities() → IOCTL 0x222000 (validar VID/PID)
/// 3. ConfigureDevice() → IOCTL 0x222059 (setup inicial)
/// 4. SendCommand(cmd) → Loop READ/WRITE
/// </summary>
public sealed class HS3DeviceProtocol : IDisposable
{
    #region Fields

    private readonly ILogger<HS3DeviceProtocol> _logger;

    /// <summary>
    /// Handle do dispositivo USB (SafeFileHandle gerencia cleanup automático)
    /// </summary>
    private SafeFileHandle? _deviceHandle;

    /// <summary>
    /// Lock para garantir single-threaded access (CRÍTICO para HS3)
    /// Todas operações DeviceIoControl DEVEM estar protegidas
    /// </summary>
    private readonly object _deviceLock = new object();

    /// <summary>
    /// Buffers pinned para reutilização (evita GC overhead)
    /// GCHandle mantém buffers fixos na memória durante P/Invoke
    /// </summary>
    private GCHandle _readBufferHandle;
    private GCHandle _writeBufferHandle;
    private GCHandle _deviceInfoBufferHandle;

    /// <summary>
    /// Buffers pre-alocados (reutilizados em cada operação)
    /// </summary>
    private readonly byte[] _readBuffer = new byte[HS3Protocol.READ_RESPONSE_SIZE];
    private readonly byte[] _writeBuffer = new byte[HS3Protocol.WRITE_RESPONSE_MAX_SIZE];
    private readonly byte[] _deviceInfoBuffer = new byte[HS3Protocol.DEVICE_INFO_BUFFER_SIZE];

    /// <summary>
    /// Flag disposed (padrão CA1063 compliant)
    /// </summary>
    private bool _disposed = false;

    #endregion

    #region Win32 P/Invoke Declarations

    /// <summary>
    /// Flags para CreateFile (acesso ao dispositivo USB)
    /// </summary>
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OVERLAPPED = 0x40000000;

    /// <summary>
    /// Abre handle para dispositivo USB via device path
    /// Path format: \\?\usb#vid_0e36&pid_0008#...#{guid}
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    /// <summary>
    /// Envia IOCTLs para dispositivo USB
    /// Core function para toda comunicação HS3
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(
        SafeFileHandle hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    #endregion

    #region Constructor & Dispose

    public HS3DeviceProtocol(ILogger<HS3DeviceProtocol> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Pin buffers para reutilização (evita GC moves durante P/Invoke)
        _readBufferHandle = GCHandle.Alloc(_readBuffer, GCHandleType.Pinned);
        _writeBufferHandle = GCHandle.Alloc(_writeBuffer, GCHandleType.Pinned);
        _deviceInfoBufferHandle = GCHandle.Alloc(_deviceInfoBuffer, GCHandleType.Pinned);

        _logger.LogDebug("HS3DeviceProtocol inicializado com buffers pinned (performance optimization)");
    }

    /// <summary>
    /// Dispose pattern CA1063-compliant
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Dispose implementation
    /// </summary>
    /// <param name="disposing">True se chamado via Dispose(), false se via finalizer</param>
    private void Dispose(bool disposing)
    {
        if (_disposed)
            return;

        if (disposing)
        {
            // Cleanup managed resources
            CloseDevice();
        }

        // Cleanup native resources (SEMPRE executar, mesmo se disposing=false)
        if (_readBufferHandle.IsAllocated)
            _readBufferHandle.Free();
        if (_writeBufferHandle.IsAllocated)
            _writeBufferHandle.Free();
        if (_deviceInfoBufferHandle.IsAllocated)
            _deviceInfoBufferHandle.Free();

        _disposed = true;
        _logger.LogDebug("HS3DeviceProtocol disposed (buffers unpinned)");
    }

    #endregion

    #region Public Methods

    /// <summary>
    /// Abre dispositivo HS3 via device path
    /// </summary>
    /// <param name="devicePath">Path USB: \\?\usb#vid_0e36&pid_0008#...#{guid}</param>
    /// <returns>True se aberto com sucesso</returns>
    public bool OpenDevice(string devicePath)
    {
        lock (_deviceLock)
        {
            if (_deviceHandle != null && !_deviceHandle.IsInvalid)
            {
                _logger.LogWarning("Device já estava aberto. Fechando handle antigo.");
                CloseDevice();
            }

            _logger.LogInformation("Abrindo HS3 device: {DevicePath}", devicePath);

            _deviceHandle = CreateFile(
                devicePath,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                IntPtr.Zero,
                OPEN_EXISTING,
                0, // Sem FILE_FLAG_OVERLAPPED (operações síncronas)
                IntPtr.Zero);

            if (_deviceHandle.IsInvalid)
            {
                var error = Marshal.GetLastWin32Error();
                _logger.LogError("FALHA ao abrir device. Win32 Error: {Error} ({ErrorCode})",
                    new Win32Exception(error).Message, error);
                return false;
            }

            _logger.LogInformation("✅ Device aberto com sucesso. Handle: {Handle}", _deviceHandle.DangerousGetHandle());
            return true;
        }
    }

    /// <summary>
    /// Fecha device handle
    /// </summary>
    public void CloseDevice()
    {
        lock (_deviceLock)
        {
            if (_deviceHandle != null && !_deviceHandle.IsInvalid)
            {
                _logger.LogInformation("Fechando HS3 device handle");
                _deviceHandle.Dispose();
                _deviceHandle = null;
            }
        }
    }

    /// <summary>
    /// Obtém capabilities do dispositivo (primeira operação após OpenDevice)
    /// IOCTL 0x222000 → 1024 bytes (HS3DeviceCapabilities)
    /// </summary>
    /// <param name="capabilities">Struct com VID, PID, serial, firmware, etc</param>
    /// <returns>True se sucesso</returns>
    public bool GetDeviceCapabilities(out HS3DeviceCapabilities capabilities)
    {
        capabilities = default;

        lock (_deviceLock)
        {
            if (!IsDeviceOpen())
            {
                _logger.LogError("GetDeviceCapabilities: Device não está aberto");
                return false;
            }

            _logger.LogDebug("Executando IOCTL_GET_DEVICE_INFO (0x222000)...");

            Array.Clear(_deviceInfoBuffer, 0, _deviceInfoBuffer.Length);

            var inputPtr = IntPtr.Zero;
            var outputPtr = _deviceInfoBufferHandle.AddrOfPinnedObject();

            bool success = DeviceIoControl(
                _deviceHandle!,
                HS3Protocol.IOCTL_GET_DEVICE_INFO,
                inputPtr,
                0,
                outputPtr,
                HS3Protocol.DEVICE_INFO_BUFFER_SIZE,
                out uint bytesReturned,
                IntPtr.Zero);

            if (!success)
            {
                var error = Marshal.GetLastWin32Error();
                _logger.LogError("IOCTL_GET_DEVICE_INFO FALHOU. Win32 Error: {Error} ({ErrorCode})",
                    new Win32Exception(error).Message, error);
                return false;
            }

            if (bytesReturned != HS3Protocol.DEVICE_INFO_BUFFER_SIZE)
            {
                _logger.LogWarning("IOCTL_GET_DEVICE_INFO retornou {Returned} bytes (esperado: {Expected})",
                    bytesReturned, HS3Protocol.DEVICE_INFO_BUFFER_SIZE);
            }

            // Parse buffer para struct HS3DeviceCapabilities
            capabilities = Marshal.PtrToStructure<HS3DeviceCapabilities>(outputPtr);

            _logger.LogInformation("✅ Device Capabilities: {Device}", capabilities.ToString());

            // Validar se é HS3 válido
            if (!capabilities.IsValidHS3Device())
            {
                _logger.LogError("❌ Device NÃO é HS3 válido! VID: 0x{VID:X4}, PID: 0x{PID:X4}",
                    capabilities.VendorId, capabilities.ProductId);
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// Configura dispositivo (segunda operação após GetDeviceCapabilities)
    /// IOCTL 0x222059 → 10 bytes input, 8 bytes output
    ///
    /// ATENÇÃO: Parâmetros corretos são DESCONHECIDOS.
    /// TODO: Validar com hardware real. Usar valores padrão por enquanto.
    /// </summary>
    /// <param name="configData">Dados de configuração (valores hipotéticos)</param>
    /// <returns>True se sucesso</returns>
    public bool ConfigureDevice(HS3ConfigData? configData = null)
    {
        lock (_deviceLock)
        {
            if (!IsDeviceOpen())
            {
                _logger.LogError("ConfigureDevice: Device não está aberto");
                return false;
            }

            var config = configData ?? HS3ConfigData.CreateDefault();

            _logger.LogDebug("Executando IOCTL_CONFIG_QUERY (0x222059) com ConfigCode: 0x{Code:X4}",
                config.ConfigCode);

            // Alocar buffer input temporário
            int configSize = Marshal.SizeOf<HS3ConfigData>();
            IntPtr inputPtr = Marshal.AllocHGlobal(configSize);
            IntPtr outputPtr = _readBufferHandle.AddrOfPinnedObject();

            try
            {
                Marshal.StructureToPtr(config, inputPtr, false);
                Array.Clear(_readBuffer, 0, _readBuffer.Length);

                bool success = DeviceIoControl(
                    _deviceHandle!,
                    HS3Protocol.IOCTL_CONFIG_QUERY,
                    inputPtr,
                    (uint)configSize,
                    outputPtr,
                    HS3Protocol.READ_RESPONSE_SIZE,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!success)
                {
                    var error = Marshal.GetLastWin32Error();
                    _logger.LogError("IOCTL_CONFIG_QUERY FALHOU. Win32 Error: {Error} ({ErrorCode})",
                        new Win32Exception(error).Message, error);
                    return false;
                }

                _logger.LogInformation("✅ Device configurado. Bytes retornados: {Bytes}", bytesReturned);

                // Parse resposta (8 bytes)
                if (bytesReturned == 8)
                {
                    var response = Marshal.PtrToStructure<HS3Response8>(outputPtr);
                    _logger.LogDebug("Config response: {Response}", response.ToString());
                }

                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }
    }

    /// <summary>
    /// Envia comando ao dispositivo usando padrão READ→WRITE
    /// Padrão descoberto: SEMPRE fazer READ (0x222051) seguido de WRITE (0x22204E)
    ///
    /// ATENÇÃO CRÍTICA: Códigos de comando são HIPOTÉTICOS.
    /// TODO: Descobrir comandos reais via análise firmware ou tentativa/erro.
    /// </summary>
    /// <param name="commandCode">Código do comando (4 bytes)</param>
    /// <param name="expectedResponseSize">Tamanho esperado da resposta WRITE</param>
    /// <param name="response">Buffer resposta WRITE (até 64 bytes)</param>
    /// <returns>True se sucesso</returns>
    public bool SendCommand(uint commandCode, int expectedResponseSize, out byte[] response)
    {
        response = Array.Empty<byte>();

        lock (_deviceLock)
        {
            if (!IsDeviceOpen())
            {
                _logger.LogError("SendCommand: Device não está aberto");
                return false;
            }

            _logger.LogDebug("SendCommand: 0x{Command:X8} (esperando {Size} bytes resposta)",
                commandCode, expectedResponseSize);

            // PASSO 1: READ_OPERATION (query status)
            if (!ReadOperation(commandCode, out HS3Response8 readResponse))
            {
                _logger.LogError("SendCommand: READ_OPERATION falhou");
                return false;
            }

            _logger.LogTrace("READ response: {Response}", readResponse.ToString());

            // PASSO 2: WRITE_OPERATION (get data)
            if (!WriteOperation(commandCode, expectedResponseSize, out response))
            {
                _logger.LogError("SendCommand: WRITE_OPERATION falhou");
                return false;
            }

            _logger.LogDebug("✅ SendCommand completado. Response size: {Size} bytes", response.Length);
            return true;
        }
    }

    /// <summary>
    /// Operação READ isolada (IOCTL 0x222051)
    /// Input: 4 bytes (command code), Output: 8 bytes (HS3Response8)
    /// </summary>
    /// <param name="commandCode">Código do comando</param>
    /// <param name="response">Resposta (8 bytes, pode ser double/long/2×uint)</param>
    /// <returns>True se sucesso</returns>
    public bool ReadOperation(uint commandCode, out HS3Response8 response)
    {
        response = default;

        lock (_deviceLock)
        {
            if (!IsDeviceOpen())
            {
                _logger.LogError("ReadOperation: Device não está aberto");
                return false;
            }

            // Preparar input: 4 bytes com command code
            var commandBytes = BitConverter.GetBytes(commandCode);
            IntPtr inputPtr = Marshal.AllocHGlobal(4);
            IntPtr outputPtr = _readBufferHandle.AddrOfPinnedObject();

            try
            {
                Marshal.Copy(commandBytes, 0, inputPtr, 4);
                Array.Clear(_readBuffer, 0, _readBuffer.Length);

                bool success = DeviceIoControl(
                    _deviceHandle!,
                    HS3Protocol.IOCTL_READ_OPERATION,
                    inputPtr,
                    4,
                    outputPtr,
                    HS3Protocol.READ_RESPONSE_SIZE,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!success)
                {
                    var error = Marshal.GetLastWin32Error();
                    _logger.LogError("READ_OPERATION (0x{Command:X8}) FALHOU. Win32 Error: {Error} ({ErrorCode})",
                        commandCode, new Win32Exception(error).Message, error);
                    return false;
                }

                if (bytesReturned != 8)
                {
                    _logger.LogWarning("READ_OPERATION retornou {Returned} bytes (esperado: 8)", bytesReturned);
                }

                response = Marshal.PtrToStructure<HS3Response8>(outputPtr);
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }
    }

    /// <summary>
    /// Operação WRITE isolada (IOCTL 0x22204E)
    /// Input: 4 bytes (command code), Output: 1-64 bytes (variável)
    ///
    /// TIMING CRÍTICO: 64-byte bulk transfers = 2.5ms (USB packet size limit)
    /// </summary>
    /// <param name="commandCode">Código do comando</param>
    /// <param name="expectedSize">Tamanho esperado da resposta (1-64 bytes)</param>
    /// <param name="response">Buffer resposta</param>
    /// <returns>True se sucesso</returns>
    public bool WriteOperation(uint commandCode, int expectedSize, out byte[] response)
    {
        response = Array.Empty<byte>();

        lock (_deviceLock)
        {
            if (!IsDeviceOpen())
            {
                _logger.LogError("WriteOperation: Device não está aberto");
                return false;
            }

            if (expectedSize < 1 || expectedSize > 64)
            {
                _logger.LogError("WriteOperation: expectedSize inválido ({Size}). Range: 1-64", expectedSize);
                return false;
            }

            var commandBytes = BitConverter.GetBytes(commandCode);
            IntPtr inputPtr = Marshal.AllocHGlobal(4);
            IntPtr outputPtr = _writeBufferHandle.AddrOfPinnedObject();

            try
            {
                Marshal.Copy(commandBytes, 0, inputPtr, 4);
                Array.Clear(_writeBuffer, 0, _writeBuffer.Length);

                bool success = DeviceIoControl(
                    _deviceHandle!,
                    HS3Protocol.IOCTL_WRITE_OPERATION,
                    inputPtr,
                    4,
                    outputPtr,
                    (uint)expectedSize,
                    out uint bytesReturned,
                    IntPtr.Zero);

                if (!success)
                {
                    var error = Marshal.GetLastWin32Error();
                    _logger.LogError("WRITE_OPERATION (0x{Command:X8}) FALHOU. Win32 Error: {Error} ({ErrorCode})",
                        commandCode, new Win32Exception(error).Message, error);
                    return false;
                }

                if (bytesReturned != expectedSize)
                {
                    _logger.LogWarning("WRITE_OPERATION retornou {Returned} bytes (esperado: {Expected})",
                        bytesReturned, expectedSize);
                }

                // Copiar resposta
                response = new byte[bytesReturned];
                Array.Copy(_writeBuffer, response, bytesReturned);

                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(inputPtr);
            }
        }
    }

    /// <summary>
    /// Verifica se device está aberto
    /// </summary>
    public bool IsDeviceOpen()
    {
        return _deviceHandle != null && !_deviceHandle.IsInvalid;
    }

    #endregion

    #region Utility Methods

    /// <summary>
    /// Converte buffer bytes para hex string (debug/logging)
    /// </summary>
    private static string ToHexString(byte[] buffer, int length)
    {
        return BitConverter.ToString(buffer, 0, Math.Min(length, buffer.Length)).Replace("-", " ");
    }

    #endregion
}
