using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Hardware.TiePie;

/// <summary>
/// Implementação do protocolo de comunicação USB para TiePie HS3
/// Baseado em engenharia reversa de hs3.dll via API Monitor (19/10/2025)
/// 
/// Sequência de inicialização:
/// 1. OpenDevice() - Abre handle USB
/// 2. GetDeviceCapabilities() - IOCTL 0x222000 (1024 bytes)
/// 3. ConfigureDevice() - IOCTL 0x222059 (10→8 bytes)
/// 4. SendCommand() loop - Padrão READ (0x222051) → WRITE (0x22204E)
/// </summary>
public class HS3DeviceProtocol : IDisposable
{
    private readonly ILogger<HS3DeviceProtocol> _logger;
    private SafeFileHandle? _deviceHandle;
    private bool _disposed;
    
    // Buffers pré-alocados e pinned em memória para performance
    private readonly byte[] _readBuffer = new byte[8];
    private readonly byte[] _writeBuffer = new byte[64];
    private readonly byte[] _deviceInfoBuffer = new byte[1024];
    private GCHandle _readBufferHandle;
    private GCHandle _writeBufferHandle;
    private GCHandle _deviceInfoHandle;
    
    // Lock para garantir thread-safety (todas as operações USB são single-threaded)
    private readonly object _deviceLock = new object();
    
    #region P/Invoke Declarations
    
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );
    
    [DllImport("kernel32.dll", SetLastError = true)]
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
    
    // Constantes Win32
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    
    #endregion
    
    public HS3DeviceProtocol(ILogger<HS3DeviceProtocol> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        
        // Pin buffers em memória para evitar realocação pelo GC durante P/Invoke
        _readBufferHandle = GCHandle.Alloc(_readBuffer, GCHandleType.Pinned);
        _writeBufferHandle = GCHandle.Alloc(_writeBuffer, GCHandleType.Pinned);
        _deviceInfoHandle = GCHandle.Alloc(_deviceInfoBuffer, GCHandleType.Pinned);
        
        _logger.LogDebug("HS3DeviceProtocol initialized with pinned buffers");
    }
    
    /// <summary>
    /// Abre comunicação com o dispositivo HS3
    /// Device path format: \\?\usb#vid_0e36&pid_0008#...#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}
    /// </summary>
    /// <param name="devicePath">Caminho USB do dispositivo</param>
    /// <returns>True se aberto com sucesso</returns>
    public bool OpenDevice(string devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath))
        {
            throw new ArgumentException("Device path não pode ser vazio", nameof(devicePath));
        }
        
        lock (_deviceLock)
        {
            if (_deviceHandle != null && !_deviceHandle.IsInvalid)
            {
                _logger.LogWarning("Device já está aberto. Ignorando OpenDevice()");
                return true;
            }
            
            _logger.LogInformation($"Abrindo device HS3: {devicePath}");
            
            _deviceHandle = CreateFile(
                devicePath,
                GENERIC_READ | GENERIC_WRITE,
                0, // Exclusive access
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                IntPtr.Zero
            );
            
            if (_deviceHandle.IsInvalid)
            {
                int error = Marshal.GetLastWin32Error();
                _logger.LogError($"Falha ao abrir device HS3. Win32 Error: {error} (0x{error:X8})");
                _deviceHandle = null;
                return false;
            }
            
            _logger.LogInformation($"Device HS3 aberto com sucesso. Handle: 0x{_deviceHandle.DangerousGetHandle():X}");
            return true;
        }
    }
    
    /// <summary>
    /// Fecha o device handle
    /// </summary>
    public void CloseDevice()
    {
        lock (_deviceLock)
        {
            if (_deviceHandle != null && !_deviceHandle.IsInvalid)
            {
                _logger.LogInformation("Fechando device HS3");
                _deviceHandle.Dispose();
                _deviceHandle = null;
            }
        }
    }
    
    /// <summary>
    /// Verifica se o device está aberto e pronto
    /// </summary>
    public bool IsDeviceOpen => _deviceHandle != null && !_deviceHandle.IsInvalid;
    
    /// <summary>
    /// Obtém capabilities do dispositivo (IOCTL 0x222000)
    /// Primeira operação após abrir device
    /// Input: 0 bytes, Output: 1024 bytes
    /// </summary>
    public bool GetDeviceCapabilities(out HS3DeviceCapabilities capabilities)
    {
        capabilities = default;
        
        lock (_deviceLock)
        {
            if (!IsDeviceOpen)
            {
                _logger.LogError("GetDeviceCapabilities: Device não está aberto");
                return false;
            }
            
            _logger.LogDebug("GetDeviceCapabilities: IOCTL 0x222000, 0→1024 bytes");
            
            IntPtr deviceInfoPtr = _deviceInfoHandle.AddrOfPinnedObject();
            Array.Clear(_deviceInfoBuffer, 0, _deviceInfoBuffer.Length);
            
            bool success = DeviceIoControl(
                _deviceHandle!,
                HS3Protocol.IOCTL_GET_DEVICE_INFO,
                IntPtr.Zero,
                0,
                deviceInfoPtr,
                1024,
                out uint bytesReturned,
                IntPtr.Zero
            );
            
            if (!success)
            {
                int error = Marshal.GetLastWin32Error();
                _logger.LogError($"GetDeviceCapabilities falhou. Win32 Error: {error} (0x{error:X8})");
                return false;
            }
            
            _logger.LogInformation($"Device capabilities obtidas: {bytesReturned} bytes");
            
            // Marshal buffer para struct
            capabilities = Marshal.PtrToStructure<HS3DeviceCapabilities>(deviceInfoPtr);
            
            _logger.LogInformation(
                $"Device Info: VID=0x{capabilities.VendorId:X4}, " +
                $"PID=0x{capabilities.ProductId:X4}, " +
                $"Serial={capabilities.SerialNumber}, " +
                $"FW={capabilities.FirmwareVersion}, " +
                $"HW={capabilities.HardwareRevision}"
            );
            
            if (!capabilities.IsValidHS3Device())
            {
                _logger.LogWarning(
                    $"Device não é um HS3 válido! Expected VID=0x{HS3Protocol.USB_VENDOR_ID:X4}, " +
                    $"PID=0x{HS3Protocol.USB_PRODUCT_ID:X4}"
                );
            }
            
            return true;
        }
    }
    
    /// <summary>
    /// Configuração inicial do dispositivo (IOCTL 0x222059)
    /// Segunda operação após GetDeviceCapabilities
    /// Input: 10 bytes, Output: 8 bytes
    /// </summary>
    public bool ConfigureDevice(HS3ConfigData configData)
    {
        lock (_deviceLock)
        {
            if (!IsDeviceOpen)
            {
                _logger.LogError("ConfigureDevice: Device não está aberto");
                return false;
            }
            
            _logger.LogDebug("ConfigureDevice: IOCTL 0x222059, 10→8 bytes");
            
            byte[] responseBuffer = new byte[8];
            
            // Alocar e marshal configData
            int configSize = Marshal.SizeOf<HS3ConfigData>();
            IntPtr configPtr = Marshal.AllocHGlobal(configSize);
            IntPtr responsePtr = Marshal.AllocHGlobal(8);
            
            try
            {
                Marshal.StructureToPtr(configData, configPtr, false);
                
                bool success = DeviceIoControl(
                    _deviceHandle!,
                    HS3Protocol.IOCTL_CONFIG_QUERY,
                    configPtr,
                    10,
                    responsePtr,
                    8,
                    out uint bytesReturned,
                    IntPtr.Zero
                );
                
                if (!success)
                {
                    int error = Marshal.GetLastWin32Error();
                    _logger.LogError($"ConfigureDevice falhou. Win32 Error: {error} (0x{error:X8})");
                    return false;
                }
                
                _logger.LogInformation($"Device configurado. Response: {bytesReturned} bytes");
                
                // Log response para debug
                Marshal.Copy(responsePtr, responseBuffer, 0, (int)bytesReturned);
                _logger.LogDebug($"Config response: {BitConverter.ToString(responseBuffer, 0, (int)bytesReturned)}");
                
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(configPtr);
                Marshal.FreeHGlobal(responsePtr);
            }
        }
    }
    
    /// <summary>
    /// Padrão read-write para envio de comandos
    /// Implementa sequência observada: READ (0x222051) → WRITE (0x22204E)
    /// </summary>
    /// <param name="command">Código do comando (4 bytes)</param>
    /// <param name="response">Resposta da operação READ (8 bytes)</param>
    /// <param name="writeData">Dados opcionais para WRITE</param>
    /// <param name="writeSize">Tamanho do buffer de output do WRITE (1-64 bytes)</param>
    /// <returns>True se ambas operações bem-sucedidas</returns>
    public bool SendCommand(uint command, out HS3Response8 response, 
                           byte[]? writeData = null, int writeSize = 1)
    {
        response = default;
        
        lock (_deviceLock)
        {
            if (!IsDeviceOpen)
            {
                _logger.LogError("SendCommand: Device não está aberto");
                return false;
            }
            
            // FASE 1: READ - Query device status
            _logger.LogTrace($"READ: IOCTL 0x222051, command=0x{command:X8}");
            
            IntPtr readBufferPtr = _readBufferHandle.AddrOfPinnedObject();
            Array.Clear(_readBuffer, 0, _readBuffer.Length);
            
            // Input: 4 bytes (command code)
            Marshal.WriteInt32(readBufferPtr, 0, (int)command);
            
            bool readSuccess = DeviceIoControl(
                _deviceHandle!,
                HS3Protocol.IOCTL_READ_OPERATION,
                readBufferPtr,
                4,
                readBufferPtr,
                8,
                out uint bytesReturned,
                IntPtr.Zero
            );
            
            if (!readSuccess)
            {
                int error = Marshal.GetLastWin32Error();
                _logger.LogError($"READ falhou. Win32 Error: {error} (0x{error:X8})");
                return false;
            }
            
            // Parse response
            response = Marshal.PtrToStructure<HS3Response8>(readBufferPtr);
            _logger.LogTrace($"READ OK: {bytesReturned} bytes, {response}");
            
            // FASE 2: WRITE - Send command/data
            _logger.LogTrace($"WRITE: IOCTL 0x22204E, command=0x{command:X8}, size={writeSize}");
            
            if (writeSize < 1 || writeSize > 64)
            {
                _logger.LogError($"WriteSize inválido: {writeSize}. Deve estar entre 1 e 64.");
                return false;
            }
            
            IntPtr writeBufferPtr = _writeBufferHandle.AddrOfPinnedObject();
            Array.Clear(_writeBuffer, 0, _writeBuffer.Length);
            
            // Input: 4 bytes (command)
            Marshal.WriteInt32(writeBufferPtr, 0, (int)command);
            
            // Copiar dados adicionais se fornecidos
            if (writeData != null && writeData.Length > 0)
            {
                int copySize = Math.Min(writeData.Length, 60); // Max 60 bytes (64 - 4 do command)
                Marshal.Copy(writeData, 0, writeBufferPtr + 4, copySize);
            }
            
            bool writeSuccess = DeviceIoControl(
                _deviceHandle!,
                HS3Protocol.IOCTL_WRITE_OPERATION,
                writeBufferPtr,
                4,
                writeBufferPtr,
                (uint)writeSize,
                out bytesReturned,
                IntPtr.Zero
            );
            
            if (!writeSuccess)
            {
                int error = Marshal.GetLastWin32Error();
                _logger.LogError($"WRITE falhou. Win32 Error: {error} (0x{error:X8})");
                return false;
            }
            
            _logger.LogTrace($"WRITE OK: {bytesReturned} bytes");
            
            // Log write response para debug
            if (bytesReturned > 0 && bytesReturned <= 64)
            {
                byte[] writeResponse = new byte[bytesReturned];
                Marshal.Copy(writeBufferPtr, writeResponse, 0, (int)bytesReturned);
                _logger.LogTrace($"Write response: {BitConverter.ToString(writeResponse)}");
            }
            
            return true;
        }
    }
    
    /// <summary>
    /// Operação READ simples (sem WRITE subsequente)
    /// Útil para queries rápidas de status
    /// </summary>
    public bool ReadOperation(uint command, out HS3Response8 response)
    {
        response = default;
        
        lock (_deviceLock)
        {
            if (!IsDeviceOpen)
            {
                _logger.LogError("ReadOperation: Device não está aberto");
                return false;
            }
            
            _logger.LogTrace($"READ: IOCTL 0x222051, command=0x{command:X8}");
            
            IntPtr readBufferPtr = _readBufferHandle.AddrOfPinnedObject();
            Array.Clear(_readBuffer, 0, _readBuffer.Length);
            
            Marshal.WriteInt32(readBufferPtr, 0, (int)command);
            
            bool success = DeviceIoControl(
                _deviceHandle!,
                HS3Protocol.IOCTL_READ_OPERATION,
                readBufferPtr,
                4,
                readBufferPtr,
                8,
                out uint bytesReturned,
                IntPtr.Zero
            );
            
            if (!success)
            {
                int error = Marshal.GetLastWin32Error();
                _logger.LogError($"READ falhou. Win32 Error: {error} (0x{error:X8})");
                return false;
            }
            
            response = Marshal.PtrToStructure<HS3Response8>(readBufferPtr);
            _logger.LogTrace($"READ OK: {bytesReturned} bytes, {response}");
            
            return true;
        }
    }
    
    public void Dispose()
    {
        if (_disposed) return;
        
        _logger.LogDebug("Disposing HS3DeviceProtocol");
        
        CloseDevice();
        
        // Free pinned buffers
        if (_readBufferHandle.IsAllocated) _readBufferHandle.Free();
        if (_writeBufferHandle.IsAllocated) _writeBufferHandle.Free();
        if (_deviceInfoHandle.IsAllocated) _deviceInfoHandle.Free();
        
        _disposed = true;
        GC.SuppressFinalize(this);
        
        _logger.LogDebug("HS3DeviceProtocol disposed");
    }
}
