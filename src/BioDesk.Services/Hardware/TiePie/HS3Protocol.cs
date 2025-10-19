using System;
using System.Runtime.InteropServices;

namespace BioDesk.Services.Hardware.TiePie;

/// <summary>
/// Estruturas de dados e constantes para protocolo USB HS3
/// Baseado em engenharia reversa via API Monitor (19/10/2025)
/// </summary>
public static class HS3Protocol
{
    #region IOCTL Codes

    /// <summary>
    /// IOCTL para obter informações do dispositivo (1024 bytes)
    /// Primeira chamada após abrir device
    /// Input: 0 bytes, Output: 1024 bytes
    /// </summary>
    public const uint IOCTL_GET_DEVICE_INFO = 0x222000;

    /// <summary>
    /// IOCTL para configuração inicial do dispositivo
    /// Segunda chamada após GET_DEVICE_INFO
    /// Input: 10 bytes, Output: 8 bytes
    /// </summary>
    public const uint IOCTL_CONFIG_QUERY = 0x222059;

    /// <summary>
    /// IOCTL para operações de leitura
    /// Usado em padrão alternado com WRITE_OPERATION
    /// Input: 4 bytes (command), Output: 8 bytes (típico)
    /// </summary>
    public const uint IOCTL_READ_OPERATION = 0x222051;

    /// <summary>
    /// IOCTL para operações de escrita/controle
    /// Usado em padrão alternado com READ_OPERATION
    /// Input: 4 bytes (command), Output: 1-64 bytes (variável)
    /// </summary>
    public const uint IOCTL_WRITE_OPERATION = 0x22204E;

    #endregion

    #region USB Device Identifiers

    /// <summary>
    /// Vendor ID: TiePie Engineering
    /// </summary>
    public const ushort USB_VENDOR_ID = 0x0E36;

    /// <summary>
    /// Product ID: Handyscope HS3
    /// </summary>
    public const ushort USB_PRODUCT_ID = 0x0008;

    /// <summary>
    /// Device Interface GUID para TiePie HS3
    /// Usado para discovery via SetupDi APIs
    /// </summary>
    public static readonly Guid DEVICE_INTERFACE_GUID = 
        new Guid("{f58af81e-4cdc-4d3f-b11e-0a89e4683972}");

    #endregion

    #region Timing Constants

    /// <summary>
    /// Timeout padrão para operações DeviceIoControl (ms)
    /// Baseado em latência média observada: 6.236ms
    /// </summary>
    public const int DEFAULT_IOCTL_TIMEOUT_MS = 100;

    /// <summary>
    /// Timeout para operações bulk (64 bytes)
    /// Baseado em latência observada: 2.5-2.6ms
    /// </summary>
    public const int BULK_TRANSFER_TIMEOUT_MS = 50;

    /// <summary>
    /// Timeout para carregamento de firmware
    /// Baseado em tempo observado: ~65ms para 243KB
    /// </summary>
    public const int FIRMWARE_LOAD_TIMEOUT_MS = 5000;

    #endregion
}

#region Data Structures

/// <summary>
/// Capabilities do dispositivo HS3 (1024 bytes)
/// Retornado por IOCTL_GET_DEVICE_INFO (0x222000)
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 1024)]
public struct HS3DeviceCapabilities
{
    // Primeiros 16 bytes - Identificação do dispositivo
    public ushort VendorId;           // 0x0E36 (TiePie Engineering)
    public ushort ProductId;          // 0x0008 (Handyscope HS3)
    public uint SerialNumber;         // Número de série único
    public ushort FirmwareVersion;    // Versão firmware (major.minor)
    public ushort HardwareRevision;   // Revisão hardware
    public uint Reserved1;            // Padding/reserved

    // Bytes 16-64 - Configurações do gerador de funções
    public double MinFrequency;       // Frequência mínima (Hz)
    public double MaxFrequency;       // Frequência máxima (Hz)
    public double MinAmplitude;       // Amplitude mínima (V)
    public double MaxAmplitude;       // Amplitude máxima (V)
    public uint SupportedWaveforms;   // Bitmask de waveforms suportados
    public uint ChannelCount;         // Número de canais (1 para HS3)

    // Bytes 64-1024 - Dados adicionais (não parseados)
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 960)]
    public byte[] RawData;

    /// <summary>
    /// Converte VendorId e ProductId para string formatada
    /// </summary>
    public readonly string GetDeviceId() => $"VID_{VendorId:X4}&PID_{ProductId:X4}";

    /// <summary>
    /// Verifica se é um dispositivo HS3 válido
    /// </summary>
    public readonly bool IsValidHS3Device() =>
        VendorId == HS3Protocol.USB_VENDOR_ID &&
        ProductId == HS3Protocol.USB_PRODUCT_ID;
}

/// <summary>
/// Resposta padrão de 8 bytes para IOCTL_READ_OPERATION
/// Pode ser interpretado como double, long ou dois uint
/// </summary>
[StructLayout(LayoutKind.Explicit, Pack = 1, Size = 8)]
public struct HS3Response8
{
    /// <summary>
    /// Interpreta resposta como double (frequência, amplitude, etc)
    /// </summary>
    [FieldOffset(0)]
    public double ValueAsDouble;

    /// <summary>
    /// Interpreta resposta como long (timestamp, contador, etc)
    /// </summary>
    [FieldOffset(0)]
    public long ValueAsLong;

    /// <summary>
    /// Parte baixa (primeiros 4 bytes)
    /// </summary>
    [FieldOffset(0)]
    public uint LowDWord;

    /// <summary>
    /// Parte alta (últimos 4 bytes)
    /// </summary>
    [FieldOffset(4)]
    public uint HighDWord;

    public override readonly string ToString() =>
        $"Double: {ValueAsDouble:F6}, Long: {ValueAsLong}, DWords: 0x{LowDWord:X8} 0x{HighDWord:X8}";
}

/// <summary>
/// Status flag de 1 byte
/// Retornado por algumas operações WRITE
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HS3StatusFlag
{
    /// <summary>
    /// Status code: 0x00 = OK, 0x01 = Busy, 0xFF = Error
    /// </summary>
    public byte Status;

    public readonly bool IsOk => Status == 0x00;
    public readonly bool IsBusy => Status == 0x01;
    public readonly bool IsError => Status == 0xFF;

    public override readonly string ToString() =>
        Status switch
        {
            0x00 => "OK",
            0x01 => "Busy",
            0xFF => "Error",
            _ => $"Unknown (0x{Status:X2})"
        };
}

/// <summary>
/// Status code de 4 bytes
/// Retornado por operações mais complexas
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct HS3Status4
{
    /// <summary>
    /// Código de status/erro detalhado
    /// </summary>
    public uint StatusCode;

    public readonly bool IsSuccess => StatusCode == 0;

    public override readonly string ToString() => $"0x{StatusCode:X8}";
}

/// <summary>
/// Transferência de dados bulk (48 bytes)
/// Observado em 8 operações durante inicialização
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 48)]
public struct HS3BulkData48
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
    public byte[] Data;

    public HS3BulkData48()
    {
        Data = new byte[48];
    }
}

/// <summary>
/// Transferência de dados bulk (64 bytes - USB max packet size)
/// Observado em 6 operações com latência crítica de ~2.5ms
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 64)]
public struct HS3BulkData64
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
    public byte[] Data;

    public HS3BulkData64()
    {
        Data = new byte[64];
    }
}

/// <summary>
/// Device info de 16 bytes
/// Observado em 4 operações durante inicialização
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 16)]
public struct HS3DeviceInfo16
{
    public ushort VendorId;           // 2 bytes
    public ushort ProductId;          // 2 bytes
    public uint SerialNumber;         // 4 bytes
    public ushort FirmwareVersion;    // 2 bytes
    public ushort HardwareRevision;   // 2 bytes
    public uint Reserved;             // 4 bytes

    public override readonly string ToString() =>
        $"VID: 0x{VendorId:X4}, PID: 0x{ProductId:X4}, " +
        $"Serial: {SerialNumber}, FW: {FirmwareVersion}, HW: {HardwareRevision}";
}

/// <summary>
/// Dados de configuração para IOCTL_CONFIG_QUERY
/// Input: 10 bytes, Output: 8 bytes
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 10)]
public struct HS3ConfigData
{
    /// <summary>
    /// Código de configuração (significado desconhecido)
    /// </summary>
    public ushort ConfigCode;

    /// <summary>
    /// Parâmetros de configuração
    /// TODO: Descobrir significado através de testes
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Parameters;

    public HS3ConfigData()
    {
        Parameters = new byte[8];
    }
}

#endregion

#region Command Codes (Hypothetical)

/// <summary>
/// Códigos de comando para IOCTL_READ_OPERATION / IOCTL_WRITE_OPERATION
/// NOTA: Valores hipotéticos - precisam ser validados com device real
/// </summary>
public static class HS3Commands
{
    // Comandos de status
    public const uint GET_STATUS = 0x00000001;
    public const uint GET_ERROR_CODE = 0x00000002;

    // Comandos do gerador de funções
    public const uint GET_FREQUENCY = 0x00000010;
    public const uint SET_FREQUENCY = 0x00000011;
    public const uint GET_AMPLITUDE = 0x00000020;
    public const uint SET_AMPLITUDE = 0x00000021;
    public const uint GET_WAVEFORM = 0x00000030;
    public const uint SET_WAVEFORM = 0x00000031;

    // Comandos de controle
    public const uint START_OUTPUT = 0x00000100;
    public const uint STOP_OUTPUT = 0x00000101;
    public const uint RESET_DEVICE = 0x000001FF;

    // Comandos de firmware
    public const uint GET_FIRMWARE_VERSION = 0x00001000;
    public const uint UPLOAD_FIRMWARE_CHUNK = 0x00001001;
}

#endregion
