using System;
using System.Runtime.InteropServices;

namespace BioDesk.Services.Hardware.TiePie.Protocol;

/// <summary>
/// Protocolo USB TiePie Handyscope HS3 - Constantes e Estruturas
/// Baseado em engenharia reversa via API Monitor (19/10/2025)
///
/// ATENÇÃO: Este código implementa comunicação USB DIRETA via DeviceIoControl.
/// NÃO usa hs3.dll do Inergetix CoRe (DLL obsoleta com validação defeituosa).
///
/// Sequência de inicialização obrigatória:
/// 1. OpenDevice() → CreateFile com device path USB
/// 2. GetDeviceInfo() → IOCTL 0x222000 (1024 bytes)
/// 3. ConfigureDevice() → IOCTL 0x222059 (10→8 bytes)
/// 4. SendCommand() → Loop de READ (0x222051) + WRITE (0x22204E)
/// </summary>
public static class HS3Protocol
{
    #region IOCTL Codes (descobertos via API Monitor)

    /// <summary>
    /// IOCTL para obter informações do dispositivo (1024 bytes)
    /// Primeira chamada após abrir device
    /// Input: 0 bytes, Output: 1024 bytes (HS3DeviceCapabilities)
    /// Latência observada: ~0.03ms
    /// </summary>
    public const uint IOCTL_GET_DEVICE_INFO = 0x222000;

    /// <summary>
    /// IOCTL para configuração inicial do dispositivo
    /// Segunda chamada após GET_DEVICE_INFO
    /// Input: 10 bytes (HS3ConfigData), Output: 8 bytes
    /// Latência observada: ~0.57ms
    /// </summary>
    public const uint IOCTL_CONFIG_QUERY = 0x222059;

    /// <summary>
    /// IOCTL para operações de leitura (query status)
    /// Usado em padrão alternado com WRITE_OPERATION
    /// Input: 4 bytes (command code), Output: 8 bytes (HS3Response8)
    /// Latência observada: ~0.1ms
    /// Frequência: 45× durante inicialização
    /// </summary>
    public const uint IOCTL_READ_OPERATION = 0x222051;

    /// <summary>
    /// IOCTL para operações de escrita/controle
    /// Usado em padrão alternado com READ_OPERATION
    /// Input: 4 bytes (command code), Output: 1-64 bytes (variável)
    /// Latência observada: 0.3ms (1B) até 2.5ms (64B - USB bulk transfer)
    /// Frequência: 33× durante inicialização
    /// </summary>
    public const uint IOCTL_WRITE_OPERATION = 0x22204E;

    #endregion

    #region USB Device Identifiers

    /// <summary>
    /// Vendor ID: TiePie Engineering
    /// Usado para device discovery via SetupDi APIs
    /// </summary>
    public const ushort USB_VENDOR_ID = 0x0E36;

    /// <summary>
    /// Product ID: Handyscope HS3
    /// Usado para device discovery via SetupDi APIs
    /// </summary>
    public const ushort USB_PRODUCT_ID = 0x0008;

    /// <summary>
    /// Device Interface GUID para TiePie HS3
    /// Usado para discovery via SetupDiGetClassDevs
    /// 
    /// ⚠️ ATENÇÃO: AMBOS GUIDs TESTADOS FALHAM (23/10/2025)
    /// - {f58af81e-4cdc-4d3f-b11e-0a89e4683972} → Error 2 (FILE_NOT_FOUND)
    /// - {AF43275C-FB24-4371-BAF8-2BA656FB33E6} → Error 2 (FILE_NOT_FOUND)
    /// 
    /// CAUSA: Driver HS3r.sys (kernel-mode) não expõe device interface.
    ///        CreateFile requer symbolic link (e.g., \\.\HS3) ainda não descoberto.
    /// 
    /// STATUS: BLOQUEADO - Ver BLOCKER_HS3_DEVICE_PATH_23OUT2025.md
    /// PRÓXIMO: Aguardar SDK TiePie Engineering
    /// </summary>
    public static readonly Guid DEVICE_INTERFACE_GUID =
        new Guid("{f58af81e-4cdc-4d3f-b11e-0a89e4683972}");

    /// <summary>
    /// Exemplo de device path USB descoberto:
    /// \\?\usb#vid_0e36&pid_0008#8&14447dc6&0&1#{f58af81e-4cdc-4d3f-b11e-0a89e4683972}
    /// </summary>
    public const string DEVICE_PATH_PATTERN = @"\\?\usb#vid_0e36&pid_0008#";

    #endregion

    #region Timing Constants (baseado em análise de logs)

    /// <summary>
    /// Timeout padrão para operações DeviceIoControl (ms)
    /// Baseado em latência média observada: 6.236ms + margem
    /// </summary>
    public const int DEFAULT_IOCTL_TIMEOUT_MS = 100;

    /// <summary>
    /// Timeout para operações bulk (64 bytes)
    /// Baseado em latência observada: 2.5-2.6ms + margem
    /// CRÍTICO: USB bulk transfers têm latência significativa
    /// </summary>
    public const int BULK_TRANSFER_TIMEOUT_MS = 50;

    /// <summary>
    /// Timeout para carregamento de firmware
    /// Baseado em tempo observado: ~65ms para 243KB + margem
    /// </summary>
    public const int FIRMWARE_LOAD_TIMEOUT_MS = 5000;

    /// <summary>
    /// Tamanho do chunk de firmware (bytes)
    /// Observado: 1948 leituras × 128 bytes = 249,344 bytes total
    /// </summary>
    public const int FIRMWARE_CHUNK_SIZE = 128;

    #endregion

    #region Buffer Sizes (descobertos via análise de logs)

    /// <summary>
    /// Tamanho do buffer de device capabilities
    /// Retornado por IOCTL_GET_DEVICE_INFO
    /// </summary>
    public const int DEVICE_INFO_BUFFER_SIZE = 1024;

    /// <summary>
    /// Tamanho típico de resposta READ_OPERATION
    /// </summary>
    public const int READ_RESPONSE_SIZE = 8;

    /// <summary>
    /// Tamanho máximo de resposta WRITE_OPERATION
    /// USB max packet size
    /// </summary>
    public const int WRITE_RESPONSE_MAX_SIZE = 64;

    /// <summary>
    /// Tamanho de comando (input para READ/WRITE)
    /// </summary>
    public const int COMMAND_SIZE = 4;

    /// <summary>
    /// Tamanho de config data para IOCTL_CONFIG_QUERY
    /// </summary>
    public const int CONFIG_DATA_SIZE = 10;

    #endregion
}

#region Data Structures (inferidas via análise de buffers)

/// <summary>
/// Capabilities do dispositivo HS3 (1024 bytes)
/// Retornado por IOCTL_GET_DEVICE_INFO (0x222000)
///
/// ATENÇÃO: Estrutura PARCIALMENTE inferida.
/// Campos além dos primeiros 64 bytes NÃO foram validados com hardware real.
/// Validar e ajustar quando conectar HS3 físico.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 1024)]
public struct HS3DeviceCapabilities
{
    // ===== Bytes 0-15: Identificação do dispositivo (VALIDADO) =====

    /// <summary>
    /// Vendor ID: 0x0E36 (TiePie Engineering)
    /// </summary>
    public ushort VendorId;

    /// <summary>
    /// Product ID: 0x0008 (Handyscope HS3)
    /// </summary>
    public ushort ProductId;

    /// <summary>
    /// Número de série único do dispositivo
    /// </summary>
    public uint SerialNumber;

    /// <summary>
    /// Versão firmware (formato: major.minor)
    /// </summary>
    public ushort FirmwareVersion;

    /// <summary>
    /// Revisão hardware
    /// </summary>
    public ushort HardwareRevision;

    /// <summary>
    /// Reservado/Padding
    /// </summary>
    public uint Reserved1;

    // ===== Bytes 16-63: Configurações do gerador (HIPOTÉTICO - VALIDAR) =====

    /// <summary>
    /// Frequência mínima suportada (Hz)
    /// VALIDAR: Valor pode não estar neste offset
    /// </summary>
    public double MinFrequency;

    /// <summary>
    /// Frequência máxima suportada (Hz)
    /// VALIDAR: Valor pode não estar neste offset
    /// </summary>
    public double MaxFrequency;

    /// <summary>
    /// Amplitude mínima suportada (V)
    /// VALIDAR: Valor pode não estar neste offset
    /// </summary>
    public double MinAmplitude;

    /// <summary>
    /// Amplitude máxima suportada (V)
    /// VALIDAR: Valor pode não estar neste offset
    /// </summary>
    public double MaxAmplitude;

    /// <summary>
    /// Bitmask de waveforms suportados
    /// VALIDAR: Formato e valores possíveis
    /// </summary>
    public uint SupportedWaveforms;

    /// <summary>
    /// Número de canais (esperado: 1 para HS3)
    /// VALIDAR: Confirmar valor
    /// </summary>
    public uint ChannelCount;

    // ===== Bytes 64-1023: Dados adicionais (NÃO PARSEADOS) =====

    /// <summary>
    /// Dados raw não interpretados
    /// TODO: Analisar com hardware real para identificar campos úteis
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 960)]
    public byte[] RawData;

    /// <summary>
    /// Verifica se é um dispositivo HS3 válido
    /// </summary>
    public readonly bool IsValidHS3Device() =>
        VendorId == HS3Protocol.USB_VENDOR_ID &&
        ProductId == HS3Protocol.USB_PRODUCT_ID;

    /// <summary>
    /// Retorna identificador do dispositivo (VID_xxxx&PID_xxxx)
    /// </summary>
    public readonly string GetDeviceId() =>
        $"VID_{VendorId:X4}&PID_{ProductId:X4}";

    public override readonly string ToString() =>
        $"HS3 Device: {GetDeviceId()}, Serial: {SerialNumber}, " +
        $"FW: {FirmwareVersion}, HW: {HardwareRevision}";
}

/// <summary>
/// Resposta padrão de 8 bytes para IOCTL_READ_OPERATION
/// Estrutura union (pode ser interpretada de múltiplas formas)
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
        $"Double: {ValueAsDouble:F6}, Long: {ValueAsLong}, " +
        $"DWords: 0x{LowDWord:X8} 0x{HighDWord:X8}";
}

/// <summary>
/// Status flag de 1 byte
/// Retornado por algumas operações WRITE_OPERATION
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 1)]
public struct HS3StatusByte
{
    /// <summary>
    /// Status code: 0x00 = OK, 0x01 = Busy, 0xFF = Error
    /// VALIDAR: Estes valores são hipotéticos
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
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 4)]
public struct HS3Status4
{
    /// <summary>
    /// Código de status/erro detalhado
    /// VALIDAR: Mapear códigos de erro reais
    /// </summary>
    public uint StatusCode;

    public readonly bool IsSuccess => StatusCode == 0;

    public override readonly string ToString() => $"0x{StatusCode:X8}";
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
/// Dados de configuração para IOCTL_CONFIG_QUERY
/// Input: 10 bytes, Output: 8 bytes
///
/// ATENÇÃO: Estrutura HIPOTÉTICA - valores corretos desconhecidos.
/// TODO: Descobrir via tentativa/erro com hardware real.
/// </summary>
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 10)]
public struct HS3ConfigData
{
    /// <summary>
    /// Código de configuração (significado desconhecido)
    /// VALIDAR: Testar com valores 0x0000, 0x0001, etc.
    /// </summary>
    public ushort ConfigCode;

    /// <summary>
    /// Parâmetros de configuração
    /// VALIDAR: Significado e valores corretos
    /// </summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
    public byte[] Parameters;

    public HS3ConfigData()
    {
        ConfigCode = 0x0001; // Valor padrão hipotético
        Parameters = new byte[8];
    }

    /// <summary>
    /// Cria config data com valores zero (seguro para teste inicial)
    /// </summary>
    public static HS3ConfigData CreateDefault() => new HS3ConfigData
    {
        ConfigCode = 0x0000,
        Parameters = new byte[8]
    };
}

#endregion

#region Command Codes (HIPOTÉTICOS - VALIDAR COM HARDWARE)

/// <summary>
/// Códigos de comando para IOCTL_READ_OPERATION / IOCTL_WRITE_OPERATION
///
/// ATENÇÃO CRÍTICA: Estes valores são COMPLETAMENTE HIPOTÉTICOS.
/// NÃO foram observados nos logs do API Monitor.
///
/// TODO URGENTE: Descobrir comandos reais via:
/// 1. Análise de firmware hs3f12.hex (reverse engineering)
/// 2. Tentativa/erro com hardware físico
/// 3. Comparação com SDK libtiepie oficial (se disponível)
/// 4. Captura de tráfego USB raw (USBPcap/Wireshark)
/// </summary>
public static class HS3Commands
{
    // ===== Comandos de status (hipotéticos) =====
    public const uint GET_STATUS = 0x00000001;
    public const uint GET_ERROR_CODE = 0x00000002;

    // ===== Comandos do gerador de funções (hipotéticos) =====
    public const uint GET_FREQUENCY = 0x00000010;
    public const uint SET_FREQUENCY = 0x00000011;
    public const uint GET_AMPLITUDE = 0x00000020;
    public const uint SET_AMPLITUDE = 0x00000021;
    public const uint GET_WAVEFORM = 0x00000030;
    public const uint SET_WAVEFORM = 0x00000031;

    // ===== Comandos de controle (hipotéticos) =====
    public const uint START_OUTPUT = 0x00000100;
    public const uint STOP_OUTPUT = 0x00000101;
    public const uint RESET_DEVICE = 0x000001FF;

    // ===== Comandos de firmware (hipotéticos) =====
    public const uint GET_FIRMWARE_VERSION = 0x00001000;
    public const uint UPLOAD_FIRMWARE_CHUNK = 0x00001001;

    /// <summary>
    /// IMPORTANTE: Usar este método para validar se comando é conhecido
    /// Retorna false para comandos não implementados
    /// </summary>
    public static bool IsValidCommand(uint command)
    {
        // TODO: Implementar validação após descobrir comandos reais
        return command != 0;
    }
}

#endregion
