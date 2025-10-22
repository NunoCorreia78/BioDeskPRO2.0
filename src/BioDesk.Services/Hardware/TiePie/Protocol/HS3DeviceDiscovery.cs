using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Hardware.TiePie.Protocol;

/// <summary>
/// Discovery de dispositivos TiePie Handyscope HS3 via SetupDi APIs
/// Enumera dispositivos USB com VID=0x0E36, PID=0x0008
///
/// IMPORTANTE: SetupDi APIs são complexas mas NECESSÁRIAS para USB discovery.
/// Alternativas (WMI, LibUsbDotNet) são menos confiáveis para device paths.
///
/// Fluxo de discovery:
/// 1. SetupDiGetClassDevs() → Obter handle para device information set
/// 2. SetupDiEnumDeviceInterfaces() → Enumerar interfaces que correspondem ao GUID
/// 3. SetupDiGetDeviceInterfaceDetail() → Obter device path completo
/// 4. Filtrar por VID_0E36&PID_0008
/// 5. Retornar device path: \\?\usb#vid_0e36&pid_0008#...#{guid}
/// </summary>
public class HS3DeviceDiscovery : IDisposable
{
    private readonly ILogger<HS3DeviceDiscovery> _logger;
    private bool _disposed = false;

    #region SetupDi API Constants

    /// <summary>
    /// Flags para SetupDiGetClassDevs
    /// </summary>
    private const uint DIGCF_PRESENT = 0x00000002;          // Apenas dispositivos presentes
    private const uint DIGCF_DEVICEINTERFACE = 0x00000010;  // Retornar device interfaces (não devices)

    /// <summary>
    /// Handle inválido retornado por SetupDi APIs em caso de erro
    /// </summary>
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    /// <summary>
    /// Código de erro Win32: no more items
    /// </summary>
    private const int ERROR_NO_MORE_ITEMS = 259;

    /// <summary>
    /// Código de erro Win32: insufficient buffer
    /// </summary>
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    #endregion

    #region SetupDi API Structures

    /// <summary>
    /// Informação sobre device interface
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVICE_INTERFACE_DATA
    {
        public uint cbSize;
        public Guid InterfaceClassGuid;
        public uint Flags;
        public IntPtr Reserved;
    }

    /// <summary>
    /// Detalhes sobre device interface (inclui device path)
    /// Estrutura variável - device path segue a estrutura
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SP_DEVICE_INTERFACE_DETAIL_DATA
    {
        public uint cbSize;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string DevicePath;
    }

    /// <summary>
    /// Informação sobre device (usado para obter properties)
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA
    {
        public uint cbSize;
        public Guid ClassGuid;
        public uint DevInst;
        public IntPtr Reserved;
    }

    #endregion

    #region SetupDi API P/Invoke

    /// <summary>
    /// Obtém handle para device information set
    /// </summary>
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SetupDiGetClassDevs(
        ref Guid classGuid,
        [MarshalAs(UnmanagedType.LPWStr)] string? enumerator,
        IntPtr hwndParent,
        uint flags);

    /// <summary>
    /// Enumera device interfaces no information set
    /// </summary>
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiEnumDeviceInterfaces(
        IntPtr deviceInfoSet,
        IntPtr deviceInfoData,
        ref Guid interfaceClassGuid,
        uint memberIndex,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData);

    /// <summary>
    /// Obtém detalhes do device interface (incluindo device path)
    /// </summary>
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr deviceInfoSet,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData,
        ref SP_DEVICE_INTERFACE_DETAIL_DATA deviceInterfaceDetailData,
        uint deviceInterfaceDetailDataSize,
        out uint requiredSize,
        IntPtr deviceInfoData);

    /// <summary>
    /// Versão overload para obter tamanho necessário do buffer
    /// </summary>
    [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool SetupDiGetDeviceInterfaceDetail(
        IntPtr deviceInfoSet,
        ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData,
        IntPtr deviceInterfaceDetailData,
        uint deviceInterfaceDetailDataSize,
        out uint requiredSize,
        IntPtr deviceInfoData);

    /// <summary>
    /// Destrói device information set
    /// </summary>
    [DllImport("setupapi.dll", SetLastError = true)]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    #endregion

    #region Constructor & Dispose

    public HS3DeviceDiscovery(ILogger<HS3DeviceDiscovery> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _logger.LogDebug("HS3DeviceDiscovery inicializado");
    }

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
                // Cleanup managed resources (nenhum neste caso)
            }
            _disposed = true;
        }
    }

    #endregion

    #region Public Methods

    /// <summary>
    /// Procura dispositivos TiePie HS3 conectados
    /// </summary>
    /// <returns>Lista de device paths encontrados</returns>
    public List<string> FindHS3Devices()
    {
        var devices = new List<string>();

        _logger.LogInformation("Iniciando discovery de dispositivos HS3 (VID_0E36&PID_0008)...");

        // Obter device information set para GUID do HS3
        Guid deviceGuid = HS3Protocol.DEVICE_INTERFACE_GUID;
        IntPtr deviceInfoSet = SetupDiGetClassDevs(
            ref deviceGuid,
            null,
            IntPtr.Zero,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);

        if (deviceInfoSet == INVALID_HANDLE_VALUE)
        {
            var error = Marshal.GetLastWin32Error();
            _logger.LogError("SetupDiGetClassDevs falhou. Win32 Error: {Error} ({ErrorCode})",
                new Win32Exception(error).Message, error);
            return devices;
        }

        try
        {
            uint memberIndex = 0;

            // Enumerar todos os device interfaces
            while (true)
            {
                var deviceInterfaceData = new SP_DEVICE_INTERFACE_DATA
                {
                    cbSize = (uint)Marshal.SizeOf<SP_DEVICE_INTERFACE_DATA>()
                };

                // Enumerar próximo device interface
                bool success = SetupDiEnumDeviceInterfaces(
                    deviceInfoSet,
                    IntPtr.Zero,
                    ref deviceGuid,
                    memberIndex,
                    ref deviceInterfaceData);

                if (!success)
                {
                    var error = Marshal.GetLastWin32Error();
                    if (error == ERROR_NO_MORE_ITEMS)
                    {
                        // Fim da enumeração (esperado)
                        _logger.LogDebug("Enumeração completa. Total encontrado: {Count}", memberIndex);
                        break;
                    }

                    _logger.LogWarning("SetupDiEnumDeviceInterfaces falhou no index {Index}. Win32 Error: {Error}",
                        memberIndex, error);
                    memberIndex++;
                    continue;
                }

                // Obter device path
                string? devicePath = GetDeviceInterfaceDetail(deviceInfoSet, ref deviceInterfaceData);

                if (devicePath != null)
                {
                    _logger.LogDebug("Device encontrado: {Path}", devicePath);

                    // Verificar se é HS3 (VID_0E36 & PID_0008)
                    if (IsHS3Device(devicePath))
                    {
                        _logger.LogInformation("✅ TiePie HS3 encontrado: {Path}", devicePath);
                        devices.Add(devicePath);
                    }
                }

                memberIndex++;
            }
        }
        finally
        {
            // Sempre destruir device information set
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
        }

        if (devices.Count == 0)
        {
            _logger.LogWarning("❌ Nenhum dispositivo HS3 encontrado. Verificar:");
            _logger.LogWarning("   - HS3 está conectado via USB?");
            _logger.LogWarning("   - Drivers TiePie instalados?");
            _logger.LogWarning("   - Device Manager mostra HS3 corretamente?");
        }
        else
        {
            _logger.LogInformation("Discovery completo: {Count} dispositivo(s) HS3 encontrado(s)", devices.Count);
        }

        return devices;
    }

    /// <summary>
    /// Procura PRIMEIRO dispositivo HS3 conectado
    /// </summary>
    /// <returns>Device path ou null se não encontrado</returns>
    public string? FindFirstHS3Device()
    {
        var devices = FindHS3Devices();
        return devices.Count > 0 ? devices[0] : null;
    }

    #endregion

    #region Private Methods

    /// <summary>
    /// Obtém device path do device interface
    /// </summary>
    private string? GetDeviceInterfaceDetail(IntPtr deviceInfoSet, ref SP_DEVICE_INTERFACE_DATA deviceInterfaceData)
    {
        // PASSO 1: Obter tamanho necessário do buffer
        bool success = SetupDiGetDeviceInterfaceDetail(
            deviceInfoSet,
            ref deviceInterfaceData,
            IntPtr.Zero,
            0,
            out uint requiredSize,
            IntPtr.Zero);

        if (!success)
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ERROR_INSUFFICIENT_BUFFER)
            {
                _logger.LogWarning("SetupDiGetDeviceInterfaceDetail (tamanho) falhou. Win32 Error: {Error}", error);
                return null;
            }
        }

        // PASSO 2: Alocar buffer e obter detalhes
        var detailData = new SP_DEVICE_INTERFACE_DETAIL_DATA
        {
            // CRÍTICO: cbSize deve ser 8 em x64, 6 em x86 (tamanho da estrutura SEM string)
            cbSize = IntPtr.Size == 8 ? 8u : 6u,
            DevicePath = string.Empty
        };

        success = SetupDiGetDeviceInterfaceDetail(
            deviceInfoSet,
            ref deviceInterfaceData,
            ref detailData,
            requiredSize,
            out _,
            IntPtr.Zero);

        if (!success)
        {
            var error = Marshal.GetLastWin32Error();
            _logger.LogWarning("SetupDiGetDeviceInterfaceDetail (dados) falhou. Win32 Error: {Error}", error);
            return null;
        }

        return detailData.DevicePath;
    }

    /// <summary>
    /// Verifica se device path corresponde a TiePie HS3 (VID_0E36 & PID_0008)
    /// </summary>
    private bool IsHS3Device(string devicePath)
    {
        // Converter para uppercase para comparação case-insensitive
        string upperPath = devicePath.ToUpperInvariant();

        // Formato esperado: \\?\usb#vid_0e36&pid_0008#...
        bool hasVID = upperPath.Contains("VID_0E36");
        bool hasPID = upperPath.Contains("PID_0008");

        if (hasVID && hasPID)
        {
            _logger.LogTrace("Device path verificado como HS3: VID_0E36 & PID_0008 encontrados");
            return true;
        }

        _logger.LogTrace("Device path NÃO é HS3 (VID={VID}, PID={PID})", hasVID, hasPID);
        return false;
    }

    #endregion

    #region Utility Methods

    /// <summary>
    /// Valida se device path tem formato correto
    /// </summary>
    public static bool IsValidDevicePath(string? devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath))
            return false;

        // Deve começar com \\?\ ou \\.\
        return devicePath.StartsWith(@"\\?\", StringComparison.OrdinalIgnoreCase) ||
               devicePath.StartsWith(@"\\.\", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Extrai VID do device path (se presente)
    /// </summary>
    public static ushort? ExtractVID(string devicePath)
    {
        // Formato: ...vid_0e36&pid_...
        var match = System.Text.RegularExpressions.Regex.Match(
            devicePath,
            @"vid_([0-9a-f]{4})",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        if (match.Success && ushort.TryParse(match.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out ushort vid))
        {
            return vid;
        }

        return null;
    }

    /// <summary>
    /// Extrai PID do device path (se presente)
    /// </summary>
    public static ushort? ExtractPID(string devicePath)
    {
        // Formato: ...vid_xxxx&pid_0008...
        var match = System.Text.RegularExpressions.Regex.Match(
            devicePath,
            @"pid_([0-9a-f]{4})",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        if (match.Success && ushort.TryParse(match.Groups[1].Value, System.Globalization.NumberStyles.HexNumber, null, out ushort pid))
        {
            return pid;
        }

        return null;
    }

    /// <summary>
    /// Formata device path de forma legível para logs
    /// </summary>
    public static string FormatDevicePathForDisplay(string devicePath)
    {
        if (string.IsNullOrWhiteSpace(devicePath))
            return "(null)";

        // Extrair componentes interessantes
        var vid = ExtractVID(devicePath);
        var pid = ExtractPID(devicePath);

        if (vid.HasValue && pid.HasValue)
        {
            return $"VID_{vid.Value:X4}&PID_{pid.Value:X4} ({devicePath.Substring(0, Math.Min(50, devicePath.Length))}...)";
        }

        return devicePath.Length > 80 ? devicePath.Substring(0, 80) + "..." : devicePath;
    }

    #endregion
}
