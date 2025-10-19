using System;
using System.Runtime.InteropServices;

namespace BioDesk.Services.Hardware.TiePie;

/// <summary>
/// FUNÇÕES ADICIONAIS da hs3.dll que podem validar conexão física
/// Descoberta via tentativa/erro baseado em padrões comuns de APIs de hardware
/// </summary>
internal static class HS3NativeExtended
{
    private const string HS3_DLL = "hs3.dll";

    // === FUNÇÕES CANDIDATAS PARA VALIDAÇÃO DE CONEXÃO ===

    /// <summary>
    /// Possível função para verificar se dispositivo está conectado
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "IsDeviceConnected")]
    public static extern bool IsDeviceConnected();

    /// <summary>
    /// Possível função para obter status da conexão
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetConnectionStatus")]
    public static extern int GetConnectionStatus();

    /// <summary>
    /// Possível função para validar hardware presente
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "CheckHardware")]
    public static extern bool CheckHardware();

    /// <summary>
    /// Possível função para obter número de dispositivos conectados
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetDeviceCount")]
    public static extern int GetDeviceCount();

    /// <summary>
    /// Teste seguro de função - chama e captura exceção se não existir
    /// </summary>
    public static bool TryCall_IsDeviceConnected(out bool result, out string error)
    {
        try
        {
            result = IsDeviceConnected();
            error = string.Empty;
            return true;
        }
        catch (EntryPointNotFoundException ex)
        {
            result = false;
            error = $"Função IsDeviceConnected não existe: {ex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            result = false;
            error = $"Erro ao chamar IsDeviceConnected: {ex.Message}";
            return false;
        }
    }

    public static bool TryCall_GetConnectionStatus(out int result, out string error)
    {
        try
        {
            result = GetConnectionStatus();
            error = string.Empty;
            return true;
        }
        catch (EntryPointNotFoundException ex)
        {
            result = -1;
            error = $"Função GetConnectionStatus não existe: {ex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            result = -1;
            error = $"Erro ao chamar GetConnectionStatus: {ex.Message}";
            return false;
        }
    }

    public static bool TryCall_CheckHardware(out bool result, out string error)
    {
        try
        {
            result = CheckHardware();
            error = string.Empty;
            return true;
        }
        catch (EntryPointNotFoundException ex)
        {
            result = false;
            error = $"Função CheckHardware não existe: {ex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            result = false;
            error = $"Erro ao chamar CheckHardware: {ex.Message}";
            return false;
        }
    }

    public static bool TryCall_GetDeviceCount(out int result, out string error)
    {
        try
        {
            result = GetDeviceCount();
            error = string.Empty;
            return true;
        }
        catch (EntryPointNotFoundException ex)
        {
            result = 0;
            error = $"Função GetDeviceCount não existe: {ex.Message}";
            return false;
        }
        catch (Exception ex)
        {
            result = 0;
            error = $"Erro ao chamar GetDeviceCount: {ex.Message}";
            return false;
        }
    }
}
