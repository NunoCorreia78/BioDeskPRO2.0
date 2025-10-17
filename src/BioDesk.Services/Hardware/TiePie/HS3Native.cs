using System;
using System.Runtime.InteropServices;

namespace BioDesk.Services.Hardware.TiePie;

/// <summary>
/// P/Invoke wrapper para hs3.dll (TiePie Handyscope HS3)
/// Baseado em hs3.dll v2.90 da TiePie Engineering
/// </summary>
internal static class HS3Native
{
    private const string HS3_DLL = "hs3.dll";

    #region Enums

    /// <summary>
    /// Tipos de sinal suportados pelo HS3
    /// </summary>
    public enum SignalType : int
    {
        Sine = 0,      // Sinusoidal
        Triangle = 1,  // Triangular
        Square = 2,    // Quadrada
        DC = 3,        // Corrente contínua
        Noise = 4,     // Ruído
        Arbitrary = 5, // Arbitrária
        Pulse = 6      // Pulso
    }

    /// <summary>
    /// Modos de frequência
    /// </summary>
    public enum FrequencyMode : int
    {
        SignalFrequency = 0, // Frequência do sinal
        SampleFrequency = 1  // Frequência de amostragem
    }

    #endregion

    #region Inicialização e Dispositivo

    /// <summary>
    /// Inicializa a biblioteca HS3
    /// </summary>
    /// <returns>true se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LibInit();

    /// <summary>
    /// Finaliza a biblioteca HS3
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern void LibExit();

    /// <summary>
    /// Atualiza a lista de dispositivos
    /// </summary>
    /// <returns>Número de dispositivos encontrados</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern int LstUpdate();

    /// <summary>
    /// Retorna o número de dispositivos disponíveis
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern int LstGetCount();

    /// <summary>
    /// Abre um dispositivo
    /// </summary>
    /// <param name="dwDeviceType">Tipo de dispositivo</param>
    /// <param name="dwSerialNumber">Número de série (0 = primeiro disponível)</param>
    /// <returns>Handle do dispositivo ou 0 se erro</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern IntPtr LstOpenDevice(uint dwDeviceType, uint dwSerialNumber);

    /// <summary>
    /// Fecha um dispositivo
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern void DevClose(IntPtr hDevice);

    #endregion

    #region Configuração do Gerador

    /// <summary>
    /// Define a frequência do sinal
    /// </summary>
    /// <param name="hDevice">Handle do dispositivo</param>
    /// <param name="dFrequency">Frequência em Hz</param>
    /// <returns>Frequência real configurada</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern double GenSetFrequency(IntPtr hDevice, double dFrequency);

    /// <summary>
    /// Obtém a frequência atual
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern double GenGetFrequency(IntPtr hDevice);

    /// <summary>
    /// Define a amplitude do sinal
    /// </summary>
    /// <param name="hDevice">Handle do dispositivo</param>
    /// <param name="dAmplitude">Amplitude em Volts (0-10V)</param>
    /// <returns>Amplitude real configurada</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern double GenSetAmplitude(IntPtr hDevice, double dAmplitude);

    /// <summary>
    /// Obtém a amplitude atual
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern double GenGetAmplitude(IntPtr hDevice);

    /// <summary>
    /// Define o tipo de sinal
    /// </summary>
    /// <param name="hDevice">Handle do dispositivo</param>
    /// <param name="dwSignalType">Tipo de sinal (0=Sine, 1=Triangle, 2=Square, etc)</param>
    /// <returns>Tipo de sinal real configurado</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern uint GenSetSignalType(IntPtr hDevice, uint dwSignalType);

    /// <summary>
    /// Obtém o tipo de sinal atual
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern uint GenGetSignalType(IntPtr hDevice);

    /// <summary>
    /// Define o modo de frequência
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern uint GenSetFrequencyMode(IntPtr hDevice, uint dwFrequencyMode);

    /// <summary>
    /// Ativa/desativa a saída do gerador
    /// </summary>
    /// <param name="hDevice">Handle do dispositivo</param>
    /// <param name="bEnable">true para ativar, false para desativar</param>
    /// <returns>true se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GenSetOutputOn(IntPtr hDevice, [MarshalAs(UnmanagedType.Bool)] bool bEnable);

    /// <summary>
    /// Verifica se a saída está ativa
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GenGetOutputOn(IntPtr hDevice);

    #endregion

    #region Controle de Emissão

    /// <summary>
    /// Inicia a geração de sinal
    /// </summary>
    /// <param name="hDevice">Handle do dispositivo</param>
    /// <returns>true se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GenStart(IntPtr hDevice);

    /// <summary>
    /// Para a geração de sinal
    /// </summary>
    /// <param name="hDevice">Handle do dispositivo</param>
    /// <returns>true se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GenStop(IntPtr hDevice);

    #endregion

    #region Informações do Dispositivo

    /// <summary>
    /// Obtém o número de série do dispositivo
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern uint DevGetSerialNumber(IntPtr hDevice);

    /// <summary>
    /// Obtém a versão do firmware
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall)]
    public static extern uint DevGetFirmwareVersion(IntPtr hDevice);

    #endregion
}
