using System;
using System.Runtime.InteropServices;

namespace BioDesk.Services.Hardware.TiePie;

/// <summary>
/// P/Invoke wrapper para hs3.dll (Inergetix CoRe Wrapper)
/// ATENÇÃO: Esta DLL é um wrapper proprietário do Inergetix CoRe,
/// NÃO é o SDK oficial libtiepie.dll da TiePie Engineering!
///
/// API descoberta via pefile - 18/10/2025
/// </summary>
internal static class HS3Native
{
    private const string HS3_DLL = "hs3.dll";

    #region Enums

    /// <summary>
    /// Tipos de sinal suportados pelo HS3
    /// NOTA: Valores empíricos - podem precisar ajuste
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

    #endregion

    #region Inicialização e Dispositivo (API Inergetix)

    /// <summary>
    /// Inicializa o instrumento HS3 (API Inergetix).
    /// Substitui LibInit() do SDK oficial.
    /// </summary>
    /// <returns>Handle do dispositivo ou 0 se falha</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "InitInstrument")]
    public static extern int InitInstrument();

    /// <summary>
    /// Finaliza o instrumento (API Inergetix).
    /// Substitui LibExit() + DevClose() do SDK oficial.
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "ExitInstrument")]
    public static extern void ExitInstrument();

    /// <summary>
    /// Obtém o número de série do dispositivo (API Inergetix).
    /// </summary>
    /// <returns>Número de série</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetSerialNumber")]
    public static extern uint GetSerialNumber();

    #endregion

    #region Configuração do Gerador (API Inergetix)

    /// <summary>
    /// Define a frequência do gerador de funções.
    /// </summary>
    /// <param name="frequencyHz">Frequência em Hz</param>
    /// <returns>0 se sucesso, código de erro caso contrário</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetFuncGenFrequency")]
    public static extern int SetFuncGenFrequency(double frequencyHz);

    /// <summary>
    /// Obtém a frequência atual do gerador.
    /// </summary>
    /// <returns>Frequência em Hz</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFuncGenFrequency")]
    public static extern double GetFuncGenFrequency();

    /// <summary>
    /// Define a amplitude do gerador de funções.
    /// </summary>
    /// <param name="amplitudeVolts">Amplitude em Volts (0-10V típico)</param>
    /// <returns>0 se sucesso, código de erro caso contrário</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetFuncGenAmplitude")]
    public static extern int SetFuncGenAmplitude(double amplitudeVolts);

    /// <summary>
    /// Obtém a amplitude atual.
    /// </summary>
    /// <returns>Amplitude em Volts</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFuncGenAmplitude")]
    public static extern double GetFuncGenAmplitude();

    /// <summary>
    /// Define o tipo de sinal (waveform).
    /// </summary>
    /// <param name="signalType">Tipo de sinal (0=Sine, 1=Triangle, 2=Square, etc)</param>
    /// <returns>0 se sucesso, código de erro caso contrário</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetFuncGenSignalType")]
    public static extern int SetFuncGenSignalType(int signalType);

    /// <summary>
    /// Obtém o tipo de sinal atual.
    /// </summary>
    /// <returns>Código do tipo de sinal</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFuncGenSignalType")]
    public static extern int GetFuncGenSignalType();

    /// <summary>
    /// Define o offset DC do sinal.
    /// </summary>
    /// <param name="offsetVolts">Offset em Volts</param>
    /// <returns>0 se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetFuncGenDCOffset")]
    public static extern int SetFuncGenDCOffset(double offsetVolts);

    /// <summary>
    /// Obtém o offset DC atual.
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFuncGenDCOffset")]
    public static extern double GetFuncGenDCOffset();

    /// <summary>
    /// Define a simetria do sinal (duty cycle para square wave).
    /// </summary>
    /// <param name="symmetryPercent">Simetria em % (0-100)</param>
    /// <returns>0 se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetFuncGenSymmetry")]
    public static extern int SetFuncGenSymmetry(double symmetryPercent);

    /// <summary>
    /// Obtém a simetria atual.
    /// </summary>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFuncGenSymmetry")]
    public static extern double GetFuncGenSymmetry();

    #endregion

    #region Controle de Emissão (API Inergetix)

    /// <summary>
    /// Ativa ou desativa a saída do gerador.
    /// CRÍTICO: Deve ser chamado ANTES de iniciar/parar emissão.
    /// </summary>
    /// <param name="enable">true para ativar, false para desativar</param>
    /// <returns>0 se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetFuncGenOutputOn")]
    public static extern int SetFuncGenOutputOn([MarshalAs(UnmanagedType.Bool)] bool enable);

    /// <summary>
    /// Verifica se a saída está ativa.
    /// </summary>
    /// <returns>true se ativa</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFuncGenOutputOn")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFuncGenOutputOn();

    /// <summary>
    /// Ativa/desativa o gerador de funções.
    /// </summary>
    /// <param name="enable">true para ativar</param>
    /// <returns>0 se sucesso</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "SetFuncGenEnable")]
    public static extern int SetFuncGenEnable([MarshalAs(UnmanagedType.Bool)] bool enable);

    /// <summary>
    /// Verifica se o gerador está ativo.
    /// </summary>
    /// <returns>true se ativo</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFuncGenEnable")]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFuncGenEnable();

    /// <summary>
    /// Obtém o status do gerador de funções.
    /// </summary>
    /// <returns>Código de status (significado desconhecido)</returns>
    [DllImport(HS3_DLL, CallingConvention = CallingConvention.StdCall, EntryPoint = "GetFunctionGenStatus")]
    public static extern int GetFunctionGenStatus();

    #endregion

    #region Funções Auxiliares (Não Mapeadas - Documentação)

    // As seguintes funções existem na DLL mas não são usadas nesta implementação:
    // - ADC_* (funções de aquisição - não necessárias para emissão)
    // - DoMeasure, GetMeasurement*, etc (medições - fora de escopo)
    // - I2C* (comunicação I2C - baixo nível)
    // - SetDigitalOutputs, GetDigitalInputValues (GPIO - não usado)
    // - FuncGenBurst (modo burst - feature avançada)
    // - FillFuncGenMemory (arbitrary waveform - não implementado)
    // - SetTrigger*, GetTrigger* (trigger modes - não necessário)
    // - SetPXITrigger* (PXI backplane - hardware específico)

    #endregion
}
