using BioDesk.Domain.Enums;

namespace BioDesk.Domain.Models;

/// <summary>
/// Configurações para aplicação de terapias bioenergéticas.
/// Pode ser específico para cada tipo de terapia (Programas, Ressonantes, Biofeedback).
/// </summary>
public class TerapiaSettings
{
    /// <summary>
    /// Tipo de terapia a que estas configurações se aplicam.
    /// </summary>
    public TipoTerapia? Tipo { get; set; }
    /// <summary>
    /// Modo Informacional: aplica terapia SEM equipamento físico (TiePie HS3)
    /// Conceito radiônico - emissão por intenção apenas
    /// Default: false (modo físico - requer hardware conectado)
    /// </summary>
    public bool ModoInformacional { get; set; } = false;

    /// <summary>
    /// Voltagem a aplicar (modo físico apenas)
    /// Range: 0.1V - 10V
    /// </summary>
    public double VoltagemV { get; set; } = 5.0;

    /// <summary>
    /// Corrente máxima permitida em mA (modo físico apenas)
    /// Range: 1mA - 100mA
    /// </summary>
    public double CorrenteMaxMa { get; set; } = 50.0;

    /// <summary>
    /// Duração uniforme por frequência em segundos
    /// Todas as frequências na fila terão esta duração
    /// </summary>
    public int DuracaoUniformeSegundos { get; set; } = 10;

    /// <summary>
    /// Forma de onda do sinal elétrico.
    /// </summary>
    public FormaOnda FormaOnda { get; set; } = FormaOnda.Seno;

    /// <summary>
    /// Amplitude do sinal em percentagem (10-100%).
    /// Controla a intensidade relativa do sinal.
    /// </summary>
    public double AmplitudePercent { get; set; } = 85.0;

    /// <summary>
    /// Duração total máxima da sessão em minutos.
    /// Sessão para automaticamente após este tempo.
    /// </summary>
    public int DuracaoTotalMinutos { get; set; } = 30;

    /// <summary>
    /// Canal de saída do gerador (modo físico apenas)
    /// Channel1 ou Channel2
    /// </summary>
    public string CanalSaida { get; set; } = "Channel1";

    /// <summary>
    /// Auto-parar quando atingir % de melhoria
    /// Default: 95%
    /// </summary>
    public double AlvoMelhoriaPercent { get; set; } = 95.0;

    /// <summary>
    /// Criar snapshot do estado atual.
    /// </summary>
    public TerapiaSettings Clone()
    {
        return new TerapiaSettings
        {
            Tipo = this.Tipo,
            ModoInformacional = this.ModoInformacional,
            VoltagemV = this.VoltagemV,
            CorrenteMaxMa = this.CorrenteMaxMa,
            DuracaoUniformeSegundos = this.DuracaoUniformeSegundos,
            FormaOnda = this.FormaOnda,
            AmplitudePercent = this.AmplitudePercent,
            DuracaoTotalMinutos = this.DuracaoTotalMinutos,
            CanalSaida = this.CanalSaida,
            AlvoMelhoriaPercent = this.AlvoMelhoriaPercent
        };
    }

    /// <summary>
    /// Retorna configurações padrão para um tipo de terapia específico.
    /// </summary>
    public static TerapiaSettings GetDefault(TipoTerapia tipo)
    {
        return tipo switch
        {
            TipoTerapia.Programas => new TerapiaSettings
            {
                Tipo = TipoTerapia.Programas,
                FormaOnda = FormaOnda.Quadrada,
                VoltagemV = 8.0,
                AmplitudePercent = 90.0,
                DuracaoUniformeSegundos = 10,
                DuracaoTotalMinutos = 30
            },
            TipoTerapia.Ressonantes => new TerapiaSettings
            {
                Tipo = TipoTerapia.Ressonantes,
                FormaOnda = FormaOnda.Seno,
                VoltagemV = 3.0,
                AmplitudePercent = 60.0,
                DuracaoUniformeSegundos = 15,
                DuracaoTotalMinutos = 45
            },
            TipoTerapia.Biofeedback => new TerapiaSettings
            {
                Tipo = TipoTerapia.Biofeedback,
                FormaOnda = FormaOnda.Triangular,
                VoltagemV = 5.0,
                AmplitudePercent = 75.0,
                DuracaoUniformeSegundos = 10,
                DuracaoTotalMinutos = 30
            },
            _ => new TerapiaSettings { Tipo = tipo }
        };
    }
}
