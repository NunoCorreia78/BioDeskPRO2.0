using System;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Configuração global da clínica (sempre Id = 1)
/// Armazena dados institucionais e caminho para logo
/// </summary>
public class ConfiguracaoClinica
{
    /// <summary>
    /// Id fixo = 1 (apenas uma configuração por instalação)
    /// </summary>
    public int Id { get; set; } = 1;

    /// <summary>
    /// Nome da clínica (ex: "Clínica de Naturopatia Dr. Silva")
    /// </summary>
    public string NomeClinica { get; set; } = "Minha Clínica";

    /// <summary>
    /// Morada completa da clínica
    /// </summary>
    public string? Morada { get; set; }

    /// <summary>
    /// Telefone da clínica (formato: +351 912 345 678)
    /// </summary>
    public string? Telefone { get; set; }

    /// <summary>
    /// Email institucional da clínica
    /// </summary>
    public string? Email { get; set; }

    /// <summary>
    /// Número de Identificação de Pessoa Coletiva (NIPC)
    /// </summary>
    public string? NIPC { get; set; }

    /// <summary>
    /// Caminho absoluto para ficheiro do logo da clínica (.png/.jpg)
    /// Null se ainda não foi definido
    /// </summary>
    public string? LogoPath { get; set; }

    /// <summary>
    /// Data da última atualização dos dados
    /// </summary>
    public DateTime DataAtualizacao { get; set; } = DateTime.Now;

    // ==================== CONFIGURAÇÕES DE TERAPIA ====================

    /// <summary>
    /// Modo Informacional padrão para novas terapias
    /// True = aplicar sem equipamento (radiônico)
    /// False = aplicar com equipamento físico (TiePie HS3)
    /// </summary>
    public bool ModoInformacionalPadrao { get; set; } = false;

    /// <summary>
    /// Voltagem padrão para terapias físicas (V)
    /// Range: 0.1V - 10V
    /// </summary>
    public double VoltageemPadraoV { get; set; } = 5.0;

    /// <summary>
    /// Corrente máxima padrão para terapias físicas (mA)
    /// Range: 1mA - 100mA
    /// </summary>
    public double CorrenteMaxPadraoma { get; set; } = 50.0;

    /// <summary>
    /// Duração uniforme padrão por frequência (segundos)
    /// Opções típicas: 5, 10, 15 segundos
    /// </summary>
    public int DuracaoUniformePadraoSegundos { get; set; } = 10;

    /// <summary>
    /// Alvo de melhoria padrão para auto-stop (%)
    /// Range: 0-100, típico: 95%
    /// </summary>
    public double AlvoMelhoriaPadraoPercent { get; set; } = 95.0;

    // ==================== CONFIGURAÇÕES POR TIPO DE TERAPIA ====================

    /// <summary>
    /// Configurações específicas para Terapias de Programas (serializado JSON).
    /// Armazena TerapiaSettings com FormaOnda, Voltagem, Amplitude, Duração, etc.
    /// </summary>
    public string? TerapiaProgramasSettingsJson { get; set; }

    /// <summary>
    /// Configurações específicas para Terapias Ressonantes (serializado JSON).
    /// </summary>
    public string? TerapiaRessonantesSettingsJson { get; set; }

    /// <summary>
    /// Configurações específicas para Terapias de Biofeedback (serializado JSON).
    /// </summary>
    public string? TerapiaBiofeedbackSettingsJson { get; set; }
}
