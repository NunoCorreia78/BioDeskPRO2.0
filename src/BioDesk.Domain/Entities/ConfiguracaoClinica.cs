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
}
