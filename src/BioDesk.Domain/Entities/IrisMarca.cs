using System;

namespace BioDesk.Domain.Entities;

/// <summary>
/// Representa uma marca/anotação sobre uma imagem de íris
/// </summary>
public class IrisMarca
{
    public int Id { get; set; }

    /// <summary>
    /// ID da imagem (FK para IrisImagem)
    /// </summary>
    public int IrisImagemId { get; set; }

    /// <summary>
    /// Coordenada X da marca (pixels)
    /// </summary>
    public double X { get; set; }

    /// <summary>
    /// Coordenada Y da marca (pixels)
    /// </summary>
    public double Y { get; set; }

    /// <summary>
    /// Tipo de marca: "Anomalia", "Ponto de Interesse", "Área Crítica", etc.
    /// </summary>
    public string Tipo { get; set; } = string.Empty;

    /// <summary>
    /// Cor da marca em formato hexadecimal (ex: "#FF0000" para vermelho)
    /// </summary>
    public string Cor { get; set; } = "#FF0000"; // Vermelho default

    /// <summary>
    /// Observações sobre a marca (opcional)
    /// </summary>
    public string? Observacoes { get; set; }

    /// <summary>
    /// Data de criação da marca
    /// </summary>
    public DateTime DataCriacao { get; set; }

    // Navegação
    public virtual IrisImagem? IrisImagem { get; set; }
}
