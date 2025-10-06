using System.Collections.Generic;

namespace BioDesk.Domain.Models;

/// <summary>
/// Representa um ponto 2D simples (sem dependência WPF)
/// </summary>
public struct SimplePoint
{
    public double X { get; set; }
    public double Y { get; set; }

    public SimplePoint(double x, double y)
    {
        X = x;
        Y = y;
    }
}

/// <summary>
/// Modelo para representar um stroke (traço) desenhado na ferramenta de desenho
/// </summary>
public class StrokeModel
{
    /// <summary>
    /// Lista de pontos que compõem o stroke
    /// </summary>
    public List<SimplePoint> Points { get; set; } = new();

    /// <summary>
    /// Cor do stroke em formato hexadecimal (#RRGGBB)
    /// </summary>
    public string Color { get; set; } = "#C85959";

    /// <summary>
    /// Espessura do stroke em pixels
    /// </summary>
    public double Thickness { get; set; } = 2.0;

    /// <summary>
    /// Construtor vazio
    /// </summary>
    public StrokeModel()
    {
    }

    /// <summary>
    /// Construtor com parâmetros
    /// </summary>
    public StrokeModel(string color, double thickness)
    {
        Color = color;
        Thickness = thickness;
    }
}
