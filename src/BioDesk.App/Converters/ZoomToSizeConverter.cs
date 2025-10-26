using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte nível de zoom em tamanho proporcional para elementos UI.
/// Usado para escalar marcas de íris dinamicamente com o zoom.
/// </summary>
public class ZoomToSizeConverter : IValueConverter
{
    /// <summary>
    /// Tamanho base em pixels quando zoom = 1.0
    /// </summary>
    public double BaseSize { get; set; } = 24.0;

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is double zoom && zoom > 0)
        {
            // 24px base * zoom 5.0 = 120px visual (sempre visível)
            return BaseSize * zoom;
        }
        return BaseSize;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException("ZoomToSizeConverter não suporta conversão bidirecional.");
    }
}
