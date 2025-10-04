using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte raio para diâmetro (raio * 2)
/// Usado para Width/Height de círculos no Canvas
/// </summary>
public class DiameterConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is double raio)
        {
            return raio * 2; // Raio 270 → Diâmetro 540
        }
        return 0.0;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is double diametro)
        {
            return diametro / 2; // Diâmetro 540 → Raio 270
        }
        return 0.0;
    }
}
