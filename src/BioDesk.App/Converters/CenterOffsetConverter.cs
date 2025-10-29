using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte posição do centro para offset de Canvas
/// Canvas.Left = Centro - Raio (para centralizar círculo)
/// </summary>
public class CenterOffsetConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is double centro)
        {
            // Aplicar offset do ConverterParameter para centrar elemento
            double offset = 0.0;
            if (parameter is string paramStr && double.TryParse(paramStr, out offset))
            {
                return centro + offset;
            }
            return centro;
        }
        return 700.0; // Centro padrão canvas 1400x1400
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
