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
            // Offset = Centro - Raio
            // Raio vem do binding Width/Height / 2
            // Simplificado: retorna centro (ajuste no binding)
            return centro;
        }
        return 300.0; // Centro padrão canvas 600x600
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
