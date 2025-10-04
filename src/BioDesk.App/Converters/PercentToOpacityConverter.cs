using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte valor percentual (0-100) para opacidade WPF (0.0-1.0)
/// </summary>
public class PercentToOpacityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is double percentual)
        {
            return percentual / 100.0; // 50% → 0.5
        }
        return 0.5; // Padrão: 50% opacidade
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is double opacity)
        {
            return opacity * 100.0; // 0.5 → 50%
        }
        return 50.0;
    }
}
