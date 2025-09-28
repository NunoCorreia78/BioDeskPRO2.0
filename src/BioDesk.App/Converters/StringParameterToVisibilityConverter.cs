using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converter para mostrar elemento baseado numa string específica com parâmetro
/// Usado para mostrar campos de data personalizada apenas quando filtro = "Personalizado"
/// </summary>
public class StringParameterToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string stringValue && parameter is string targetValue)
        {
            return string.Equals(stringValue, targetValue, StringComparison.OrdinalIgnoreCase) 
                ? Visibility.Visible 
                : Visibility.Collapsed;
        }
        
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}