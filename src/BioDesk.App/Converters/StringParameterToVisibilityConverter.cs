using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converter para mostrar elemento baseado numa string específica ou número com parâmetro
/// Usado para mostrar campos de data personalizada apenas quando filtro = "Personalizado"
/// Também usado para mostrar abas baseado no número da aba ativa
/// </summary>
public class StringParameterToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (parameter is string targetValue)
        {
            string? valueAsString = value?.ToString();
            bool isMatch = string.Equals(valueAsString, targetValue, StringComparison.OrdinalIgnoreCase);
            
            return isMatch ? Visibility.Visible : Visibility.Collapsed;
        }
        
        // Se parameter for um int ou conversível para int, comparar numericamente
        if (parameter != null && int.TryParse(parameter.ToString(), out int targetInt))
        {
            if (value is int intValue)
            {
                return intValue == targetInt ? Visibility.Visible : Visibility.Collapsed;
            }
            
            if (int.TryParse(value?.ToString(), out int parsedValue))
            {
                return parsedValue == targetInt ? Visibility.Visible : Visibility.Collapsed;
            }
        }
        
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}