using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Conversor para comparar valor numérico com parâmetro
/// Usado para mostrar "AUTO-STOP ATIVO" quando Improvement >= 95%
/// Retorna Visibility.Visible se valor >= parâmetro
/// </summary>
public class GreaterThanConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value == null || parameter == null)
            return Visibility.Collapsed;

        try
        {
            double numericValue = System.Convert.ToDouble(value);
            double threshold = System.Convert.ToDouble(parameter);

            if (targetType == typeof(Visibility))
            {
                return numericValue >= threshold ? Visibility.Visible : Visibility.Collapsed;
            }
            else if (targetType == typeof(bool))
            {
                return numericValue >= threshold;
            }
        }
        catch
        {
            // Em caso de erro de conversão, retorna collapsed/false
        }

        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException("GreaterThanConverter é one-way apenas");
    }
}
