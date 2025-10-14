using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte string não-vazia para Visibility.Visible, string vazia/null para Visibility.Collapsed
/// </summary>
public class NotEmptyStringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string str && !string.IsNullOrWhiteSpace(str))
        {
            return Visibility.Visible;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
