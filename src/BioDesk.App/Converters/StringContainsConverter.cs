using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Returns true when the input string contains the converter parameter (case-insensitive).
/// Helps XAML triggers react to status glyphs or short tags in status messages.
/// </summary>
public class StringContainsConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not string source || string.IsNullOrEmpty(source))
        {
            return false;
        }

        if (parameter is not string token || string.IsNullOrEmpty(token))
        {
            return false;
        }

        return source.IndexOf(token, StringComparison.CurrentCultureIgnoreCase) >= 0;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return Binding.DoNothing;
    }
}
