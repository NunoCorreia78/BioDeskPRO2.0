using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte estado booleano Pausado para texto do botão ("Pausar"/"Retomar")
/// Usado em TerapiaLocalWindow e BiofeedbackSessionWindow
/// </summary>
public class PausedTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        // value: bool Pausado do ViewModel
        // true = terapia pausada → mostrar "Retomar"
        // false = terapia em execução → mostrar "Pausar"
        if (value is bool pausado)
        {
            return pausado ? "▶ Retomar" : "⏸ Pausar";
        }
        return "⏸ Pausar"; // Fallback seguro
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException("PausedTextConverter is OneWay only");
    }
}
