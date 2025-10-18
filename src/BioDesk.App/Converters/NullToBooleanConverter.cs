using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte null para false, não-null para true (para bindings IsEnabled)
/// Usado em HistoricoWindow para habilitar botão apenas quando sessão está selecionada
/// </summary>
public class NullToBooleanConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        // value: objeto SessaoSelecionada do ViewModel
        // null → false (botão desabilitado)
        // não-null → true (botão habilitado)
        return value != null;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException("NullToBooleanConverter is OneWay only");
    }
}
