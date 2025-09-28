using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows;

namespace BioDesk.App.Converters;

/// <summary>
/// Converter para estilos de separadores/abas baseado na aba ativa
/// Retorna TabButtonActiveStyle para aba ativa, TabButtonStyle para as outras
/// </summary>
public class TabStyleConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is int abaAtiva && parameter is string abaParameterStr && int.TryParse(abaParameterStr, out int abaParameter))
        {
            // Procurar pelos recursos no Application
            var app = Application.Current;
            if (app != null)
            {
                var activeStyle = app.TryFindResource("TabButtonActiveStyle") as Style;
                var normalStyle = app.TryFindResource("TabButtonStyle") as Style;

                // Garantir que nunca retornamos null
                var resultStyle = abaAtiva == abaParameter ? activeStyle : normalStyle;
                return resultStyle ?? normalStyle ?? new Style();
            }
        }

        // Fallback para estilo normal ou criar um novo estilo
        var fallbackStyle = Application.Current?.TryFindResource("TabButtonStyle") as Style;
        return fallbackStyle ?? new Style();
    }

    public object? ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException("TabStyleConverter é apenas OneWay");
    }
}
