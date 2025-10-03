using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Conversor flexível para inputs de data que aceita múltiplos formatos
/// Suporta: dd/MM/yyyy, dd-MM-yyyy, yyyy-MM-dd, dd.MM.yyyy, etc.
/// </summary>
public class FlexibleDateConverter : IValueConverter
{
    private static readonly string[] _dateFormats = new[]
    {
        "dd/MM/yyyy",
        "dd-MM-yyyy",
        "dd.MM.yyyy",
        "yyyy-MM-dd",
        "yyyy/MM/dd",
        "dd/MM/yy",
        "dd-MM-yy",
        "d/M/yyyy",
        "d-M-yyyy",
        "d/M/yy",
        "ddMMyyyy"  // ✅ NOVO: Suporte para 8 dígitos sem separadores
    };

    /// <summary>
    /// Converte DateTime? para string (dd/MM/yyyy)
    /// </summary>
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is DateTime dateTime)
        {
            return dateTime.ToString("dd/MM/yyyy");
        }

        return string.Empty;
    }

    /// <summary>
    /// Converte string para DateTime? (aceita múltiplos formatos)
    /// NOVO: Suporta ddmmaaaa (ex: "01012000" → 01/01/2000)
    /// </summary>
    public object? ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string text && !string.IsNullOrWhiteSpace(text))
        {
            // ✅ NOVO: Detectar 8 dígitos sem separadores e auto-formatar
            if (text.Length == 8 && long.TryParse(text, out _))
            {
                // ddmmaaaa → dd/mm/aaaa
                text = $"{text.Substring(0, 2)}/{text.Substring(2, 2)}/{text.Substring(4, 4)}";
            }

            // Tentar parsear com formatos definidos
            if (DateTime.TryParseExact(text, _dateFormats, CultureInfo.InvariantCulture, DateTimeStyles.None, out DateTime result))
            {
                return result;
            }

            // Tentar parse genérico (aceita formatos localizados)
            if (DateTime.TryParse(text, culture, DateTimeStyles.None, out result))
            {
                return result;
            }
        }

        return null; // DateTime? = null se não conseguir parsear
    }
}
