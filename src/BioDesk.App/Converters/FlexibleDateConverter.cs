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
        "MM/yyyy",    // ✅ NOVO: Mês e ano
        "yyyy",       // ✅ NOVO: Apenas ano
        "ddMMyyyy"
    };

    /// <summary>
    /// Converte DateTime? para string com formato flexível
    /// Se dia=1 e mês=1: mostra apenas ano (yyyy)
    /// Se dia=1: mostra mês/ano (MM/yyyy)
    /// Caso contrário: mostra data completa (dd/MM/yyyy)
    /// </summary>
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is DateTime dateTime && dateTime.Year > 1)
        {
            // Detectar formato baseado na data
            if (dateTime.Day == 1 && dateTime.Month == 1)
            {
                return dateTime.ToString("yyyy"); // Apenas ano
            }
            else if (dateTime.Day == 1)
            {
                return dateTime.ToString("MM/yyyy"); // Mês e ano
            }
            else
            {
                return dateTime.ToString("dd/MM/yyyy"); // Data completa
            }
        }

        return string.Empty;
    }

    /// <summary>
    /// Converte string para DateTime (aceita múltiplos formatos)
    /// Suporta: dd/MM/yyyy, MM/yyyy, yyyy, ddmmaaaa
    /// </summary>
    public object? ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string text && !string.IsNullOrWhiteSpace(text))
        {
            text = text.Trim();

            // ✅ NOVO: Detectar 8 dígitos sem separadores e auto-formatar
            if (text.Length == 8 && long.TryParse(text, out _))
            {
                // ddmmaaaa → dd/mm/aaaa
                text = $"{text.Substring(0, 2)}/{text.Substring(2, 2)}/{text.Substring(4, 4)}";
            }

            // ✅ NOVO: Detectar apenas 4 dígitos = ano
            if (text.Length == 4 && int.TryParse(text, out int year) && year >= 1900 && year <= 2100)
            {
                return new DateTime(year, 1, 1);
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

        return default(DateTime); // Retorna 01/01/0001 se não conseguir parsear
    }
}
