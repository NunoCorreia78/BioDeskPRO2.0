using System;
using System.Globalization;
using System.Windows.Data;
using BioDesk.Domain.Enums;

namespace BioDesk.App.Converters;

/// <summary>
/// Converter para transformar int/string em CategoriaCore? (enum nullable)
/// Usado nos botões de filtro do Banco Core
/// </summary>
public class IntToCategoriaCoreConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        // Não usado - apenas ConvertBack
        return value;
    }

    public object? ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (parameter == null)
            return null;

        // Converter string/int para CategoriaCore
        if (parameter is string strValue && int.TryParse(strValue, out int intValue))
        {
            return (CategoriaCore)intValue;
        }

        if (parameter is int directInt)
        {
            return (CategoriaCore)directInt;
        }

        return null;
    }
}
