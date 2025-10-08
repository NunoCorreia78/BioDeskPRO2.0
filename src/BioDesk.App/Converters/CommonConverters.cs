using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte string para Visibility (null/empty = Collapsed, valor = Visible)
/// Para mensagens de erro e loading states
/// </summary>
public class StringToVisibilityConverter : IValueConverter
{
    public static readonly StringToVisibilityConverter Instance = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string str)
        {
            return string.IsNullOrWhiteSpace(str) ? Visibility.Collapsed : Visibility.Visible;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converte bool para Visibility (true = Visible, false = Collapsed)
/// </summary>
public class BooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return boolValue ? Visibility.Visible : Visibility.Collapsed;
        }
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is Visibility visibility)
        {
            return visibility == Visibility.Visible;
        }
        return false;
    }
}

/// <summary>
/// Converte bool para Visibility invertido (true = Collapsed, false = Visible)
/// </summary>
public class InverseBooleanToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return boolValue ? Visibility.Collapsed : Visibility.Visible;
        }
        return Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is Visibility visibility)
        {
            return visibility == Visibility.Collapsed;
        }
        return true;
    }
}

/// <summary>
/// Inverte um valor boolean
/// </summary>
public class InverseBooleanConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return !boolValue;
        }
        return true;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return !boolValue;
        }
        return false;
    }
}

/// <summary>
/// Conversor que converte null/string vazio para Visibility
/// </summary>
public class NullToVisibilityConverter : IValueConverter
{
    public static NullToVisibilityConverter Collapsed { get; } = new() { NullValue = Visibility.Collapsed, NotNullValue = Visibility.Visible };
    public static NullToVisibilityConverter Visible { get; } = new() { NullValue = Visibility.Visible, NotNullValue = Visibility.Collapsed };

    public Visibility NullValue { get; set; } = Visibility.Collapsed;
    public Visibility NotNullValue { get; set; } = Visibility.Visible;

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        bool isNullOrEmpty = value == null || (value is string str && string.IsNullOrWhiteSpace(str));
        return isNullOrEmpty ? NullValue : NotNullValue;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converte status da consulta para cor do card
/// Verde = Realizada, Azul = Agendada, Cinzento = Cancelada
/// </summary>
public class StatusToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string status)
        {
            return status.ToLower() switch
            {
                "realizada" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4CAF50")), // Verde
                "agendada" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2196F3")),   // Azul
                "cancelada" => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#9E9E9E")),  // Cinzento
                _ => new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7A9471"))             // Default verde terroso
            };
        }
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7A9471"));
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converte bool para cor (para indicadores de status)
/// True = Verde (sucesso), False = Vermelho (erro)
/// </summary>
public class BoolToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return boolValue
                ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#4CAF50")) // Verde
                : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F44336")); // Vermelho
        }
        return new SolidColorBrush((Color)ColorConverter.ConvertFromString("#9E9E9E")); // Cinzento default
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converte bool para texto de status
/// True = "✅ Consentimentos Completos", False = "⚠️ Consentimentos Pendentes"
/// </summary>
public class BoolToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue)
        {
            return boolValue
                ? "✅ Consentimentos Completos"
                : "⚠️ Consentimentos Pendentes";
        }
        return "❓ Estado Desconhecido";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}

/// <summary>
/// Converte string para bool comparando com o parâmetro
/// Usado para RadioButtons vinculados a propriedades string
/// </summary>
public class StringToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is string stringValue && parameter is string parameterValue)
        {
            return stringValue.Equals(parameterValue, StringComparison.OrdinalIgnoreCase);
        }
        return false;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is bool boolValue && boolValue && parameter is string parameterValue)
        {
            return parameterValue;
        }
        return Binding.DoNothing;
    }
}

/// <summary>
/// Converte null/objeto para bool (null = false, não-null = true)
/// Usado para habilitar/desabilitar botões baseado em seleção
/// </summary>
public class NullToBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value != null;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
