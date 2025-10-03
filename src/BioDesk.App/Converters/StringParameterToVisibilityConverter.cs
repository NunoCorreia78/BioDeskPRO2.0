using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace BioDesk.App.Converters;

/// <summary>
/// Converter para mostrar elemento baseado numa string específica ou número com parâmetro
/// Usado para mostrar campos de data personalizada apenas quando filtro = "Personalizado"
/// Também usado para mostrar abas baseado no número da aba ativa
/// </summary>
public class StringParameterToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        // LOG TEMPORÁRIO - DESCOBRIR O PROBLEMA
        var logMessage = $"🔍 CONVERTER DEBUG: value='{value}' (type={value?.GetType().Name}), parameter='{parameter}' (type={parameter?.GetType().Name})";
        System.Diagnostics.Debug.WriteLine(logMessage);
        System.Console.WriteLine(logMessage);

        if (parameter is string targetValue)
        {
            string? valueAsString = value?.ToString();
            bool isMatch = string.Equals(valueAsString, targetValue, StringComparison.OrdinalIgnoreCase);

            var result = isMatch ? Visibility.Visible : Visibility.Collapsed;
            var resultLog = $"🎯 STRING MATCH: '{valueAsString}' == '{targetValue}' = {isMatch} → {result}";
            System.Diagnostics.Debug.WriteLine(resultLog);
            System.Console.WriteLine(resultLog);

            return result;
        }

        // Se parameter for um int ou conversível para int, comparar numericamente
        if (parameter != null && int.TryParse(parameter.ToString(), out int targetInt))
        {
            if (value is int intValue)
            {
                var result = intValue == targetInt ? Visibility.Visible : Visibility.Collapsed;
                var resultLog = $"🎯 INT MATCH: {intValue} == {targetInt} = {intValue == targetInt} → {result}";
                System.Diagnostics.Debug.WriteLine(resultLog);
                System.Console.WriteLine(resultLog);
                return result;
            }

            if (int.TryParse(value?.ToString(), out int parsedValue))
            {
                var result = parsedValue == targetInt ? Visibility.Visible : Visibility.Collapsed;
                var resultLog = $"🎯 PARSED MATCH: {parsedValue} == {targetInt} = {parsedValue == targetInt} → {result}";
                System.Diagnostics.Debug.WriteLine(resultLog);
                System.Console.WriteLine(resultLog);
                return result;
            }
        }

        var defaultLog = "❌ CONVERTER: Nenhuma condição atendida, retornando Collapsed";
        System.Diagnostics.Debug.WriteLine(defaultLog);
        System.Console.WriteLine(defaultLog);
        return Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
