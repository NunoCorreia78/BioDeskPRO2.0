using System;
using System.Globalization;
using System.IO;
using System.Windows.Data;
using System.Windows.Media.Imaging;

namespace BioDesk.App.Converters;

/// <summary>
/// Converte caminho de ficheiro para BitmapImage SEM manter lock no ficheiro.
/// Usa BitmapCacheOption.OnLoad para carregar imagem em memória e libertar o ficheiro.
/// </summary>
public class PathToImageSourceConverter : IValueConverter
{
    public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not string caminho || string.IsNullOrWhiteSpace(caminho))
            return null;

        if (!File.Exists(caminho))
            return null;

        try
        {
            var bitmap = new BitmapImage();
            bitmap.BeginInit();
            bitmap.CacheOption = BitmapCacheOption.OnLoad; // 🔓 CRÍTICO: Carrega em memória e liberta ficheiro
            bitmap.UriSource = new Uri(caminho, UriKind.Absolute);
            bitmap.EndInit();
            bitmap.Freeze(); // Torna thread-safe e imutável
            
            return bitmap;
        }
        catch
        {
            return null; // Se falhar, retorna null (sem imagem)
        }
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
