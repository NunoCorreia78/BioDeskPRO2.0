using System;
using System.Collections.Generic;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using BioDesk.Domain.Models;

namespace BioDesk.App.Converters;

/// <summary>
/// Converter para transformar List&lt;SimplePoint&gt; em PointCollection do WPF
/// </summary>
public class SimplePointCollectionConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        if (value is not List<SimplePoint> points)
            return new PointCollection();

        var pointCollection = new PointCollection();
        foreach (var point in points)
        {
            pointCollection.Add(new Point(point.X, point.Y));
        }

        return pointCollection;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException("ConvertBack não é suportado para SimplePointCollectionConverter");
    }
}
