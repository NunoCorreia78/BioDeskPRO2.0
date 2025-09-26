using System.Windows;
using System.Windows.Controls;

namespace BioDesk.App.Controls;

/// <summary>
/// UserControl para slider de intensidade (0-10) otimizado para avaliação clínica
/// Com visual claro e valores bem definidos para rapidez no preenchimento
/// </summary>
public partial class IntensitySlider : UserControl
{
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(IntensitySlider), 
            new PropertyMetadata("Intensidade"));

    public static readonly DependencyProperty ValueProperty =
        DependencyProperty.Register(nameof(Value), typeof(int), typeof(IntensitySlider), 
            new PropertyMetadata(0));

    public static readonly DependencyProperty MinimumProperty =
        DependencyProperty.Register(nameof(Minimum), typeof(int), typeof(IntensitySlider), 
            new PropertyMetadata(0));

    public static readonly DependencyProperty MaximumProperty =
        DependencyProperty.Register(nameof(Maximum), typeof(int), typeof(IntensitySlider), 
            new PropertyMetadata(10));

    public IntensitySlider()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Título do slider
    /// </summary>
    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    /// <summary>
    /// Valor atual do slider
    /// </summary>
    public int Value
    {
        get => (int)GetValue(ValueProperty);
        set => SetValue(ValueProperty, value);
    }

    /// <summary>
    /// Valor mínimo do slider
    /// </summary>
    public int Minimum
    {
        get => (int)GetValue(MinimumProperty);
        set => SetValue(MinimumProperty, value);
    }

    /// <summary>
    /// Valor máximo do slider
    /// </summary>
    public int Maximum
    {
        get => (int)GetValue(MaximumProperty);
        set => SetValue(MaximumProperty, value);
    }
}