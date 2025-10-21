using System.Windows;
using System.Windows.Controls;

namespace BioDesk.App.Controls;

public partial class TerapiaControlosCompactoUserControl : UserControl
{
    // Dependency Properties
    public static readonly DependencyProperty VoltagemVProperty =
        DependencyProperty.Register(nameof(VoltagemV), typeof(double), typeof(TerapiaControlosCompactoUserControl), new PropertyMetadata(5.0));

    public static readonly DependencyProperty DuracaoTotalMinutosProperty =
        DependencyProperty.Register(nameof(DuracaoTotalMinutos), typeof(double), typeof(TerapiaControlosCompactoUserControl), new PropertyMetadata(30.0));

    public static readonly DependencyProperty TempoFrequenciaSegundosProperty =
        DependencyProperty.Register(nameof(TempoFrequenciaSegundos), typeof(int), typeof(TerapiaControlosCompactoUserControl), new PropertyMetadata(10));

    public static readonly DependencyProperty AjusteHzProperty =
        DependencyProperty.Register(nameof(AjusteHz), typeof(double), typeof(TerapiaControlosCompactoUserControl), new PropertyMetadata(0.0));

    public static readonly DependencyProperty TextoBotaoProperty =
        DependencyProperty.Register(nameof(TextoBotao), typeof(string), typeof(TerapiaControlosCompactoUserControl), new PropertyMetadata("▶ INICIAR TERAPIA"));

    // Properties
    public double VoltagemV
    {
        get => (double)GetValue(VoltagemVProperty);
        set => SetValue(VoltagemVProperty, value);
    }

    public double DuracaoTotalMinutos
    {
        get => (double)GetValue(DuracaoTotalMinutosProperty);
        set => SetValue(DuracaoTotalMinutosProperty, value);
    }

    public int TempoFrequenciaSegundos
    {
        get => (int)GetValue(TempoFrequenciaSegundosProperty);
        set => SetValue(TempoFrequenciaSegundosProperty, value);
    }

    public double AjusteHz
    {
        get => (double)GetValue(AjusteHzProperty);
        set => SetValue(AjusteHzProperty, value);
    }

    public string TextoBotao
    {
        get => (string)GetValue(TextoBotaoProperty);
        set => SetValue(TextoBotaoProperty, value);
    }

    // Events
    public event RoutedEventHandler? IniciarClick;
    public event RoutedEventHandler? PararClick;

    public TerapiaControlosCompactoUserControl()
    {
        InitializeComponent();
    }

    private void IniciarButton_Click(object sender, RoutedEventArgs e)
    {
        IniciarClick?.Invoke(this, e);
    }

    private void PararButton_Click(object sender, RoutedEventArgs e)
    {
        PararClick?.Invoke(this, e);
    }
}
