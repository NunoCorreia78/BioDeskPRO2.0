using System.Windows;
using System.Windows.Controls;

namespace BioDesk.App.Controls;

/// <summary>
/// UserControl reutilizável com controlos unificados de terapia.
/// Usado em Programas, Ressonantes e Biofeedback.
/// </summary>
public partial class TerapiaControlosUserControl : UserControl
{
    public TerapiaControlosUserControl()
    {
        InitializeComponent();
    }

    // Dependency Properties para binding

    public static readonly DependencyProperty VoltagemVProperty =
        DependencyProperty.Register(nameof(VoltagemV), typeof(double), typeof(TerapiaControlosUserControl),
            new PropertyMetadata(5.0));

    public double VoltagemV
    {
        get => (double)GetValue(VoltagemVProperty);
        set => SetValue(VoltagemVProperty, value);
    }

    public static readonly DependencyProperty DuracaoTotalMinutosProperty =
        DependencyProperty.Register(nameof(DuracaoTotalMinutos), typeof(int), typeof(TerapiaControlosUserControl),
            new PropertyMetadata(30));

    public int DuracaoTotalMinutos
    {
        get => (int)GetValue(DuracaoTotalMinutosProperty);
        set => SetValue(DuracaoTotalMinutosProperty, value);
    }

    public static readonly DependencyProperty TempoFrequenciaSegundosProperty =
        DependencyProperty.Register(nameof(TempoFrequenciaSegundos), typeof(int), typeof(TerapiaControlosUserControl),
            new PropertyMetadata(10));

    public int TempoFrequenciaSegundos
    {
        get => (int)GetValue(TempoFrequenciaSegundosProperty);
        set => SetValue(TempoFrequenciaSegundosProperty, value);
    }

    public static readonly DependencyProperty AjusteHzProperty =
        DependencyProperty.Register(nameof(AjusteHz), typeof(int), typeof(TerapiaControlosUserControl),
            new PropertyMetadata(0));

    public int AjusteHz
    {
        get => (int)GetValue(AjusteHzProperty);
        set => SetValue(AjusteHzProperty, value);
    }

    public static readonly DependencyProperty TextoBotaoProperty =
        DependencyProperty.Register(nameof(TextoBotao), typeof(string), typeof(TerapiaControlosUserControl),
            new PropertyMetadata("Iniciar Terapia"));

    public string TextoBotao
    {
        get => (string)GetValue(TextoBotaoProperty);
        set => SetValue(TextoBotaoProperty, value);
    }

    // Eventos
    public event RoutedEventHandler? IniciarClick;
    public event RoutedEventHandler? PararClick;

    private void IniciarButton_Click(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🟢 TerapiaControlosUserControl: IniciarButton_Click DISPARADO");
        System.Diagnostics.Debug.WriteLine($"📊 Valores: V={VoltagemV}, Duração={DuracaoTotalMinutos}min, Tempo/Freq={TempoFrequenciaSegundos}s, Ajuste={AjusteHz}Hz");
        System.Diagnostics.Debug.WriteLine($"🔗 IniciarClick subscribers: {IniciarClick?.GetInvocationList().Length ?? 0}");
        IniciarClick?.Invoke(this, e);
        System.Diagnostics.Debug.WriteLine("✅ TerapiaControlosUserControl: Evento IniciarClick invocado");
    }

    private void PararButton_Click(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🔴 TerapiaControlosUserControl: PararButton_Click DISPARADO");
        PararClick?.Invoke(this, e);
        System.Diagnostics.Debug.WriteLine("✅ TerapiaControlosUserControl: Evento PararClick invocado");
    }
}
