using System.Windows;
using System.Windows.Controls;

namespace BioDesk.App.Controls;

public partial class TerapiaProgressoUserControl : UserControl
{
    // Dependency Properties
    public static readonly DependencyProperty TerapiaEmAndamentoProperty =
        DependencyProperty.Register(nameof(TerapiaEmAndamento), typeof(bool), typeof(TerapiaProgressoUserControl), new PropertyMetadata(false));

    public static readonly DependencyProperty FrequenciaAtualHzProperty =
        DependencyProperty.Register(nameof(FrequenciaAtualHz), typeof(double), typeof(TerapiaProgressoUserControl), new PropertyMetadata(0.0));

    public static readonly DependencyProperty FrequenciaOriginalHzProperty =
        DependencyProperty.Register(nameof(FrequenciaOriginalHz), typeof(double), typeof(TerapiaProgressoUserControl), new PropertyMetadata(0.0));

    public static readonly DependencyProperty AjusteAplicadoHzProperty =
        DependencyProperty.Register(nameof(AjusteAplicadoHz), typeof(double), typeof(TerapiaProgressoUserControl), new PropertyMetadata(0.0));

    public static readonly DependencyProperty ProgramaAtualProperty =
        DependencyProperty.Register(nameof(ProgramaAtual), typeof(string), typeof(TerapiaProgressoUserControl), new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty MostrarProgramaProperty =
        DependencyProperty.Register(nameof(MostrarPrograma), typeof(bool), typeof(TerapiaProgressoUserControl), new PropertyMetadata(true));

    public static readonly DependencyProperty FrequenciaAtualIndexProperty =
        DependencyProperty.Register(nameof(FrequenciaAtualIndex), typeof(int), typeof(TerapiaProgressoUserControl), new PropertyMetadata(0));

    public static readonly DependencyProperty TotalFrequenciasProperty =
        DependencyProperty.Register(nameof(TotalFrequencias), typeof(int), typeof(TerapiaProgressoUserControl), new PropertyMetadata(0));

    public static readonly DependencyProperty ProgressoPercentualProperty =
        DependencyProperty.Register(nameof(ProgressoPercentual), typeof(double), typeof(TerapiaProgressoUserControl), new PropertyMetadata(0.0));

    public static readonly DependencyProperty TempoRestanteFormatadoProperty =
        DependencyProperty.Register(nameof(TempoRestanteFormatado), typeof(string), typeof(TerapiaProgressoUserControl), new PropertyMetadata("--:--"));

    // Properties
    public bool TerapiaEmAndamento
    {
        get => (bool)GetValue(TerapiaEmAndamentoProperty);
        set => SetValue(TerapiaEmAndamentoProperty, value);
    }

    public double FrequenciaAtualHz
    {
        get => (double)GetValue(FrequenciaAtualHzProperty);
        set => SetValue(FrequenciaAtualHzProperty, value);
    }

    public double FrequenciaOriginalHz
    {
        get => (double)GetValue(FrequenciaOriginalHzProperty);
        set => SetValue(FrequenciaOriginalHzProperty, value);
    }

    public double AjusteAplicadoHz
    {
        get => (double)GetValue(AjusteAplicadoHzProperty);
        set => SetValue(AjusteAplicadoHzProperty, value);
    }

    public string ProgramaAtual
    {
        get => (string)GetValue(ProgramaAtualProperty);
        set => SetValue(ProgramaAtualProperty, value);
    }

    public bool MostrarPrograma
    {
        get => (bool)GetValue(MostrarProgramaProperty);
        set => SetValue(MostrarProgramaProperty, value);
    }

    public int FrequenciaAtualIndex
    {
        get => (int)GetValue(FrequenciaAtualIndexProperty);
        set => SetValue(FrequenciaAtualIndexProperty, value);
    }

    public int TotalFrequencias
    {
        get => (int)GetValue(TotalFrequenciasProperty);
        set => SetValue(TotalFrequenciasProperty, value);
    }

    public double ProgressoPercentual
    {
        get => (double)GetValue(ProgressoPercentualProperty);
        set => SetValue(ProgressoPercentualProperty, value);
    }

    public string TempoRestanteFormatado
    {
        get => (string)GetValue(TempoRestanteFormatadoProperty);
        set => SetValue(TempoRestanteFormatadoProperty, value);
    }

    public TerapiaProgressoUserControl()
    {
        InitializeComponent();
    }
}
