using System.Collections;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BioDesk.App.Controls;

/// <summary>
/// UserControl para botões de frases rápidas otimizado para rapidez clínica
/// Permite preenchimento automático com um clique
/// </summary>
public partial class QuickPhraseButtons : UserControl
{
    public static readonly DependencyProperty PhrasesProperty =
        DependencyProperty.Register(nameof(Phrases), typeof(IEnumerable), typeof(QuickPhraseButtons), 
            new PropertyMetadata(null));

    public static readonly DependencyProperty PhraseClickedCommandProperty =
        DependencyProperty.Register(nameof(PhraseClickedCommand), typeof(ICommand), typeof(QuickPhraseButtons), 
            new PropertyMetadata(null));

    public QuickPhraseButtons()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Coleção de frases rápidas para exibir como botões
    /// </summary>
    public IEnumerable Phrases
    {
        get => (IEnumerable)GetValue(PhrasesProperty);
        set => SetValue(PhrasesProperty, value);
    }

    /// <summary>
    /// Comando executado quando uma frase rápida é clicada
    /// </summary>
    public ICommand PhraseClickedCommand
    {
        get => (ICommand)GetValue(PhraseClickedCommandProperty);
        set => SetValue(PhraseClickedCommandProperty, value);
    }
}