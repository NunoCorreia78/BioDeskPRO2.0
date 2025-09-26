using System.Collections;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace BioDesk.App.Controls;

/// <summary>
/// UserControl para chips multi-seleção otimizado para interface clínica
/// Permite seleção rápida com visual moderno e responsivo
/// </summary>
public partial class MultiSelectChips : UserControl
{
    public static readonly DependencyProperty TitleProperty =
        DependencyProperty.Register(nameof(Title), typeof(string), typeof(MultiSelectChips), 
            new PropertyMetadata(string.Empty));

    public static readonly DependencyProperty ItemsProperty =
        DependencyProperty.Register(nameof(Items), typeof(IEnumerable), typeof(MultiSelectChips), 
            new PropertyMetadata(null));

    public static readonly DependencyProperty ChipToggledCommandProperty =
        DependencyProperty.Register(nameof(ChipToggledCommand), typeof(ICommand), typeof(MultiSelectChips), 
            new PropertyMetadata(null));

    public MultiSelectChips()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Título exibido acima dos chips
    /// </summary>
    public string Title
    {
        get => (string)GetValue(TitleProperty);
        set => SetValue(TitleProperty, value);
    }

    /// <summary>
    /// Coleção de itens (ChipItem) para exibir como chips
    /// </summary>
    public IEnumerable Items
    {
        get => (IEnumerable)GetValue(ItemsProperty);
        set => SetValue(ItemsProperty, value);
    }

    /// <summary>
    /// Comando executado quando um chip é selecionado/desmarcado
    /// </summary>
    public ICommand ChipToggledCommand
    {
        get => (ICommand)GetValue(ChipToggledCommandProperty);
        set => SetValue(ChipToggledCommandProperty, value);
    }
}