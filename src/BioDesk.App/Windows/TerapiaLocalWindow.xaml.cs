using System.Windows;

namespace BioDesk.App.Windows;

/// <summary>
/// Lógica de interação para TerapiaLocalWindow.xaml
/// Modal para terapia local com emissão direta de Hz e controlo de voltagem.
/// </summary>
public partial class TerapiaLocalWindow : Window
{
    public TerapiaLocalWindow()
    {
        InitializeComponent();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
