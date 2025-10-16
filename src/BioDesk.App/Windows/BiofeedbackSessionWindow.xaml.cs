using System.Windows;

namespace BioDesk.App.Windows;

/// <summary>
/// Lógica de interação para BiofeedbackSessionWindow.xaml
/// Modal para sessão de biofeedback com loop autónomo (scan → emit → repeat).
/// </summary>
public partial class BiofeedbackSessionWindow : Window
{
    public BiofeedbackSessionWindow()
    {
        InitializeComponent();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
