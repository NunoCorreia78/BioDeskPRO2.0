using System.Windows;

namespace BioDesk.App.Windows;

/// <summary>
/// Modal para configuração e início de Terapia Remota (Informacional)
/// </summary>
public partial class TerapiaRemotaWindow : Window
{
    public TerapiaRemotaWindow()
    {
        InitializeComponent();
    }
    
    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        Close();
    }
}
