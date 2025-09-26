using System.Windows;
using System.Windows.Controls;
using BioDesk.ViewModels;

namespace BioDesk.App.Views;

/// <summary>
/// Interação lógica para FichaPacienteView.xaml
/// Exibe a ficha completa do paciente com possibilidade de edição
/// </summary>
public partial class FichaPacienteView : UserControl
{
    public FichaPacienteView()
    {
        InitializeComponent();
    }

    private void FichaPacienteView_Loaded(object sender, RoutedEventArgs e)
    {
        // O DataContext já é definido no MainWindow.xaml.cs
        // O ViewModel já é inicializado no construtor com o paciente ativo
    }
}