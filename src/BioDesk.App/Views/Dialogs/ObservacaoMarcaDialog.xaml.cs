using System.Windows;

namespace BioDesk.App.Views.Dialogs;

/// <summary>
/// Dialog para captura de observações clínicas ao adicionar marca na íris.
/// </summary>
public partial class ObservacaoMarcaDialog : Window
{
    /// <summary>
    /// Observações clínicas fornecidas pelo utilizador.
    /// </summary>
    public string Observacoes { get; private set; } = string.Empty;

    public ObservacaoMarcaDialog()
    {
        InitializeComponent();

        // Focus no TextBox quando dialog abre
        Loaded += (s, e) => ObservacoesTextBox.Focus();
    }

    private void Confirmar_Click(object sender, RoutedEventArgs e)
    {
        Observacoes = ObservacoesTextBox.Text.Trim();
        DialogResult = true;
        Close();
    }

    private void Cancelar_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
