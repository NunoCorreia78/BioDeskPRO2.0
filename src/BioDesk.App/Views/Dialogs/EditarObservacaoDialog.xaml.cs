using System.Windows;

namespace BioDesk.App.Views.Dialogs;

/// <summary>
/// Dialog para editar observações de uma marca existente.
/// </summary>
public partial class EditarObservacaoDialog : Window
{
    /// <summary>
    /// Observações editadas pelo utilizador.
    /// </summary>
    public string Observacoes { get; private set; } = string.Empty;

    public EditarObservacaoDialog(string observacoesAtuais)
    {
        InitializeComponent();

        // Preencher com observações existentes
        ObservacoesTextBox.Text = observacoesAtuais ?? string.Empty;

        // Selecionar todo o texto e focar
        Loaded += (s, e) =>
        {
            ObservacoesTextBox.SelectAll();
            ObservacoesTextBox.Focus();
        };
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
