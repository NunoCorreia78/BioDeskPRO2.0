using BioDeskPro.Core.Interfaces;
using Microsoft.Win32;
using System.Windows;

namespace BioDeskPro.UI.Services;

public class DialogService : IDialogService
{
    public void ShowInfo(string message, string title = "Informação")
    {
        MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information);
    }

    public void ShowWarning(string message, string title = "Aviso")
    {
        MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    public void ShowError(string message, string title = "Erro")
    {
        MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Error);
    }

    public DialogResult ShowConfirmation(string message, string title = "Confirmação")
    {
        var result = MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question);
        return result == MessageBoxResult.Yes ? DialogResult.Yes : DialogResult.No;
    }

    public DialogResult ShowYesNoCancel(string message, string title = "Confirmação")
    {
        var result = MessageBox.Show(message, title, MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
        return result switch
        {
            MessageBoxResult.Yes => DialogResult.Yes,
            MessageBoxResult.No => DialogResult.No,
            MessageBoxResult.Cancel => DialogResult.Cancel,
            _ => DialogResult.Cancel
        };
    }

    public DialogResult ShowSaveChangesDialog(string message = "Existem alterações não guardadas. Deseja guardá-las?")
    {
        var result = MessageBox.Show(
            message,
            "Guardar Alterações",
            MessageBoxButton.YesNoCancel,
            MessageBoxImage.Question);

        return result switch
        {
            MessageBoxResult.Yes => DialogResult.Save,
            MessageBoxResult.No => DialogResult.DontSave,
            MessageBoxResult.Cancel => DialogResult.Cancel,
            _ => DialogResult.Cancel
        };
    }

    public bool ShowDialog<T>(T viewModel) where T : class
    {
        // TODO: Implementar quando tivermos as views personalizadas
        throw new NotImplementedException("Diálogos personalizados serão implementados na próxima fase");
    }

    public T? ShowDialog<T>() where T : class, new()
    {
        // TODO: Implementar quando tivermos as views personalizadas
        throw new NotImplementedException("Diálogos personalizados serão implementados na próxima fase");
    }

    public string? ShowOpenFileDialog(string filter = "Todos os arquivos|*.*", string title = "Abrir arquivo")
    {
        var dialog = new OpenFileDialog
        {
            Filter = filter,
            Title = title,
            Multiselect = false
        };

        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    public string[]? ShowOpenMultipleFilesDialog(string filter = "Todos os arquivos|*.*", string title = "Abrir arquivos")
    {
        var dialog = new OpenFileDialog
        {
            Filter = filter,
            Title = title,
            Multiselect = true
        };

        return dialog.ShowDialog() == true ? dialog.FileNames : null;
    }

    public string? ShowSaveFileDialog(string filter = "Todos os arquivos|*.*", string title = "Guardar arquivo", string? defaultFileName = null)
    {
        var dialog = new SaveFileDialog
        {
            Filter = filter,
            Title = title,
            FileName = defaultFileName ?? string.Empty
        };

        return dialog.ShowDialog() == true ? dialog.FileName : null;
    }

    public string? ShowFolderBrowserDialog(string title = "Selecionar pasta")
    {
        var dialog = new OpenFolderDialog
        {
            Title = title
        };

        return dialog.ShowDialog() == true ? dialog.FolderName : null;
    }
}