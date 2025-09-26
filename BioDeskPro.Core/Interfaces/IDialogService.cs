namespace BioDeskPro.Core.Interfaces;

public enum DialogResult
{
    None,
    OK,
    Cancel,
    Yes,
    No,
    Save,
    DontSave
}

public interface IDialogService
{
    // Mensagens simples
    void ShowInfo(string message, string title = "Informação");
    void ShowWarning(string message, string title = "Aviso");
    void ShowError(string message, string title = "Erro");
    
    // Diálogos de confirmação
    DialogResult ShowConfirmation(string message, string title = "Confirmação");
    DialogResult ShowYesNoCancel(string message, string title = "Confirmação");
    
    // Diálogo específico para IsDirty
    DialogResult ShowSaveChangesDialog(string message = "Existem alterações não guardadas. Deseja guardá-las?");
    
    // Diálogos personalizados
    bool ShowDialog<T>(T viewModel) where T : class;
    T? ShowDialog<T>() where T : class, new();
    
    // Selecionar arquivos
    string? ShowOpenFileDialog(string filter = "Todos os arquivos|*.*", string title = "Abrir arquivo");
    string[]? ShowOpenMultipleFilesDialog(string filter = "Todos os arquivos|*.*", string title = "Abrir arquivos");
    string? ShowSaveFileDialog(string filter = "Todos os arquivos|*.*", string title = "Guardar arquivo", string? defaultFileName = null);
    
    // Selecionar pasta
    string? ShowFolderBrowserDialog(string title = "Selecionar pasta");
}