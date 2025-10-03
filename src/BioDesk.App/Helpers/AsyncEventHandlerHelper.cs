using System;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Extensions.Logging;

namespace BioDesk.App.Helpers;

/// <summary>
/// Helper para lidar com async void event handlers de forma segura
/// Captura exceções e previne crashes silenciosos
/// </summary>
public static class AsyncEventHandlerHelper
{
    /// <summary>
    /// Executa operação async dentro de event handler com tratamento robusto de erros
    /// </summary>
    /// <param name="operation">Operação async a executar</param>
    /// <param name="logger">Logger para registar erros</param>
    /// <param name="errorTitle">Título da mensagem de erro (default: "Erro")</param>
    /// <param name="showMessageBox">Se true, mostra MessageBox ao utilizador</param>
    public static async Task ExecuteSafelyAsync(
        Func<Task> operation,
        ILogger? logger = null,
        string errorTitle = "Erro",
        bool showMessageBox = true)
    {
        try
        {
            await operation();
        }
        catch (Exception ex)
        {
            // Log detalhado para diagnóstico
            logger?.LogError(ex, "💥 Exceção capturada em event handler: {Message}", ex.Message);

            // Feedback visual ao utilizador
            if (showMessageBox)
            {
                MessageBox.Show(
                    $"Ocorreu um erro:\n\n{ex.Message}",
                    errorTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }
        }
    }

    /// <summary>
    /// Executa operação async com valor de retorno dentro de event handler
    /// </summary>
    /// <typeparam name="T">Tipo do valor de retorno</typeparam>
    /// <param name="operation">Operação async a executar</param>
    /// <param name="logger">Logger para registar erros</param>
    /// <param name="errorTitle">Título da mensagem de erro</param>
    /// <param name="defaultValue">Valor a retornar em caso de erro</param>
    /// <param name="showMessageBox">Se true, mostra MessageBox ao utilizador</param>
    /// <returns>Resultado da operação ou defaultValue se houver erro</returns>
    public static async Task<T?> ExecuteSafelyAsync<T>(
        Func<Task<T>> operation,
        ILogger? logger = null,
        string errorTitle = "Erro",
        T? defaultValue = default,
        bool showMessageBox = true)
    {
        try
        {
            return await operation();
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "💥 Exceção capturada em event handler: {Message}", ex.Message);

            if (showMessageBox)
            {
                MessageBox.Show(
                    $"Ocorreu um erro:\n\n{ex.Message}",
                    errorTitle,
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }

            return defaultValue;
        }
    }

    /// <summary>
    /// Wrapper para event handlers async void - previne exceções não capturadas
    /// Uso: private async void Button_Click(object sender, RoutedEventArgs e) 
    ///         => await AsyncEventHandlerHelper.WrapAsync(Button_ClickAsync, _logger);
    /// </summary>
    public static async Task WrapAsync(
        Func<Task> operation,
        ILogger? logger = null,
        string operationName = "operação")
    {
        await ExecuteSafelyAsync(
            operation,
            logger,
            errorTitle: $"Erro em {operationName}",
            showMessageBox: true);
    }
}
