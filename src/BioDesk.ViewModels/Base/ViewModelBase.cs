using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Extensions.Logging;
using FluentValidation;
using FluentValidation.Results;

namespace BioDesk.ViewModels.Base;

/// <summary>
/// Base para todos os ViewModels do BioDeskPro2
/// Utiliza CommunityToolkit.Mvvm com [ObservableProperty] e [RelayCommand]
/// </summary>
public abstract partial class ViewModelBase : ObservableObject
{
    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _errorMessage = string.Empty;

    [ObservableProperty]
    private string? _successMessage;

    [ObservableProperty]
    private Dictionary<string, List<string>> _validationErrors = new();

    /// <summary>
    /// Indica se o ViewModel tem erros de validação
    /// </summary>
    public bool HasValidationErrors => ValidationErrors.Count > 0;

    /// <summary>
    /// Obtém os erros de validação formatados como string
    /// </summary>
    public string ValidationErrorsText => string.Join(Environment.NewLine,
        ValidationErrors.SelectMany(kv => kv.Value.Select(v => $"• {v}")));

    /// <summary>
    /// Valida um objeto usando FluentValidation
    /// </summary>
    protected bool ValidateModel<T>(T model, IValidator<T> validator)
    {
        var validationResult = validator.Validate(model);

        ValidationErrors.Clear();

        if (!validationResult.IsValid)
        {
            foreach (var error in validationResult.Errors)
            {
                if (!ValidationErrors.ContainsKey(error.PropertyName))
                {
                    ValidationErrors[error.PropertyName] = new List<string>();
                }
                ValidationErrors[error.PropertyName].Add(error.ErrorMessage);
            }
        }

        OnPropertyChanged(nameof(HasValidationErrors));
        OnPropertyChanged(nameof(ValidationErrorsText));

        return validationResult.IsValid;
    }

    /// <summary>
    /// Limpa todos os erros de validação
    /// </summary>
    protected void ClearValidationErrors()
    {
        ValidationErrors.Clear();
        OnPropertyChanged(nameof(HasValidationErrors));
        OnPropertyChanged(nameof(ValidationErrorsText));
    }

    /// <summary>
    /// Limpa a mensagem de erro
    /// </summary>
    protected void ClearError()
    {
        ErrorMessage = string.Empty;
    }

    /// <summary>
    /// Define uma mensagem de erro
    /// </summary>
    protected void SetError(string message)
    {
        ErrorMessage = message;
    }

    /// <summary>
    /// Executa uma ação de forma segura com tratamento de erros robusto
    /// Inclui logging, UI feedback e tratamento de exceções específicas
    /// </summary>
    protected async Task ExecuteWithErrorHandlingAsync(Func<Task> operation, string errorContext = "", ILogger? logger = null)
    {
        try
        {
            ClearError();
            IsLoading = true;
            await operation();
        }
        catch (OperationCanceledException)
        {
            // Operação cancelada - não mostrar erro
            SetError("Operação cancelada pelo utilizador");
        }
        catch (UnauthorizedAccessException ex)
        {
            var message = $"Acesso negado {errorContext}";
            SetError(message);
            logger?.LogWarning(ex, message);
            ShowErrorDialog(message, "Acesso Negado");
        }
        catch (InvalidOperationException ex)
        {
            var message = $"Operação inválida {errorContext}: {ex.Message}";
            SetError(message);
            logger?.LogError(ex, message);
            ShowErrorDialog(message, "Operação Inválida");
        }
        catch (Exception ex)
        {
            var message = $"Erro {errorContext}: {ex.Message}";
            SetError(message);
            logger?.LogError(ex, message);
            ShowErrorDialog(message, "Erro Inesperado");
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Executa uma função de forma segura com tratamento de erros robusto
    /// </summary>
    protected async Task<T?> ExecuteWithErrorHandlingAsync<T>(Func<Task<T>> operation, string errorContext = "", ILogger? logger = null)
    {
        try
        {
            ClearError();
            IsLoading = true;
            return await operation();
        }
        catch (OperationCanceledException)
        {
            SetError("Operação cancelada pelo utilizador");
            return default;
        }
        catch (UnauthorizedAccessException ex)
        {
            var message = $"Acesso negado {errorContext}";
            SetError(message);
            logger?.LogWarning(ex, message);
            ShowErrorDialog(message, "Acesso Negado");
            return default;
        }
        catch (InvalidOperationException ex)
        {
            var message = $"Operação inválida {errorContext}: {ex.Message}";
            SetError(message);
            logger?.LogError(ex, message);
            ShowErrorDialog(message, "Operação Inválida");
            return default;
        }
        catch (Exception ex)
        {
            var message = $"Erro {errorContext}: {ex.Message}";
            SetError(message);
            logger?.LogError(ex, message);
            ShowErrorDialog(message, "Erro Inesperado");
            return default;
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Adiciona mensagem de erro ao log de erros interno
    /// Substituiu MessageBox para evitar dependência de WPF nos ViewModels
    /// </summary>
    private static void ShowErrorDialog(string message, string title)
    {
        // ViewModels não devem ter dependência direta de WPF
        // O erro já está em ErrorMessage para binding na UI
        System.Diagnostics.Debug.WriteLine($"[ERROR] {title}: {message}");
    }
}