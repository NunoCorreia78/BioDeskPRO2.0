using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;

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
    /// Executa uma ação de forma segura com tratamento de erros
    /// </summary>
    protected async Task ExecuteSafelyAsync(Func<Task> action, string? errorMessage = null)
    {
        try
        {
            ClearError();
            IsLoading = true;
            await action();
        }
        catch (Exception ex)
        {
            SetError(errorMessage ?? ex.Message);
        }
        finally
        {
            IsLoading = false;
        }
    }

    /// <summary>
    /// Executa uma função de forma segura com tratamento de erros
    /// </summary>
    protected async Task<T?> ExecuteSafelyAsync<T>(Func<Task<T>> function, string? errorMessage = null)
    {
        try
        {
            ClearError();
            IsLoading = true;
            return await function();
        }
        catch (Exception ex)
        {
            SetError(errorMessage ?? ex.Message);
            return default;
        }
        finally
        {
            IsLoading = false;
        }
    }
}