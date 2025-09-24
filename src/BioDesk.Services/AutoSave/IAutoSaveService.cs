using System;
using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.AutoSave;

/// <summary>
/// Interface para serviço de auto-save com debounce
/// </summary>
public interface IAutoSaveService<T>
{
    /// <summary>
    /// Inicia o monitoramento de alterações para auto-save
    /// </summary>
    void StartMonitoring();

    /// <summary>
    /// Para o monitoramento
    /// </summary>
    void StopMonitoring();

    /// <summary>
    /// Dispara uma operação de auto-save com debounce
    /// </summary>
    void TriggerAutoSave(T data);

    /// <summary>
    /// Define a função que será executada no auto-save
    /// </summary>
    void SetSaveFunction(Func<T, Task> saveFunction);

    /// <summary>
    /// Configura o tempo de debounce (padrão: 2 segundos)
    /// </summary>
    void SetDebounceTime(TimeSpan debounceTime);

    /// <summary>
    /// Evento disparado quando auto-save é executado
    /// </summary>
    event EventHandler<AutoSaveEventArgs<T>>? AutoSaveExecuted;

    /// <summary>
    /// Evento disparado quando auto-save falha
    /// </summary>
    event EventHandler<AutoSaveErrorEventArgs<T>>? AutoSaveError;
}

/// <summary>
/// Argumentos para evento de auto-save
/// </summary>
public class AutoSaveEventArgs<T> : EventArgs
{
    public T Data { get; init; } = default!;
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public TimeSpan Duration { get; init; }
}

/// <summary>
/// Argumentos para evento de erro no auto-save
/// </summary>
public class AutoSaveErrorEventArgs<T> : EventArgs
{
    public T Data { get; init; } = default!;
    public Exception Exception { get; init; } = null!;
    public DateTime Timestamp { get; init; } = DateTime.Now;
}