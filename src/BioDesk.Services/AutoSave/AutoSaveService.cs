using System;
using System.Reactive.Linq;
using System.Reactive.Subjects;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.AutoSave;

/// <summary>
/// Implementação de auto-save com debounce usando System.Reactive
/// Thread-safe e com logging integrado
/// </summary>
public class AutoSaveService<T> : IAutoSaveService<T>, IDisposable
{
    private readonly ILogger<AutoSaveService<T>> _logger;
    private readonly Subject<T> _autoSaveSubject;
    private IDisposable? _autoSaveSubscription;
    private Func<T, Task>? _saveFunction;
    private TimeSpan _debounceTime = TimeSpan.FromSeconds(2);
    private bool _isMonitoring = false;

    public event EventHandler<AutoSaveEventArgs<T>>? AutoSaveExecuted;
    public event EventHandler<AutoSaveErrorEventArgs<T>>? AutoSaveError;

    public AutoSaveService(ILogger<AutoSaveService<T>> logger)
    {
        _logger = logger;
        _autoSaveSubject = new Subject<T>();
    }

    public void StartMonitoring()
    {
        if (_isMonitoring)
        {
            _logger.LogWarning("Auto-save já está a monitorar");
            return;
        }

        if (_saveFunction == null)
        {
            throw new InvalidOperationException("SaveFunction deve ser definida antes de iniciar o monitoramento");
        }

        _autoSaveSubscription = _autoSaveSubject
            .Throttle(_debounceTime)
            .DistinctUntilChanged()
            .SelectMany(async data =>
            {
                var startTime = DateTime.Now;
                try
                {
                    _logger.LogInformation("Executando auto-save com debounce de {DebounceMs}ms", _debounceTime.TotalMilliseconds);
                    
                    await _saveFunction(data);
                    
                    var duration = DateTime.Now - startTime;
                    _logger.LogInformation("Auto-save executado com sucesso em {Duration}ms", duration.TotalMilliseconds);
                    
                    AutoSaveExecuted?.Invoke(this, new AutoSaveEventArgs<T>
                    {
                        Data = data,
                        Duration = duration
                    });

                    return data;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erro no auto-save");
                    
                    AutoSaveError?.Invoke(this, new AutoSaveErrorEventArgs<T>
                    {
                        Data = data,
                        Exception = ex
                    });

                    // Re-throw para manter o comportamento esperado
                    throw;
                }
            })
            .Subscribe(
                _ => { }, // Success já tratado acima
                ex => _logger.LogError(ex, "Erro crítico no stream de auto-save")
            );

        _isMonitoring = true;
        _logger.LogInformation("Auto-save iniciado com debounce de {DebounceSeconds}s", _debounceTime.TotalSeconds);
    }

    public void StopMonitoring()
    {
        if (!_isMonitoring)
        {
            _logger.LogWarning("Auto-save já não está a monitorar");
            return;
        }

        _autoSaveSubscription?.Dispose();
        _autoSaveSubscription = null;
        _isMonitoring = false;
        
        _logger.LogInformation("Auto-save parado");
    }

    public void TriggerAutoSave(T data)
    {
        if (!_isMonitoring)
        {
            _logger.LogWarning("Auto-save não está a monitorar. Chame StartMonitoring() primeiro");
            return;
        }

        _logger.LogDebug("Trigger auto-save disparado");
        _autoSaveSubject.OnNext(data);
    }

    public void SetSaveFunction(Func<T, Task> saveFunction)
    {
        _saveFunction = saveFunction ?? throw new ArgumentNullException(nameof(saveFunction));
        _logger.LogDebug("SaveFunction definida para auto-save");
    }

    public void SetDebounceTime(TimeSpan debounceTime)
    {
        if (debounceTime <= TimeSpan.Zero)
        {
            throw new ArgumentException("Debounce time deve ser maior que zero", nameof(debounceTime));
        }

        _debounceTime = debounceTime;
        _logger.LogInformation("Debounce time definido para {DebounceSeconds}s", debounceTime.TotalSeconds);
    }

    public void Dispose()
    {
        StopMonitoring();
        _autoSaveSubject?.Dispose();
    }
}