using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.AutoSave;

/// <summary>
/// Serviço de auto-save inteligente com debounce
/// Aguarda 5s de inatividade antes de gravar para evitar writes excessivos
/// </summary>
public interface IAutoSaveService
{
    /// <summary>
    /// Agenda uma operação de auto-save (reseta timer se já existir)
    /// </summary>
    void ScheduleSave(Func<Task> saveAction, string context = "");

    /// <summary>
    /// Cancela auto-save pendente
    /// </summary>
    void CancelPendingSave();

    /// <summary>
    /// Força save imediato (ignora timer)
    /// </summary>
    Task ForceSaveAsync();

    /// <summary>
    /// Verifica se há save pendente
    /// </summary>
    bool HasPendingSave { get; }
}

public class AutoSaveService : IAutoSaveService, IDisposable
{
    private readonly ILogger<AutoSaveService> _logger;
    private readonly TimeSpan _debounceDelay = TimeSpan.FromSeconds(5);
    private readonly int _maxRetries = 3;
    
    private Timer? _timer;
    private Func<Task>? _pendingSaveAction;
    private string _saveContext = "";
    private int _retryCount = 0;
    private bool _isSaving = false;
    private bool _disposed = false;
    private readonly object _lock = new();

    public AutoSaveService(ILogger<AutoSaveService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public bool HasPendingSave
    {
        get
        {
            lock (_lock)
            {
                return _pendingSaveAction != null || _isSaving;
            }
        }
    }

    public void ScheduleSave(Func<Task> saveAction, string context = "")
    {
        if (saveAction == null)
            throw new ArgumentNullException(nameof(saveAction));

        lock (_lock)
        {
            // Cancelar timer existente
            _timer?.Dispose();

            // Armazenar nova ação
            _pendingSaveAction = saveAction;
            _saveContext = context;
            _retryCount = 0;

            // Criar novo timer
            _timer = new Timer(
                async _ => await ExecuteSaveAsync(),
                null,
                _debounceDelay,
                Timeout.InfiniteTimeSpan
            );

            _logger.LogDebug("⏰ Auto-save agendado em {Delay}s - Contexto: {Context}", 
                _debounceDelay.TotalSeconds, context);
        }
    }

    public void CancelPendingSave()
    {
        lock (_lock)
        {
            _timer?.Dispose();
            _timer = null;
            _pendingSaveAction = null;
            _saveContext = "";
            _retryCount = 0;

            _logger.LogDebug("❌ Auto-save cancelado");
        }
    }

    public async Task ForceSaveAsync()
    {
        Func<Task>? actionToExecute;
        string context;

        lock (_lock)
        {
            if (_pendingSaveAction == null && !_isSaving)
            {
                _logger.LogWarning("⚠️ ForceSaveAsync chamado mas não há save pendente");
                return;
            }

            actionToExecute = _pendingSaveAction;
            context = _saveContext;

            // Cancelar timer (vamos executar agora)
            _timer?.Dispose();
            _timer = null;
        }

        if (actionToExecute != null)
        {
            _logger.LogInformation("⚡ Força save imediato - Contexto: {Context}", context);
            await ExecuteSaveInternalAsync(actionToExecute, context);
        }
    }

    private async Task ExecuteSaveAsync()
    {
        Func<Task>? actionToExecute;
        string context;

        lock (_lock)
        {
            if (_pendingSaveAction == null || _isSaving)
                return;

            actionToExecute = _pendingSaveAction;
            context = _saveContext;
            _isSaving = true;
        }

        await ExecuteSaveInternalAsync(actionToExecute, context);

        lock (_lock)
        {
            _isSaving = false;
            _pendingSaveAction = null;
            _saveContext = "";
            _retryCount = 0;
        }
    }

    private async Task ExecuteSaveInternalAsync(Func<Task> saveAction, string context)
    {
        try
        {
            _logger.LogInformation("💾 Executando auto-save... Contexto: {Context}", context);

            await saveAction();

            _logger.LogInformation("✅ Auto-save concluído com sucesso! Contexto: {Context}", context);
        }
        catch (Exception ex)
        {
            _retryCount++;

            if (_retryCount <= _maxRetries)
            {
                _logger.LogWarning(ex, 
                    "⚠️ Erro no auto-save (tentativa {Retry}/{Max}) - Contexto: {Context}. Retentar em 2s...", 
                    _retryCount, _maxRetries, context);

                // Reagendar com delay menor
                lock (_lock)
                {
                    _isSaving = false;
                    _timer?.Dispose();
                    _timer = new Timer(
                        async _ => await ExecuteSaveAsync(),
                        null,
                        TimeSpan.FromSeconds(2),
                        Timeout.InfiniteTimeSpan
                    );
                }
            }
            else
            {
                _logger.LogError(ex, 
                    "❌ Falha no auto-save após {MaxRetries} tentativas - Contexto: {Context}", 
                    _maxRetries, context);

                // Limpar estado
                lock (_lock)
                {
                    _isSaving = false;
                    _pendingSaveAction = null;
                    _saveContext = "";
                    _retryCount = 0;
                }

                // Re-throw para que ViewModel possa tratar
                throw;
            }
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _timer?.Dispose();
            _timer = null;
        }
        _disposed = true;
    }
}
