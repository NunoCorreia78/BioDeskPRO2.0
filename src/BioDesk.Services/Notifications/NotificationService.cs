using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Notifications;

/// <summary>
/// Implementação do serviço de notificações toast para BioDeskPro2
/// Thread-safe e com logging integrado
/// </summary>
public class NotificationService : INotificationService
{
    private readonly ILogger<NotificationService> _logger;

    public event EventHandler<NotificationEventArgs>? NotificationRequested;

    public NotificationService(ILogger<NotificationService> logger)
    {
        _logger = logger;
    }

    public async Task ShowSuccessAsync(string message, string? title = null, int durationMs = 4000)
    {
        await ShowAsync(NotificationType.Success, message, title ?? "Sucesso", durationMs);
    }

    public async Task ShowErrorAsync(string message, string? title = null, int durationMs = 6000)
    {
        await ShowAsync(NotificationType.Error, message, title ?? "Erro", durationMs);
    }

    public async Task ShowWarningAsync(string message, string? title = null, int durationMs = 5000)
    {
        await ShowAsync(NotificationType.Warning, message, title ?? "Aviso", durationMs);
    }

    public async Task ShowInfoAsync(string message, string? title = null, int durationMs = 4000)
    {
        await ShowAsync(NotificationType.Info, message, title ?? "Informação", durationMs);
    }

    public async Task ShowAsync(NotificationType type, string message, string? title = null, int durationMs = 4000)
    {
        try
        {
            var eventArgs = new NotificationEventArgs
            {
                Type = type,
                Message = message,
                Title = title,
                DurationMs = durationMs
            };

            _logger.LogInformation("Mostrando notificação {Type}: {Message}", type, message);

            // Enviar evento para UI thread
            await Task.Run(() =>
            {
                NotificationRequested?.Invoke(this, eventArgs);
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao mostrar notificação: {Message}", message);
        }
    }

    public void ClearAll()
    {
        try
        {
            _logger.LogInformation("Limpando todas as notificações");
            
            // Enviar evento especial para limpar
            var clearEvent = new NotificationEventArgs
            {
                Type = NotificationType.Info,
                Message = "__CLEAR_ALL__",
                DurationMs = 0
            };

            NotificationRequested?.Invoke(this, clearEvent);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao limpar notificações");
        }
    }
}