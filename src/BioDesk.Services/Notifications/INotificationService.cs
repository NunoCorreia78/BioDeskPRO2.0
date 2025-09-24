using System;
using System.Threading.Tasks;

namespace BioDesk.Services.Notifications;

/// <summary>
/// Tipos de notificação disponíveis
/// </summary>
public enum NotificationType
{
    Success,
    Error,
    Warning,
    Info
}

/// <summary>
/// Interface para serviço de notificações toast
/// </summary>
public interface INotificationService
{
    /// <summary>
    /// Mostra uma notificação de sucesso
    /// </summary>
    Task ShowSuccessAsync(string message, string? title = null, int durationMs = 4000);

    /// <summary>
    /// Mostra uma notificação de erro
    /// </summary>
    Task ShowErrorAsync(string message, string? title = null, int durationMs = 6000);

    /// <summary>
    /// Mostra uma notificação de aviso
    /// </summary>
    Task ShowWarningAsync(string message, string? title = null, int durationMs = 5000);

    /// <summary>
    /// Mostra uma notificação informativa
    /// </summary>
    Task ShowInfoAsync(string message, string? title = null, int durationMs = 4000);

    /// <summary>
    /// Mostra uma notificação personalizada
    /// </summary>
    Task ShowAsync(NotificationType type, string message, string? title = null, int durationMs = 4000);

    /// <summary>
    /// Limpa todas as notificações visíveis
    /// </summary>
    void ClearAll();

    /// <summary>
    /// Evento disparado quando uma notificação é criada
    /// </summary>
    event EventHandler<NotificationEventArgs>? NotificationRequested;
}

/// <summary>
/// Argumentos para eventos de notificação
/// </summary>
public class NotificationEventArgs : EventArgs
{
    public NotificationType Type { get; init; }
    public string Message { get; init; } = string.Empty;
    public string? Title { get; init; }
    public int DurationMs { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public Guid Id { get; init; } = Guid.NewGuid();
}