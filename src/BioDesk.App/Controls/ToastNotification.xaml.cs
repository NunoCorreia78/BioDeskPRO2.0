using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using BioDesk.Services.Notifications;

namespace BioDesk.App.Controls;

/// <summary>
/// UserControl para notificações toast no BioDeskPro2
/// Suporte a animações e auto-close
/// </summary>
public partial class ToastNotification : UserControl
{
    private DispatcherTimer? _autoCloseTimer;
    private Storyboard? _slideInAnimation;
    private Storyboard? _slideOutAnimation;

    public event EventHandler? CloseRequested;

    public ToastNotification()
    {
        InitializeComponent();
        LoadAnimations();
    }

    public void ShowToast(NotificationType type, string message, string? title = null, int durationMs = 4000)
    {
        // Configurar estilo baseado no tipo
        ConfigureStyle(type);

        // Configurar conteúdo
        TitleText.Text = title ?? GetDefaultTitle(type);
        MessageText.Text = message;
        IconText.Text = GetIcon(type);

        // Configurar visibilidade do título
        TitleText.Visibility = string.IsNullOrEmpty(title) ? Visibility.Collapsed : Visibility.Visible;

        // Iniciar animação de entrada
        _slideInAnimation?.Begin();

        // Configurar timer para auto-close
        if (durationMs > 0)
        {
            _autoCloseTimer?.Stop();
            _autoCloseTimer = new DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(durationMs)
            };
            _autoCloseTimer.Tick += (s, e) => CloseToast();
            _autoCloseTimer.Start();
        }
    }

    private void LoadAnimations()
    {
        _slideInAnimation = (Storyboard)Resources["SlideInAnimation"];
        _slideOutAnimation = (Storyboard)Resources["SlideOutAnimation"];

        if (_slideOutAnimation != null)
        {
            _slideOutAnimation.Completed += (s, e) => CloseRequested?.Invoke(this, EventArgs.Empty);
        }
    }

    private void ConfigureStyle(NotificationType type)
    {
        var style = type switch
        {
            NotificationType.Success => (Style)Resources["SuccessToast"],
            NotificationType.Error => (Style)Resources["ErrorToast"],
            NotificationType.Warning => (Style)Resources["WarningToast"],
            NotificationType.Info => (Style)Resources["InfoToast"],
            _ => (Style)Resources["InfoToast"]
        };

        ToastBorder.Style = style;
    }

    private static string GetDefaultTitle(NotificationType type)
    {
        return type switch
        {
            NotificationType.Success => "Sucesso",
            NotificationType.Error => "Erro",
            NotificationType.Warning => "Aviso",
            NotificationType.Info => "Informação",
            _ => "Notificação"
        };
    }

    private static string GetIcon(NotificationType type)
    {
        return type switch
        {
            NotificationType.Success => "✓", // &#xE73E; for Segoe MDL2
            NotificationType.Error => "✗",   // &#xE711; for Segoe MDL2  
            NotificationType.Warning => "⚠", // &#xE7BA; for Segoe MDL2
            NotificationType.Info => "ℹ",    // &#xE946; for Segoe MDL2
            _ => "ℹ"
        };
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        CloseToast();
    }

    private void CloseToast()
    {
        _autoCloseTimer?.Stop();
        _slideOutAnimation?.Begin();
    }

    protected override void OnMouseEnter(System.Windows.Input.MouseEventArgs e)
    {
        // Pausar timer quando mouse está sobre o toast
        _autoCloseTimer?.Stop();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(System.Windows.Input.MouseEventArgs e)
    {
        // Retomar timer quando mouse sai do toast
        _autoCloseTimer?.Start();
        base.OnMouseLeave(e);
    }
}