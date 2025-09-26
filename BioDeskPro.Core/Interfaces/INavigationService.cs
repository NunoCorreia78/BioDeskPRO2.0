namespace BioDeskPro.Core.Interfaces;

public interface INavigationService
{
    // Navegação básica
    void NavigateTo(string viewName, object? parameter = null);
    void NavigateTo<T>(object? parameter = null) where T : class;
    
    // Controle de histórico
    bool CanGoBack { get; }
    bool CanGoForward { get; }
    void GoBack();
    void GoForward();
    void ClearHistory();
    
    // Navegação com guard de IsDirty
    Task<bool> NavigateToAsync(string viewName, object? parameter = null);
    Task<bool> NavigateToAsync<T>(object? parameter = null) where T : class;
    
    // Informações sobre navegação atual
    string? CurrentView { get; }
    object? CurrentParameter { get; }
    
    // Eventos
    event EventHandler<NavigationEventArgs>? Navigating;
    event EventHandler<NavigationEventArgs>? Navigated;
    
    // Registro de views
    void RegisterView<TView, TViewModel>() where TView : class where TViewModel : class;
    void RegisterView(string viewName, Type viewType, Type? viewModelType = null);
    
    // Validação antes de navegar
    Func<Task<bool>>? NavigationGuard { get; set; }
}

public class NavigationEventArgs : EventArgs
{
    public string ViewName { get; }
    public object? Parameter { get; }
    public bool Cancel { get; set; }
    
    public NavigationEventArgs(string viewName, object? parameter = null)
    {
        ViewName = viewName;
        Parameter = parameter;
    }
}