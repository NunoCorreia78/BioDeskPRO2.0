using BioDeskPro.Core.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using System.Windows;
using System.Windows.Controls;
using System.Diagnostics;

namespace BioDeskPro.UI.Services;

public class NavigationService : INavigationService
{
    private readonly Dictionary<string, Type> _viewTypes = new();
    private readonly Dictionary<Type, Type> _viewModelTypes = new();
    private readonly Stack<NavigationEntry> _backStack = new();
    private readonly Stack<NavigationEntry> _forwardStack = new();
    private readonly IChangeTracker _changeTracker;
    private readonly IDialogService _dialogService;
    private readonly IServiceProvider _serviceProvider;
    private NavigationEntry? _current;
    private Frame? _frame;
    
    public NavigationService(IChangeTracker changeTracker, IDialogService dialogService, IServiceProvider serviceProvider)
    {
        _changeTracker = changeTracker ?? throw new ArgumentNullException(nameof(changeTracker));
        _dialogService = dialogService ?? throw new ArgumentNullException(nameof(dialogService));
        _serviceProvider = serviceProvider ?? throw new ArgumentNullException(nameof(serviceProvider));
        
        // Configurar o guard de navegação para verificar IsDirty
        NavigationGuard = CheckDirtyStateAsync;
    }
    
    public string? CurrentView => _current?.ViewName;
    public object? CurrentParameter => _current?.Parameter;
    public bool CanGoBack => _backStack.Count > 0;
    public bool CanGoForward => _forwardStack.Count > 0;
    
    public Func<Task<bool>>? NavigationGuard { get; set; }
    
    public event EventHandler<NavigationEventArgs>? Navigating;
    public event EventHandler<NavigationEventArgs>? Navigated;
    
    public void SetFrame(Frame frame)
    {
        _frame = frame ?? throw new ArgumentNullException(nameof(frame));
        Console.WriteLine($"✅ DEBUG: Frame configurado no NavigationService: {frame.Name}");
        Console.WriteLine($"✅ DEBUG: Frame Parent: {frame.Parent?.GetType().Name}");
        Console.WriteLine($"✅ DEBUG: Frame ActualWidth: {frame.ActualWidth}, ActualHeight: {frame.ActualHeight}");
    }
    
    public void NavigateTo(string viewName, object? parameter = null)
    {
        Console.WriteLine($"🔍 DEBUG: NavigateTo chamado para '{viewName}'");
        Console.WriteLine($"🔍 DEBUG: Frame é null? {_frame == null}");
        Console.WriteLine($"🔍 DEBUG: Views registradas: {string.Join(", ", _viewTypes.Keys)}");
        _ = NavigateToAsync(viewName, parameter);
    }
    
    public void NavigateTo<T>(object? parameter = null) where T : class
    {
        NavigateTo(typeof(T).Name, parameter);
    }
    
    public async Task<bool> NavigateToAsync(string viewName, object? parameter = null)
    {
        // Executar navigation guard se existir
        if (NavigationGuard != null)
        {
            var canNavigate = await NavigationGuard();
            if (!canNavigate)
                return false;
        }
        
        // Disparar evento Navigating
        var navigatingArgs = new NavigationEventArgs(viewName, parameter);
        Navigating?.Invoke(this, navigatingArgs);
        
        if (navigatingArgs.Cancel)
            return false;
        
        // Verificar se a view está registrada
        Console.WriteLine($"🔍 DEBUG: Verificando se '{viewName}' está registrada...");
        if (!_viewTypes.TryGetValue(viewName, out var viewType))
        {
            Console.WriteLine($"❌ DEBUG: View '{viewName}' NÃO está registrada!");
            Console.WriteLine($"❌ DEBUG: Views disponíveis: {string.Join(", ", _viewTypes.Keys)}");
            throw new InvalidOperationException($"View '{viewName}' não está registrada");
        }
        Console.WriteLine($"✅ DEBUG: View '{viewName}' encontrada: {viewType.Name}");
        
        try
        {
            Console.WriteLine($"🔍 DEBUG: Criando instância da view '{viewType.Name}'...");
            // Criar a instância da view
            var view = Activator.CreateInstance(viewType);
            
            if (view is not UserControl userControl)
            {
                Console.WriteLine($"❌ DEBUG: View '{viewName}' não herda de UserControl!");
                throw new InvalidOperationException($"View '{viewName}' deve herdar de UserControl");
            }
            Console.WriteLine($"✅ DEBUG: UserControl criado com sucesso");
            
            // Configurar ViewModel se existir
            if (_viewModelTypes.TryGetValue(viewType, out var viewModelType))
            {
                Console.WriteLine($"🔍 DEBUG: Criando ViewModel '{viewModelType.Name}'...");
                var viewModel = _serviceProvider.GetRequiredService(viewModelType);
                userControl.DataContext = viewModel;
                Console.WriteLine($"✅ DEBUG: ViewModel configurado");
            }
            else
            {
                Console.WriteLine($"⚠️ DEBUG: Nenhum ViewModel registrado para '{viewName}'");
            }
            
            // Adicionar à pilha de navegação
            if (_current != null)
            {
                _backStack.Push(_current);
                _forwardStack.Clear(); // Limpar forward stack quando navegamos para nova página
            }
            
            _current = new NavigationEntry(viewName, parameter);
            
            // Navegar no Frame se existir
            Console.WriteLine($"🔍 DEBUG: Frame é null? {_frame == null}");
            if (_frame != null)
            {
                Console.WriteLine($"🔍 DEBUG: Definindo conteúdo do Frame...");
                _frame.Content = userControl;
                Console.WriteLine($"✅ DEBUG: Navegação concluída para '{viewName}'");
            }
            else
            {
                Console.WriteLine($"❌ DEBUG: Frame é null! Não é possível navegar.");
            }
            
            // Marcar como limpo após navegação bem-sucedida
            _changeTracker.MarkClean();
            
            // Disparar evento Navigated
            Navigated?.Invoke(this, new NavigationEventArgs(viewName, parameter));
            
            return true;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Erro ao navegar para '{viewName}': {ex.Message}", ex);
        }
    }
    
    public async Task<bool> NavigateToAsync<T>(object? parameter = null) where T : class
    {
        return await NavigateToAsync(typeof(T).Name, parameter);
    }
    
    public void GoBack()
    {
        if (!CanGoBack) return;
        
        var previous = _backStack.Pop();
        
        if (_current != null)
        {
            _forwardStack.Push(_current);
        }
        
        _current = previous;
        _ = NavigateToAsync(previous.ViewName, previous.Parameter);
    }
    
    public void GoForward()
    {
        if (!CanGoForward) return;
        
        var next = _forwardStack.Pop();
        
        if (_current != null)
        {
            _backStack.Push(_current);
        }
        
        _current = next;
        _ = NavigateToAsync(next.ViewName, next.Parameter);
    }
    
    public void ClearHistory()
    {
        _backStack.Clear();
        _forwardStack.Clear();
    }
    
    public void RegisterView<TView, TViewModel>() 
        where TView : class 
        where TViewModel : class
    {
        RegisterView(typeof(TView).Name, typeof(TView), typeof(TViewModel));
    }
    
    public void RegisterView(string viewName, Type viewType, Type? viewModelType = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(viewName);
        ArgumentNullException.ThrowIfNull(viewType);
        
        _viewTypes[viewName] = viewType;
        
        if (viewModelType != null)
        {
            _viewModelTypes[viewType] = viewModelType;
        }
    }
    
    private async Task<bool> CheckDirtyStateAsync()
    {
        if (!_changeTracker.IsDirty)
            return true;
        
        // Executar no thread da UI
        var result = DialogResult.Cancel;
        
        await Application.Current.Dispatcher.InvokeAsync(() =>
        {
            result = _dialogService.ShowSaveChangesDialog();
        });
        
        switch (result)
        {
            case DialogResult.Save:
                // TODO: Implementar lógica de guardar
                // Por agora, apenas marcar como limpo
                _changeTracker.MarkClean();
                return true;
            
            case DialogResult.DontSave:
                // Descartar alterações
                _changeTracker.MarkClean();
                return true;
            
            case DialogResult.Cancel:
            default:
                // Cancelar navegação
                return false;
        }
    }
    
    private record NavigationEntry(string ViewName, object? Parameter);
}