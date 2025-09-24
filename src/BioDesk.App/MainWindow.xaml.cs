using System;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using BioDesk.Services.Navigation;
using BioDesk.ViewModels;

namespace BioDesk.App;

/// <summary>
/// MainWindow do BioDeskPro2
/// Contém o sistema de navegação e inicialização do Dashboard
/// </summary>
public partial class MainWindow : Window
{
    private readonly IServiceProvider _serviceProvider;
    private readonly INavigationService _navigationService;

    public MainWindow(IServiceProvider serviceProvider, INavigationService navigationService)
    {
        InitializeComponent();
        
        _serviceProvider = serviceProvider;
        _navigationService = navigationService;

        // Armazenar o serviceProvider para acesso das views filhas
        this.Tag = serviceProvider;

        // Configurar navegação
        ConfigurarNavegacao();

        // Navegar para o Dashboard
        _navigationService.NavigateTo("Dashboard");
    }

    private void ConfigurarNavegacao()
    {
        // Registar views no sistema de navegação
        _navigationService.Register("Dashboard", typeof(Views.DashboardView));
        _navigationService.Register("NovoPaciente", typeof(Views.NovoPacienteView));
        _navigationService.Register("ListaPacientes", typeof(Views.ListaPacientesView));
        _navigationService.Register("FichaPaciente", typeof(Views.FichaPacienteView));

        // Subscrever ao evento de navegação
        _navigationService.NavigationRequested += OnNavigationRequested;
    }

    private async void OnNavigationRequested(object? sender, string viewName)
    {
        if (!Dispatcher.CheckAccess())
        {
            Dispatcher.Invoke(() => OnNavigationRequested(sender, viewName));
            return;
        }

        try
        {
            var viewType = ((NavigationService)_navigationService).GetViewType(viewName);
            if (viewType == null) 
            {
                MessageBox.Show($"Tipo de view '{viewName}' não encontrado.", "Erro de Navegação", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // Criar a view usando o DI container
            FrameworkElement? view = null;
            switch (viewName)
            {
                case "Dashboard":
                    view = _serviceProvider.GetRequiredService<Views.DashboardView>();
                    break;
                case "NovoPaciente":
                    view = _serviceProvider.GetRequiredService<Views.NovoPacienteView>();
                    break;
                case "FichaPaciente":
                    view = _serviceProvider.GetRequiredService<Views.FichaPacienteView>();
                    break;
                case "ListaPacientes":
                    view = _serviceProvider.GetRequiredService<Views.ListaPacientesView>();
                    break;
            }

            if (view == null) 
            {
                MessageBox.Show($"Não foi possível criar instância da view '{viewName}'.", "Erro de Navegação", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // Definir o DataContext baseado na view
            switch (viewName)
            {
                case "Dashboard":
                    var dashboardViewModel = _serviceProvider.GetRequiredService<DashboardViewModel>();
                    view.DataContext = dashboardViewModel;
                    
                    ContentArea.Content = view;
                    await dashboardViewModel.CarregarDadosAsync();
                    return;

                case "NovoPaciente":
                    var novoPacienteViewModel = _serviceProvider.GetRequiredService<NovoPacienteViewModel>();
                    view.DataContext = novoPacienteViewModel;
                    break;
                    
                case "FichaPaciente":
                    var fichaPacienteViewModel = _serviceProvider.GetRequiredService<FichaPacienteViewModel>();
                    view.DataContext = fichaPacienteViewModel;
                    break;
                    
                case "ListaPacientes":
                    var listaPacientesViewModel = _serviceProvider.GetRequiredService<ListaPacientesViewModel>();
                    view.DataContext = listaPacientesViewModel;
                    ContentArea.Content = view;
                    await listaPacientesViewModel.CarregarDadosAsync();
                    return;
            }

            // Substituir o conteúdo principal
            ContentArea.Content = view;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao navegar para '{viewName}': {ex.Message}", "Erro de Navegação", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}