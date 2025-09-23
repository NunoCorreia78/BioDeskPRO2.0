using BioDeskPro.Core.Interfaces;
using BioDeskPro.UI.Services;
using BioDeskPro.UI.ViewModels;
using BioDeskPro.UI.Views;
using Microsoft.Extensions.DependencyInjection;
using System.Windows;
using System.Windows.Controls;

namespace BioDeskPro.UI;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        
        Console.WriteLine("🔍 DEBUG: MainWindow iniciado");
        
        // Aguardar que o Frame seja carregado
        this.Loaded += OnMainWindowLoaded;
    }
    
    private void OnMainWindowLoaded(object sender, RoutedEventArgs e)
    {
        Console.WriteLine("🔍 DEBUG: MainWindow Loaded event");
        
        // Configurar NavigationService com o Frame
        var navigationService = App.ServiceProvider?.GetService<NavigationService>();
        var mainFrame = this.FindName("MainFrame") as Frame;
        
        Console.WriteLine($"🔍 DEBUG: NavigationService é null? {navigationService == null}");
        Console.WriteLine($"🔍 DEBUG: MainFrame é null? {mainFrame == null}");
        
        if (mainFrame != null && navigationService != null)
        {
            Console.WriteLine($"🔍 DEBUG: Frame encontrado: {mainFrame.Name}");
            navigationService.SetFrame(mainFrame);
            
            // Agora navegar para o Dashboard usando o NavigationService
            Console.WriteLine("🔍 DEBUG: Navegando para Dashboard via NavigationService");
            navigationService.NavigateTo("Dashboard");
        }
        else
        {
            Console.WriteLine("❌ DEBUG: Não foi possível configurar NavigationService!");
            // Fallback para método antigo se algo falhar
            ShowDashboard();
        }
    }
    
    private void ShowDashboard()
    {
        Console.WriteLine("🔍 DEBUG: ShowDashboard chamado");
        
        // Criar e configurar DashboardView diretamente
        var dashboardView = new DashboardView();
        var dashboardViewModel = App.ServiceProvider?.GetService<DashboardViewModel>();
        
        Console.WriteLine($"🔍 DEBUG: DashboardView criado: {dashboardView != null}");
        Console.WriteLine($"🔍 DEBUG: DashboardViewModel criado: {dashboardViewModel != null}");
        
        if (dashboardView != null)
        {
            dashboardView.DataContext = dashboardViewModel;
        }
        
        var mainFrame = this.FindName("MainFrame") as Frame;
        if (mainFrame != null)
        {
            Console.WriteLine("🔍 DEBUG: Definindo DashboardView como conteúdo do Frame");
            mainFrame.Content = dashboardView;
            Console.WriteLine("✅ DEBUG: Dashboard carregado no Frame");
        }
        else
        {
            Console.WriteLine("❌ DEBUG: MainFrame não encontrado ao carregar Dashboard!");
        }
    }
}