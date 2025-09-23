using BioDeskPro.Core.Interfaces;
using BioDeskPro.Core.Services;
using BioDeskPro.Data;
using BioDeskPro.Data.Services;
using BioDeskPro.UI.Services;
using BioDeskPro.UI.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.IO;
using System.Windows;

namespace BioDeskPro.UI;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    public static IServiceProvider? ServiceProvider { get; private set; }
    
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        
        try
        {
            // Configurar serviços
            var services = new ServiceCollection();
            ConfigureServices(services);
            ServiceProvider = services.BuildServiceProvider();
            
            // Inicializar base de dados
            await ServiceProvider.InitializeDatabaseAsync();
            
            // Configurar NavigationService
            ConfigureNavigation();
            
            // Configurar logging
            SetupLogging();
            
            // Iniciar aplicação
            var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
            mainWindow.Show();
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao inicializar a aplicação: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            Shutdown();
        }
    }
    
    private static void ConfigureServices(ServiceCollection services)
    {
        // Data services
        services.AddBioDeskData();
        
        // Core services
        services.AddSingleton<IPacienteContext, PacienteContext>();
        services.AddSingleton<IChangeTracker, ChangeTracker>();
        services.AddSingleton<IDialogService, DialogService>();
        services.AddSingleton<NavigationService>();
        services.AddSingleton<INavigationService>(provider => provider.GetRequiredService<NavigationService>());
        
        // ViewModels
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<ListaPacientesViewModel>();
        services.AddTransient<FichaPacienteViewModel>();
        services.AddTransient<NovoPacienteViewModel>();
        
        // Views
        services.AddTransient<MainWindow>();
        services.AddTransient<Views.DashboardView>();
        services.AddTransient<Views.ListaPacientesView>();
        services.AddTransient<Views.FichaPacienteView>();
        services.AddTransient<Views.NovoPacienteView>();
        
        // Logging
        services.AddLogging(builder =>
        {
            builder.AddConsole();
#if DEBUG
            builder.SetMinimumLevel(LogLevel.Debug);
#else
            builder.SetMinimumLevel(LogLevel.Information);
#endif
        });
    }
    
    private static void SetupLogging()
    {
        // Configurar logs rotativos conforme especificado
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var bioDeskPath = Path.Combine(appDataPath, "BioDesk", "logs");
        Directory.CreateDirectory(bioDeskPath);
        
        // TODO: Implementar logs rotativos (máx X MB)
        // Por agora, vamos usar apenas console logging
    }
    
    private void ConfigureNavigation()
    {
        if (ServiceProvider == null) return;
        
        var navigationService = ServiceProvider.GetRequiredService<NavigationService>();
        
        // Registrar views e seus ViewModels
        navigationService.RegisterView("Dashboard", typeof(Views.DashboardView), typeof(ViewModels.DashboardViewModel));
        navigationService.RegisterView("ListaPacientes", typeof(Views.ListaPacientesView), typeof(ViewModels.ListaPacientesViewModel));
        navigationService.RegisterView("FichaPaciente", typeof(Views.FichaPacienteView), typeof(ViewModels.FichaPacienteViewModel));
        navigationService.RegisterView("NovoPaciente", typeof(Views.NovoPacienteView), typeof(ViewModels.NovoPacienteViewModel));
    }
    
    protected override void OnExit(ExitEventArgs e)
    {
        if (ServiceProvider is IDisposable disposable)
        {
            disposable.Dispose();
        }
        base.OnExit(e);
    }
}

