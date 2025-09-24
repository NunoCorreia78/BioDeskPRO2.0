using System;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Notifications;
using BioDesk.Services.AutoSave;
using BioDesk.Services.Cache;
using BioDesk.ViewModels;

namespace BioDesk.App;

/// <summary>
/// App principal do BioDeskPro2
/// Configuração: DI Container, EF Core com SQLite, Logging
/// </summary>
public partial class App : Application
{
    private IHost? _host;

    /// <summary>
    /// ServiceProvider público para acesso aos serviços registrados
    /// </summary>
    public IServiceProvider? ServiceProvider => _host?.Services;

    protected override async void OnStartup(StartupEventArgs e)
    {
        try
        {
            // Configurar o host com DI
            _host = Host.CreateDefaultBuilder()
                .ConfigureServices(ConfigureServices)
                .ConfigureLogging(logging =>
                {
                    logging.AddConsole();
                    logging.AddDebug();
                    logging.SetMinimumLevel(LogLevel.Information);
                })
                .Build();

            // Inicializar a base de dados
            await InicializarBaseDadosAsync();

            // Iniciar o host
            await _host.StartAsync();

            // Criar e mostrar a janela principal
            var mainWindow = _host.Services.GetRequiredService<MainWindow>();
            mainWindow.Show();

            base.OnStartup(e);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro fatal no arranque: {ex.Message}\n\nDetalhes: {ex}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            Environment.Exit(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_host != null)
        {
            _host.StopAsync().Wait();
            _host.Dispose();
        }

        base.OnExit(e);
    }

    private static void ConfigureServices(IServiceCollection services)
    {
        // Entity Framework
        services.AddDbContext<BioDeskContext>(options =>
            options.UseSqlite("Data Source=biodesk.db"));

        // Serviços
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddScoped<IPacienteService, PacienteService>();
        services.AddSingleton<INotificationService, NotificationService>();
        services.AddSingleton(typeof(IAutoSaveService<>), typeof(AutoSaveService<>));
        services.AddMemoryCache(); // Para IMemoryCache
        services.AddSingleton<ICacheService, CacheService>();

        // ViewModels
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<NovoPacienteViewModel>();
        services.AddTransient<FichaPacienteViewModel>();
        services.AddTransient<ListaPacientesViewModel>();

        // Views
        services.AddSingleton<MainWindow>();
        services.AddTransient<Views.DashboardView>();
        services.AddTransient<Views.NovoPacienteView>();
        services.AddTransient<Views.FichaPacienteView>();
        services.AddTransient<Views.ListaPacientesView>();
        services.AddTransient<Views.FichaPacienteView>();
        services.AddTransient<Views.ListaPacientesView>();
    }

    private async Task InicializarBaseDadosAsync()
    {
        try
        {
            var serviceScope = _host!.Services.CreateScope();
            var context = serviceScope.ServiceProvider.GetRequiredService<BioDeskContext>();
            
            // Criar a base de dados e aplicar migrações
            await context.Database.EnsureCreatedAsync();
            
            var logger = _host.Services.GetRequiredService<ILogger<App>>();
            logger.LogInformation("Base de dados inicializada com sucesso");
        }
        catch (Exception ex)
        {
            var logger = _host!.Services.GetRequiredService<ILogger<App>>();
            logger.LogError(ex, "Erro ao inicializar a base de dados");
            throw;
        }
    }
}