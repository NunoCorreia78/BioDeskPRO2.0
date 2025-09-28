using System;
using System.Threading.Tasks;
using System.Threading;
using System.Globalization;
using System.Windows;
using System.Windows.Markup;
using System.IO;
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
using BioDesk.Services.FuzzySearch;
using BioDesk.Services.Dashboard;
using BioDesk.Services.Activity;
using BioDesk.Services.Consultas;
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
            Console.WriteLine("🔧 OnStartup iniciado...");
            
            // Configurar cultura portuguesa para toda a aplicação
            var culture = new CultureInfo("pt-PT");
            Thread.CurrentThread.CurrentCulture = culture;
            Thread.CurrentThread.CurrentUICulture = culture;
            
            // Importante: definir para novos threads também
            CultureInfo.DefaultThreadCurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;
            
            Console.WriteLine("✅ Cultura portuguesa configurada");
            
            // Forçar o WPF a usar a cultura definida
            FrameworkElement.LanguageProperty.OverrideMetadata(
                typeof(FrameworkElement),
                new FrameworkPropertyMetadata(
                    XmlLanguage.GetLanguage(CultureInfo.CurrentCulture.IetfLanguageTag)));

            Console.WriteLine("🏗️ Configurando host com DI...");
            // Configurar o host com DI
            _host = Host.CreateDefaultBuilder()
                .ConfigureServices(ConfigureServices)
                .ConfigureLogging(logging =>
                {
                    logging.AddConsole();
                    logging.AddDebug();
                    logging.SetMinimumLevel(LogLevel.Trace);
                })
                .Build();

            Console.WriteLine("🗄️ Inicializando base de dados...");
            // Inicializar a base de dados
            await InicializarBaseDadosAsync();

            Console.WriteLine("🚀 Iniciando host...");
            // Iniciar o host
            await _host.StartAsync();

            Console.WriteLine("🪟 Criando MainWindow...");
            // Criar e mostrar a janela principal
            var mainWindow = _host.Services.GetRequiredService<MainWindow>();
            
            // Log para confirmar inicialização
            var logger = _host.Services.GetRequiredService<ILogger<App>>();
            logger.LogInformation("🚀 BioDeskPro2 inicializado com sucesso!");
            
            Console.WriteLine("📺 Mostrando MainWindow...");
            mainWindow.Show();
            logger.LogInformation("✅ MainWindow apresentada - aplicação pronta!");

            base.OnStartup(e);
            Console.WriteLine("🎉 OnStartup completado!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"💥 ERRO em OnStartup: {ex}");
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
        services.AddSingleton<IPacienteService, PacienteService>(); // 🔧 FIXE: Mudado para Singleton para manter estado PacienteAtivo
        services.AddSingleton<INotificationService, NotificationService>();
        services.AddSingleton<BioDesk.Services.Settings.ISettingsService, BioDesk.Services.Settings.SettingsService>();
        services.AddSingleton(typeof(IAutoSaveService<>), typeof(AutoSaveService<>));
        services.AddMemoryCache(); // Para IMemoryCache
        services.AddSingleton<ICacheService, CacheService>();
        services.AddSingleton<IFuzzySearchService, FuzzySearchService>(); // 🔍 Fuzzy Search
        services.AddTransient<IDashboardStatsService, DashboardStatsService>(); // 📊 Dashboard Charts - Transient
        services.AddTransient<IActivityService, ActivityService>(); // 🔔 Activity Service - Transient
        services.AddTransient<IConsultaService, ConsultaService>(); // 🩺 Consulta Service - Transient

        // ViewModels - Como Transient para evitar problemas de scoping
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<NovoPacienteViewModel>();
        services.AddTransient<FichaPacienteViewModel>();
        services.AddTransient<ListaPacientesViewModel>();
        services.AddTransient<ConsultasViewModel>(); // 🩺 Gestão Consultas

        // Views
        services.AddSingleton<MainWindow>();
        services.AddTransient<Views.DashboardView>();
        services.AddTransient<Views.NovoPacienteView>();
        services.AddTransient<Views.FichaPacienteView>();
        services.AddTransient<Views.ListaPacientesView>();
        services.AddTransient<Views.ConsultasView>(); // 🩺 View Consultas
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