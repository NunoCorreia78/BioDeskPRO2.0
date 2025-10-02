using System;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using System.Globalization;
using System.Windows;
using System.Windows.Markup;
using System.Windows.Threading;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;
using BioDesk.Data.Repositories;
using BioDesk.Services.Navigation;
using BioDesk.Services.Email;
using BioDesk.Services.Cache;
using BioDesk.Services.AutoSave;
using BioDesk.Services.Documentos;
using BioDesk.ViewModels;
using BioDesk.ViewModels.Abas;

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

    // ✅ CRITICAL: Constructor com handlers de exceptions globais
    public App()
    {
        // 🚨 Capturar TODAS as exceptions não tratadas
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    // ✅ HANDLER 1: Exceptions em background threads
    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var exception = e.ExceptionObject as Exception;
        var errorMessage = $@"💥 UNHANDLED EXCEPTION (Background Thread)

Exception Type: {exception?.GetType().Name ?? "Unknown"}
Message: {exception?.Message ?? "No message"}

Stack Trace:
{exception?.StackTrace ?? "No stack trace"}

Inner Exception:
{exception?.InnerException?.Message ?? "None"}

Inner Stack:
{exception?.InnerException?.StackTrace ?? "None"}

Is Terminating: {e.IsTerminating}";

        // Log para ficheiro
        System.IO.File.WriteAllText(@"C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2\UNHANDLED_EXCEPTION.txt", errorMessage);

        // Mostrar ao utilizador
        MessageBox.Show(errorMessage, "🚨 UNHANDLED EXCEPTION", MessageBoxButton.OK, MessageBoxImage.Stop);
    }

    // ✅ HANDLER 2: Exceptions na UI thread (MAIS PROVÁVEL)
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var errorMessage = $@"💥 DISPATCHER EXCEPTION (UI Thread)

Exception Type: {e.Exception.GetType().Name}
Message: {e.Exception.Message}

Stack Trace:
{e.Exception.StackTrace}

Inner Exception:
{e.Exception.InnerException?.Message ?? "None"}

Inner Stack:
{e.Exception.InnerException?.StackTrace ?? "None"}

Source: {e.Exception.Source}
Target Site: {e.Exception.TargetSite?.Name ?? "Unknown"}";

        // Log para ficheiro
        System.IO.File.WriteAllText(@"C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2\DISPATCHER_EXCEPTION.txt", errorMessage);

        // Mostrar ao utilizador
        MessageBox.Show(errorMessage, "🚨 UI THREAD CRASH", MessageBoxButton.OK, MessageBoxImage.Stop);

        // ✅ CRITICAL: Marcar como tratado para evitar crash silencioso
        e.Handled = true;
    }

    // ✅ HANDLER 3: Task exceptions não observadas
    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        var errorMessage = $@"💥 UNOBSERVED TASK EXCEPTION

Exception Type: {e.Exception.GetType().Name}
Message: {e.Exception.Message}

Stack Trace:
{e.Exception.StackTrace}

Inner Exceptions:
{string.Join("\n", e.Exception.InnerExceptions.Select(ex => $"- {ex.Message}"))}";

        // Log para ficheiro
        System.IO.File.WriteAllText(@"C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2\TASK_EXCEPTION.txt", errorMessage);

        // ✅ CRITICAL: Marcar como observado
        e.SetObserved();
    }

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
                .ConfigureAppConfiguration((context, config) =>
                {
                    // ⚡ CRITICAL: Garantir carregamento de User Secrets em WPF
                    config.AddUserSecrets<App>();
                })
                .ConfigureServices(ConfigureServices)
                .ConfigureLogging(logging =>
                {
                    logging.AddConsole();
                    logging.AddDebug();
                    logging.SetMinimumLevel(LogLevel.Trace);
                })
                .Build();

            Console.WriteLine("✅ Sistema limpo iniciado com sucesso...");

            Console.WriteLine("�️ Aplicando migrations ao arranque...");
            // ⚡ CRITICAL: Garantir que DB tem schema atualizado ANTES de iniciar serviços
            using (var scope = _host.Services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();
                await dbContext.Database.MigrateAsync();
                Console.WriteLine("✅ Migrations aplicadas com sucesso!");
            }

            Console.WriteLine("�🚀 Iniciando host...");
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
        // === NAVIGATION ===
        services.AddSingleton<INavigationService, NavigationService>();

        // === DATABASE: EF Core + SQLite ===
        services.AddDbContext<BioDeskDbContext>(options =>
            options.UseSqlite("Data Source=biodesk.db")); // Relative to App folder

        // === REPOSITORY PATTERN + UNIT OF WORK ===
        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IPacienteRepository, PacienteRepository>();
        services.AddScoped<ISessaoRepository, SessaoRepository>();

        // === CACHE SERVICE (Singleton para performance) ===
        services.AddMemoryCache();
        services.AddSingleton<ICacheService, CacheService>();

        // === AUTO-SAVE SERVICE (Transient - cada ViewModel tem o seu) ===
        services.AddTransient<IAutoSaveService, AutoSaveService>();

        // === EMAIL SERVICE + BACKGROUND QUEUE PROCESSOR ===
        services.AddSingleton<IEmailService, EmailService>();
        services.AddHostedService<EmailQueueProcessor>();

        // === DOCUMENTO SERVICE (gestão de pastas por paciente) ===
        services.AddSingleton<IDocumentoService, DocumentoService>();
        services.AddSingleton<IDocumentosPacienteService, DocumentosPacienteService>();

        // === PDF SERVICES (QuestPDF) ===
        services.AddScoped<Services.Pdf.ConsentimentoPdfService>();
        services.AddScoped<Services.Pdf.PrescricaoPdfService>();
        services.AddScoped<Services.Pdf.DeclaracaoSaudePdfService>();

        // === VIEWMODELS ===
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<FichaPacienteViewModel>();
        services.AddTransient<ListaPacientesViewModel>(); // ✅ LISTA DE PACIENTES
        services.AddTransient<ConfiguracoesViewModel>(); // ✅ CONFIGURAÇÕES

        // ViewModels das Abas
        services.AddTransient<DeclaracaoSaudeViewModel>();
        services.AddTransient<ConsentimentosViewModel>();
        services.AddTransient<RegistoConsultasViewModel>(); // ABA 4: Registo de Sessões
        services.AddTransient<ComunicacaoViewModel>(); // ✅ ABA 5: Comunicação

        // Views - SISTEMA LIMPO
        services.AddSingleton<MainWindow>();
        services.AddTransient<Views.DashboardView>();
        services.AddTransient<Views.ConsultasView>();
        services.AddTransient<Views.FichaPacienteView>();
        services.AddTransient<Views.ListaPacientesView>(); // ✅ LISTA DE PACIENTES
        services.AddTransient<Views.ConfiguracoesView>(); // ✅ CONFIGURAÇÕES
    }
}
