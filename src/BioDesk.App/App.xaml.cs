using System;
using System.Linq;
using System.Threading.Tasks;
using System.Threading;
using System.Globalization;
using System.Runtime.InteropServices;
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
using BioDesk.Services;
using BioDesk.Services.Navigation;
using BioDesk.Services.Email;
using BioDesk.Services.Cache;
using BioDesk.Services.AutoSave;
using BioDesk.Services.Documentos;
using BioDesk.ViewModels;
using BioDesk.ViewModels.Abas;
using BioDesk.ViewModels.UserControls;
using BioDesk.ViewModels.UserControls.Terapia;
using BioDesk.ViewModels.Services.Terapia;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Application.Terapia.Impl;
using BioDesk.Services.Core.Infrastructure;
using BioDesk.Services.Debug;
using BioDesk.Services.Logging;

namespace BioDesk.App;

/// <summary>
/// App principal do BioDeskPro2
/// Configura├º├úo: DI Container, EF Core com SQLite, Logging
/// </summary>
public partial class App : Application
{
    // ÔÜí CRITICAL: P/Invoke para alocar console em aplica├º├úo WPF
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();


    private IHost? _host;

    /// <summary>
    /// ServiceProvider p├║blico para acesso aos servi├ºos registrados
    /// </summary>
    public IServiceProvider? ServiceProvider => _host?.Services;

    // Ô£à CRITICAL: Constructor com handlers de exceptions globais
    public App()
    {
        // ­ƒÜ¿ Capturar TODAS as exceptions n├úo tratadas
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
    }

    // Ô£à HANDLER 1: Exceptions em background threads
    private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        var exception = e.ExceptionObject as Exception;
        var errorMessage = $@"­ƒÆÑ UNHANDLED EXCEPTION (Background Thread)

Exception Type: {exception?.GetType().Name ?? "Unknown"}
Message: {exception?.Message ?? "No message"}

Stack Trace:
{exception?.StackTrace ?? "No stack trace"}

Inner Exception:
{exception?.InnerException?.Message ?? "None"}

Inner Stack:
{exception?.InnerException?.StackTrace ?? "None"}

Is Terminating: {e.IsTerminating}";

        // Log para ficheiro (SEMPRE escreve, mesmo que a app crashe)
        try
        {
            var logPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "BioDeskPro2",
                "CRASH_LOG.txt");
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(logPath)!);
            System.IO.File.WriteAllText(logPath, errorMessage);
        }
        catch { /* Ignorar se falhar */ }

        // Mostrar ao utilizador
        MessageBox.Show(errorMessage, "­ƒÜ¿ UNHANDLED EXCEPTION", MessageBoxButton.OK, MessageBoxImage.Stop);
    }

    // Ô£à HANDLER 2: Exceptions na UI thread (MAIS PROV├üVEL)
    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        var errorMessage = $@"­ƒÆÑ DISPATCHER EXCEPTION (UI Thread)

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

        // Log para ficheiro (SEMPRE escreve, mesmo que a app crashe)
        try
        {
            var logPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "BioDeskPro2",
                "CRASH_LOG_DISPATCHER.txt");
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(logPath)!);
            System.IO.File.WriteAllText(logPath, errorMessage);
        }
        catch { /* Ignorar se falhar */ }

        // Mostrar ao utilizador
        MessageBox.Show(errorMessage, "­ƒÜ¿ UI THREAD CRASH", MessageBoxButton.OK, MessageBoxImage.Stop);

        // Ô£à CRITICAL: Marcar como tratado para evitar crash silencioso
        e.Handled = true;
    }

    // Ô£à HANDLER 3: Task exceptions n├úo observadas
    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        var errorMessage = $@"­ƒÆÑ UNOBSERVED TASK EXCEPTION

Exception Type: {e.Exception.GetType().Name}
Message: {e.Exception.Message}

Stack Trace:
{e.Exception.StackTrace}

Inner Exceptions:
{string.Join("\n", e.Exception.InnerExceptions.Select(ex => $"- {ex.Message}"))}";

        // Log para ficheiro (SEMPRE escreve, mesmo que a app crashe)
        try
        {
            var logPath = System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "BioDeskPro2",
                "CRASH_LOG_TASK.txt");
            System.IO.Directory.CreateDirectory(System.IO.Path.GetDirectoryName(logPath)!);
            System.IO.File.WriteAllText(logPath, errorMessage);
        }
        catch { /* Ignorar se falhar */ }

        // Ô£à CRITICAL: Marcar como observado
        e.SetObserved();
    }

    protected override async void OnStartup(StartupEventArgs e)
    {
        try
        {
            if (Environment.UserInteractive && GetConsoleWindow() == IntPtr.Zero)
            {
                AllocConsole();
            }

            Console.WriteLine("­ƒöº OnStartup iniciado...");

            // ­ƒÅù´©Å CRIAR ESTRUTURA DE PASTAS (Debug ou Release)
            PathService.EnsureDirectories();
            Console.WriteLine("Ô£à Estrutura de pastas criada");
            Console.WriteLine(PathService.GetDiagnosticInfo());

            // ­ƒöì DIAGN├ôSTICO ADICIONAL PathService (8 OUT 2025)
            Console.WriteLine("\n" + new string('=', 80));
            Console.WriteLine("­ƒöì DIAGN├ôSTICO DETALHADO PathService");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"­ƒôé Debugger.IsAttached: {System.Diagnostics.Debugger.IsAttached}");
            Console.WriteLine($"­ƒôé CurrentDirectory: {System.IO.Directory.GetCurrentDirectory()}");
            Console.WriteLine($"­ƒôé BaseDirectory: {AppContext.BaseDirectory}");
            Console.WriteLine($"­ƒôé Contains 'BioDeskPro2': {System.IO.Directory.GetCurrentDirectory().Contains("BioDeskPro2")}");
            Console.WriteLine($"­ƒôé PathService.AppDataPath: {PathService.AppDataPath}");
            Console.WriteLine($"­ƒôé PathService.DatabasePath: {PathService.DatabasePath}");
            Console.WriteLine($"­ƒôé Database EXISTS: {System.IO.File.Exists(PathService.DatabasePath)}");

            // Verificar qual BD est├í a ser usada
            if (System.IO.File.Exists(PathService.DatabasePath))
            {
                var fileInfo = new System.IO.FileInfo(PathService.DatabasePath);
                Console.WriteLine($"­ƒôé Database SIZE: {fileInfo.Length / 1024} KB");
                Console.WriteLine($"­ƒôé Database MODIFIED: {fileInfo.LastWriteTime:dd/MM/yyyy HH:mm:ss}");
            }
            Console.WriteLine(new string('=', 80) + "\n");

            // Configurar cultura portuguesa para toda a aplica├º├úo
            var culture = new CultureInfo("pt-PT");
            Thread.CurrentThread.CurrentCulture = culture;
            Thread.CurrentThread.CurrentUICulture = culture;

            // Importante: definir para novos threads tamb├®m
            CultureInfo.DefaultThreadCurrentCulture = culture;
            CultureInfo.DefaultThreadCurrentUICulture = culture;

            Console.WriteLine("Ô£à Cultura portuguesa configurada");

            // For├ºar o WPF a usar a cultura definida
            FrameworkElement.LanguageProperty.OverrideMetadata(
                typeof(FrameworkElement),
                new FrameworkPropertyMetadata(
                    XmlLanguage.GetLanguage(CultureInfo.CurrentCulture.IetfLanguageTag)));

            Console.WriteLine("­ƒÅù´©Å Configurando host com DI...");

            // Configurar o host com DI
            _host = Host.CreateDefaultBuilder()
                .ConfigureAppConfiguration((context, config) =>
                {
                    // ÔÜí Carregar appsettings.json primeiro
                    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

                    // ÔÜí CRITICAL: Garantir carregamento de User Secrets em WPF
                    config.AddUserSecrets<App>();
                })
                .ConfigureServices(ConfigureServices)
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders(); // Limpar providers default
                    logging.AddConsole();     // Console (n├úo funciona mas n├úo faz mal)
                    logging.AddDebug();       // Debug output window
                    logging.AddFile(date => System.IO.Path.Combine(PathService.LogsPath, $"biodesk-{date:yyyyMMdd}.log"));
                    logging.SetMinimumLevel(LogLevel.Information); // Information level
                })
                .Build();

            Console.WriteLine("Ô£à Sistema limpo iniciado com sucesso...");

            Console.WriteLine("­ƒôè Aplicando migrations ao arranque...");
            // ÔÜí CRITICAL: Garantir que DB tem schema atualizado ANTES de iniciar servi├ºos
            using (var scope = _host.Services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();
                await dbContext.Database.MigrateAsync();
                Console.WriteLine("Ô£à Migrations aplicadas com sucesso!");

                dbContext.EnsureItensBancoCoreSeeded();
                // ­ƒöÑ SEED: Importar protocolos do FrequencyList.xls se BD estiver vazia
                var protocoloRepo = scope.ServiceProvider.GetRequiredService<IProtocoloRepository>();
                var totalProtocolos = await protocoloRepo.CountActiveAsync();

                if (totalProtocolos == 0)
                {
                    Console.WriteLine("´┐¢ BD vazia! Importando FrequencyList.xls...");
                    var excelService = scope.ServiceProvider.GetRequiredService<BioDesk.Services.Excel.IExcelImportService>();
                    var excelPath = System.IO.Path.Combine(Services.PathService.TemplatesPath, "Terapias", "FrequencyList.xls");

                    if (System.IO.File.Exists(excelPath))
                    {
                        try
                        {
                            var resultado = await excelService.ImportAsync(excelPath);
                            if (resultado.Sucesso)
                            {
                                Console.WriteLine($"Ô£à Importados {resultado.LinhasOk} protocolos do Excel!");
                                // Ô£à SILENCIOSO: Apenas log, sem popup (evitar interromper arranque)
                            }
                            else
                            {
                                Console.WriteLine($"ÔØî ERRO ao importar: {resultado.MensagemErro}");
                                System.Windows.MessageBox.Show($"ÔØî Erro ao importar Excel:\n{resultado.MensagemErro}\n\nA aplica├º├úo continuar├í com BD vazia.", "Erro de Importa├º├úo", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                            }
                        }
                        catch (System.Exception ex)
                        {
                            Console.WriteLine($"ÔØî EXCE├ç├âO ao importar: {ex.Message}");
                            System.Windows.MessageBox.Show($"ÔØî Exce├º├úo ao importar Excel:\n{ex.Message}\n\nA aplica├º├úo continuar├í com BD vazia.", "Erro Cr├¡tico", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                        }
                    }
                    else
                    {
                        Console.WriteLine($"ÔÜá´©Å FrequencyList.xls n├úo encontrado em: {excelPath}");
                        System.Windows.MessageBox.Show($"ÔÜá´©Å Ficheiro n├úo encontrado:\n{excelPath}\n\nPor favor, coloque o FrequencyList.xls na pasta Templates/Terapias/", "Ficheiro N├úo Encontrado", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    }
                }
                else
                {
                    Console.WriteLine($"Ô£à BD j├í tem {totalProtocolos} protocolos");
                }
            }

            Console.WriteLine("­ƒÜÇ Iniciando host...");
            // Iniciar o host
            await _host.StartAsync();

            Console.WriteLine("­ƒ¬ƒ Criando MainWindow...");
            // Criar e mostrar a janela principal
            var mainWindow = _host.Services.GetRequiredService<MainWindow>();

            // Log para confirmar inicializa├º├úo
            var logger = _host.Services.GetRequiredService<ILogger<App>>();
            logger.LogInformation("­ƒÜÇ BioDeskPro2 inicializado com sucesso!");

            Console.WriteLine("­ƒô║ Mostrando MainWindow...");
            mainWindow.Show();
            logger.LogInformation("Ô£à MainWindow apresentada - aplica├º├úo pronta!");
            Console.WriteLine("Ô£à Aplica├º├úo pronta! Aguardando intera├º├úo do utilizador...");

            base.OnStartup(e);
            Console.WriteLine("­ƒÄë OnStartup completado!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"­ƒÆÑ ERRO em OnStartup: {ex}");
            MessageBox.Show($"Erro fatal no arranque: {ex.Message}\n\nDetalhes: {ex}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            Environment.Exit(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_host != null)
        {
            // ­ƒÆ¥ BACKUP AUTOM├üTICO ao fechar aplica├º├úo
            try
            {
                Console.WriteLine("­ƒÆ¥ Criando backup autom├ítico...");
                var backupService = _host.Services.GetService<BioDesk.Services.Backup.IBackupService>();
                if (backupService != null)
                {
                    var result = Task.Run(async () => await backupService.CreateBackupAsync(
                        incluirDocumentos: false, // Backup r├ípido apenas BD
                        incluirTemplates: false)).GetAwaiter().GetResult();

                    if (result.Sucesso)
                    {
                        Console.WriteLine($"Ô£à Backup criado: {result.CaminhoZip} ({result.TamanhoFormatado})");

                        // Limpar backups antigos (manter ├║ltimos 10)
                        var removed = Task.Run(async () => await backupService.CleanOldBackupsAsync(10))
                            .GetAwaiter().GetResult();
                        if (removed > 0)
                            Console.WriteLine($"­ƒùæ´©Å {removed} backups antigos removidos");
                    }
                    else
                    {
                        Console.WriteLine($"ÔÜá´©Å Backup falhou: {result.Erro}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ÔÜá´©Å Erro no backup autom├ítico: {ex.Message}");
            }

            // Ô£à CORRETO: Task.Run evita deadlock com SynchronizationContext
            Task.Run(async () => await _host.StopAsync()).GetAwaiter().GetResult();
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
            options.UseSqlite($"Data Source={PathService.DatabasePath}")); // Ô£à Usa PathService (Debug: projeto | Release: ProgramData)

        // === REPOSITORY & TERAPIA CORE ===
        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IPacienteRepository, PacienteRepository>();
        services.AddScoped<ISessaoRepository, SessaoRepository>();
        services.AddScoped<BioDesk.Data.Repositories.IProtocoloRepository, BioDesk.Data.Repositories.ProtocoloRepository>();
        services.AddScoped<BioDesk.Data.Repositories.IItemBancoCoreRepository, BioDesk.Data.Repositories.ItemBancoCoreRepository>();

        services.AddSingleton<IActiveListService, ActiveListService>();
        services.AddSingleton<ISeedProvider, SeedProvider>();
        services.AddSingleton<IPatternValidator, PatternValidator>();
        services.AddSingleton<ICoreCatalogProvider, CoreCatalogProvider>();
        services.AddSingleton<IResonanceEngine, ResonanceEngine>();
        services.AddSingleton<IResonantFrequencyFinder, ResonantFrequencyFinder>();
        services.AddSingleton<IProgramLibrary, ProgramLibraryExcel>();
        services.AddSingleton<IImprovementModel, LogisticImprovementModel>();
        services.AddSingleton<IEmissionDevice, NullInformationalEmitter>();
        services.AddSingleton<IBiofeedbackRunner, BiofeedbackRunner>();

        services.AddMemoryCache();
        services.AddSingleton<ICacheService, CacheService>();

        // === AUTO-SAVE SERVICE (Transient - cada ViewModel tem o seu) ===
        services.AddTransient<IAutoSaveService, AutoSaveService>();

        // === EMAIL SERVICE + BACKGROUND QUEUE PROCESSOR ===
        services.AddSingleton<IEmailService, EmailService>();
        services.AddHostedService<EmailQueueProcessor>();

        // === DOCUMENTO SERVICE (gest├úo de pastas por paciente) ===
        services.AddSingleton<IDocumentoService, DocumentoService>();
        services.AddSingleton<IDocumentosPacienteService, DocumentosPacienteService>();

        // === TEMPLATE SERVICES (Templates PDF) ===
        services.AddSingleton<BioDesk.Services.Templates.ITemplatesPdfService, BioDesk.Services.Templates.TemplatesPdfService>();

        // === TEMPLATE GLOBAL SERVICE (Gest├úo de templates globais) ===
        services.AddScoped<BioDesk.Services.Templates.ITemplateGlobalService, BioDesk.Services.Templates.TemplateGlobalService>();

        // === DOCUMENTO EXTERNO PACIENTE SERVICE (Documentos externos dos pacientes) ===
        services.AddScoped<BioDesk.Services.Documentos.IDocumentoExternoPacienteService, BioDesk.Services.Documentos.DocumentoExternoPacienteService>();

        // === TEMPLATE & DOCUMENTO VIEWMODELS ===
        services.AddTransient<BioDesk.ViewModels.Templates.TemplatesGlobalViewModel>();
        services.AddTransient<BioDesk.ViewModels.Documentos.DocumentosExternosViewModel>();

        // === CAMERA SERVICE (captura REAL de ├¡ris via USB com AForge.NET) ===
        services.AddSingleton<ICameraService, RealCameraService>();

        // === IRIDOLOGY SERVICE (mapa iridol├│gico + JSON loader) ===
        services.AddSingleton<IIridologyService, IridologyService>();

        // === DEBUG SERVICES ===
        services.AddSingleton<IDragDebugService, DragDebugService>();

        // === BANCO CORE SERVICE (156 itens: Bach Florais + Chakras + Meridianos + Órgãos) ===
        services.AddScoped<BioDesk.Services.Core.IItemBancoCoreService, BioDesk.Services.Core.ItemBancoCoreService>();

        // === PDF SERVICES (QuestPDF) ===
        services.AddScoped<Services.Pdf.ConsentimentoPdfService>();
        services.AddScoped<Services.Pdf.PrescricaoPdfService>();
        services.AddScoped<Services.Pdf.DeclaracaoSaudePdfService>();

        // === EXCEL IMPORT SERVICE (EPPlus - Terapias Bioenerg├®ticas) ===
        services.AddScoped<BioDesk.Services.Excel.IExcelImportService, BioDesk.Services.Excel.ExcelImportService>();

        // === BACKUP SERVICE (Sistema de Backup/Restore Autom├ítico) ­ƒöÑ CR├ìTICO ===
        services.AddSingleton<BioDesk.Services.Backup.IBackupService, BioDesk.Services.Backup.BackupService>();
        Console.WriteLine("­ƒÆ¥ Backup Service: REGISTRADO (Backup autom├ítico + Restore)");

        // === HTTP CLIENT FACTORY (para Random.org atmospheric RNG) ===
        services.AddHttpClient("RandomOrg", client =>
        {
            client.BaseAddress = new Uri("https://www.random.org/");
            client.Timeout = TimeSpan.FromSeconds(10);
        });

        // === RNG SERVICE (True Random Number Generator - Terapias Bioenerg├®ticas) ===
        services.AddSingleton<BioDesk.Services.Rng.IRngService, BioDesk.Services.Rng.RngService>();

        // === VALUE SCANNING SERVICE (CoRe 5.0 Algorithm - Value % Scanning) ===
        services.AddSingleton<BioDesk.Services.Terapias.IValueScanningService, BioDesk.Services.Terapias.ValueScanningService>();
        Console.WriteLine("­ƒöì Value Scanning Service: REGISTRADO (CoRe 5.0 Algorithm)");

        // === TIEPIE HARDWARE SERVICE (Handyscope HS5 - Gerador de Sinais) ===
        // ´┐¢ TOGGLE: Ler configura├º├úo appsettings.json para decidir Dummy vs Real
        var configuration = services.BuildServiceProvider().GetRequiredService<IConfiguration>();
        var useDummyTiePie = configuration.GetValue<bool>("Hardware:UseDummyTiePie", defaultValue: false);

        if (useDummyTiePie)
        {
            // ÔÜí MODO DUMMY: Para testes sem hardware
            services.AddSingleton<BioDesk.Services.Hardware.ITiePieHardwareService, BioDesk.Services.Hardware.DummyTiePieHardwareService>();
            Console.WriteLine("­ƒÄ¡ TiePie Hardware: DUMMY mode (appsettings.json: UseDummyTiePie=true)");
        }
        else
        {
            // ­ƒö┤ MODO REAL: Hardware f├¡sico conectado via USB (LibTiePie SDK)
            // Com tratamento de erro - N├âO crash se SDK/hardware n├úo dispon├¡vel
            services.AddSingleton<BioDesk.Services.Hardware.ITiePieHardwareService, BioDesk.Services.Hardware.RealTiePieHardwareService>();
            Console.WriteLine("ÔÜí TiePie Hardware: REAL mode (appsettings.json: UseDummyTiePie=false ou n├úo definido)");
        }

        // === MEDI├ç├âO SERVICE (Biofeedback INPUT - Oscilloscope) ===
        // ­ƒöä TOGGLE: Ler configura├º├úo appsettings.json para decidir Dummy vs Real
        var useDummyMedicao = configuration.GetValue<bool>("Hardware:UseDummyMedicao", defaultValue: false);

        if (useDummyMedicao)
        {
            // ÔÜí MODO DUMMY: Simula├º├úo para testes sem hardware
            services.AddSingleton<BioDesk.Services.Medicao.IMedicaoService, BioDesk.Services.Medicao.DummyMedicaoService>();
            Console.WriteLine("­ƒÄ¡ Medi├º├úo Hardware: DUMMY mode (appsettings.json: UseDummyMedicao=true)");
        }
        else
        {
            // ­ƒö┤ MODO REAL: TiePie Oscilloscope INPUT (LibTiePie SDK)
            // Com tratamento de erro - N├âO crash se SDK/hardware n├úo dispon├¡vel
            services.AddSingleton<BioDesk.Services.Medicao.IMedicaoService, BioDesk.Services.Medicao.RealMedicaoService>();
            Console.WriteLine("ÔÜí Medi├º├úo Hardware: REAL mode (appsettings.json: UseDummyMedicao=false ou n├úo definido)");
        }

        // === FLUENTVALIDATION VALIDATORS (Regras de Neg├│cio) ­ƒöÆ ===
        services.AddScoped<FluentValidation.IValidator<BioDesk.Domain.Entities.ProtocoloTerapeutico>, BioDesk.Domain.Validators.ProtocoloTerapeuticoValidator>();
        services.AddScoped<FluentValidation.IValidator<BioDesk.Domain.DTOs.TerapiaFilaItem>, BioDesk.Domain.Validators.TerapiaFilaItemValidator>();
        Console.WriteLine("­ƒöÆ FluentValidation: REGISTRADO (ProtocoloTerapeutico + TerapiaFilaItem)");

        // === VIEWMODELS ===
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<FichaPacienteViewModel>();
        services.AddTransient<ListaPacientesViewModel>(); // Ô£à LISTA DE PACIENTES
        services.AddTransient<ConfiguracoesViewModel>(); // Ô£à CONFIGURA├ç├òES (Email SMTP)
        services.AddTransient<ConfiguracaoClinicaViewModel>(); // Ô£à CONFIGURA├ç├âO CL├ìNICA

        // ViewModels das Abas
        services.AddTransient<DeclaracaoSaudeViewModel>();
        services.AddTransient<ConsentimentosViewModel>();
        services.AddTransient<RegistoConsultasViewModel>(); // ABA 4: Registo de Sess├Áes
        services.AddTransient<IrisdiagnosticoViewModel>(); // Ô£à ABA 5: Irisdiagn├│stico
        services.AddTransient<ComunicacaoViewModel>();
        services.AddTransient<BioDesk.ViewModels.FichaPaciente.TerapiasBioenergeticasViewModel>();
        services.AddTransient<TerapiasBioenergeticasUserControlViewModel>();
        services.AddTransient<AvaliacaoViewModel>();
        services.AddTransient<ProgramasViewModel>();
        services.AddTransient<RessonantesViewModel>();
        services.AddTransient<BiofeedbackViewModel>();
        services.AddTransient<HistoricoViewModel>();
        services.AddTransient<TerapiaCoreViewModel>();
        services.AddTransient<SelecionarTemplatesViewModel>();

        // UserControls (precisam de DI para construtores parametrizados)
        services.AddTransient<Views.Abas.TerapiasBioenergeticasUserControl>(); // Ô£à ABA 8: Terapias

        // Views - SISTEMA LIMPO
        services.AddSingleton<MainWindow>();
        services.AddTransient<Views.DashboardView>();
        services.AddTransient<Views.ConsultasView>();
        services.AddTransient<Views.Dialogs.ConfiguracoesWindow>(); // Ô£à JANELA CONFIGURA├ç├òES CL├ìNICA
        services.AddTransient<Views.FichaPacienteView>();
        services.AddTransient<Views.ListaPacientesView>(); // Ô£à LISTA DE PACIENTES
        services.AddTransient<Views.ConfiguracoesView>(); // Ô£à CONFIGURA├ç├òES
    }
}


