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
using BioDesk.Services.Debug;

namespace BioDesk.App;

/// <summary>
/// App principal do BioDeskPro2
/// Configuração: DI Container, EF Core com SQLite, Logging
/// </summary>
public partial class App : Application
{
    // ⚡ CRITICAL: P/Invoke para alocar console em aplicação WPF
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

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

        // ✅ CRITICAL: Marcar como observado
        e.SetObserved();
    }

    protected override async void OnStartup(StartupEventArgs e)
    {
        try
        {
            Console.WriteLine("🔧 OnStartup iniciado...");

            // 🏗️ CRIAR ESTRUTURA DE PASTAS (Debug ou Release)
            PathService.EnsureDirectories();
            Console.WriteLine("✅ Estrutura de pastas criada");
            Console.WriteLine(PathService.GetDiagnosticInfo());

            // 🔍 DIAGNÓSTICO ADICIONAL PathService (8 OUT 2025)
            Console.WriteLine("\n" + new string('=', 80));
            Console.WriteLine("🔍 DIAGNÓSTICO DETALHADO PathService");
            Console.WriteLine(new string('=', 80));
            Console.WriteLine($"📂 Debugger.IsAttached: {System.Diagnostics.Debugger.IsAttached}");
            Console.WriteLine($"📂 CurrentDirectory: {System.IO.Directory.GetCurrentDirectory()}");
            Console.WriteLine($"📂 BaseDirectory: {AppContext.BaseDirectory}");
            Console.WriteLine($"📂 Contains 'BioDeskPro2': {System.IO.Directory.GetCurrentDirectory().Contains("BioDeskPro2")}");
            Console.WriteLine($"📂 PathService.AppDataPath: {PathService.AppDataPath}");
            Console.WriteLine($"📂 PathService.DatabasePath: {PathService.DatabasePath}");
            Console.WriteLine($"📂 Database EXISTS: {System.IO.File.Exists(PathService.DatabasePath)}");

            // Verificar qual BD está a ser usada
            if (System.IO.File.Exists(PathService.DatabasePath))
            {
                var fileInfo = new System.IO.FileInfo(PathService.DatabasePath);
                Console.WriteLine($"📂 Database SIZE: {fileInfo.Length / 1024} KB");
                Console.WriteLine($"📂 Database MODIFIED: {fileInfo.LastWriteTime:dd/MM/yyyy HH:mm:ss}");
            }
            Console.WriteLine(new string('=', 80) + "\n");

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
                    // ⚡ Carregar appsettings.json primeiro
                    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

                    // ⚡ CRITICAL: Garantir carregamento de User Secrets em WPF
                    config.AddUserSecrets<App>();
                })
                .ConfigureServices(ConfigureServices)
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders(); // Limpar providers default
                    logging.AddConsole();     // Console (não funciona mas não faz mal)
                    logging.AddDebug();       // Debug output window
                    logging.SetMinimumLevel(LogLevel.Information); // Information level
                })
                .Build();

            Console.WriteLine("✅ Sistema limpo iniciado com sucesso...");

            Console.WriteLine("📊 Aplicando migrations ao arranque...");
            // ⚡ CRITICAL: Garantir que DB tem schema atualizado ANTES de iniciar serviços
            using (var scope = _host.Services.CreateScope())
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();
                await dbContext.Database.MigrateAsync();
                Console.WriteLine("✅ Migrations aplicadas com sucesso!");

                // 🔥 SEED: Importar protocolos do FrequencyList.xls se BD estiver vazia
                var protocoloRepo = scope.ServiceProvider.GetRequiredService<IProtocoloRepository>();
                var totalProtocolos = await protocoloRepo.CountActiveAsync();

                if (totalProtocolos == 0)
                {
                    Console.WriteLine("� BD vazia! Importando FrequencyList.xls...");
                    var excelService = scope.ServiceProvider.GetRequiredService<BioDesk.Services.Excel.IExcelImportService>();
                    var excelPath = System.IO.Path.Combine(Services.PathService.TemplatesPath, "Terapias", "FrequencyList.xls");

                    if (System.IO.File.Exists(excelPath))
                    {
                        try
                        {
                            var resultado = await excelService.ImportAsync(excelPath);
                            if (resultado.Sucesso)
                            {
                                Console.WriteLine($"✅ Importados {resultado.LinhasOk} protocolos do Excel!");
                                // ✅ SILENCIOSO: Apenas log, sem popup (evitar interromper arranque)
                            }
                            else
                            {
                                Console.WriteLine($"❌ ERRO ao importar: {resultado.MensagemErro}");
                                System.Windows.MessageBox.Show($"❌ Erro ao importar Excel:\n{resultado.MensagemErro}\n\nA aplicação continuará com BD vazia.", "Erro de Importação", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                            }
                        }
                        catch (System.Exception ex)
                        {
                            Console.WriteLine($"❌ EXCEÇÃO ao importar: {ex.Message}");
                            System.Windows.MessageBox.Show($"❌ Exceção ao importar Excel:\n{ex.Message}\n\nA aplicação continuará com BD vazia.", "Erro Crítico", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
                        }
                    }
                    else
                    {
                        Console.WriteLine($"⚠️ FrequencyList.xls não encontrado em: {excelPath}");
                        System.Windows.MessageBox.Show($"⚠️ Ficheiro não encontrado:\n{excelPath}\n\nPor favor, coloque o FrequencyList.xls na pasta Templates/Terapias/", "Ficheiro Não Encontrado", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Warning);
                    }
                }
                else
                {
                    Console.WriteLine($"✅ BD já tem {totalProtocolos} protocolos");
                }
            }

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
            Console.WriteLine("✅ Aplicação pronta! Aguardando interação do utilizador...");

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
            // 💾 BACKUP AUTOMÁTICO ao fechar aplicação
            try
            {
                Console.WriteLine("💾 Criando backup automático...");
                var backupService = _host.Services.GetService<BioDesk.Services.Backup.IBackupService>();
                if (backupService != null)
                {
                    var result = Task.Run(async () => await backupService.CreateBackupAsync(
                        incluirDocumentos: false, // Backup rápido apenas BD
                        incluirTemplates: false)).GetAwaiter().GetResult();

                    if (result.Sucesso)
                    {
                        Console.WriteLine($"✅ Backup criado: {result.CaminhoZip} ({result.TamanhoFormatado})");

                        // Limpar backups antigos (manter últimos 10)
                        var removed = Task.Run(async () => await backupService.CleanOldBackupsAsync(10))
                            .GetAwaiter().GetResult();
                        if (removed > 0)
                            Console.WriteLine($"🗑️ {removed} backups antigos removidos");
                    }
                    else
                    {
                        Console.WriteLine($"⚠️ Backup falhou: {result.Erro}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Erro no backup automático: {ex.Message}");
            }

            // ✅ CORRETO: Task.Run evita deadlock com SynchronizationContext
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
            options.UseSqlite($"Data Source={PathService.DatabasePath}")); // ✅ Usa PathService (Debug: projeto | Release: ProgramData)

        // === REPOSITORY PATTERN + UNIT OF WORK ===
        services.AddScoped<IUnitOfWork, UnitOfWork>();
        services.AddScoped<IPacienteRepository, PacienteRepository>();
        services.AddScoped<ISessaoRepository, SessaoRepository>();
        services.AddScoped<BioDesk.Data.Repositories.IProtocoloRepository, BioDesk.Data.Repositories.ProtocoloRepository>(); // ⚡ TERAPIAS BIOENERGÉTICAS

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

        // === TEMPLATE SERVICES (Templates PDF) ===
        services.AddSingleton<BioDesk.Services.Templates.ITemplatesPdfService, BioDesk.Services.Templates.TemplatesPdfService>();

        // === TEMPLATE GLOBAL SERVICE (Gestão de templates globais) ===
        services.AddScoped<BioDesk.Services.Templates.ITemplateGlobalService, BioDesk.Services.Templates.TemplateGlobalService>();

        // === DOCUMENTO EXTERNO PACIENTE SERVICE (Documentos externos dos pacientes) ===
        services.AddScoped<BioDesk.Services.Documentos.IDocumentoExternoPacienteService, BioDesk.Services.Documentos.DocumentoExternoPacienteService>();

        // === TEMPLATE & DOCUMENTO VIEWMODELS ===
        services.AddTransient<BioDesk.ViewModels.Templates.TemplatesGlobalViewModel>();
        services.AddTransient<BioDesk.ViewModels.Documentos.DocumentosExternosViewModel>();

        // === CAMERA SERVICE (captura REAL de íris via USB com AForge.NET) ===
        services.AddSingleton<ICameraService, RealCameraService>();

        // === IRIDOLOGY SERVICE (mapa iridológico + JSON loader) ===
        services.AddSingleton<IIridologyService, IridologyService>();

        // === DEBUG SERVICES ===
        services.AddSingleton<IDragDebugService, DragDebugService>();

        // === PDF SERVICES (QuestPDF) ===
        services.AddScoped<Services.Pdf.ConsentimentoPdfService>();
        services.AddScoped<Services.Pdf.PrescricaoPdfService>();
        services.AddScoped<Services.Pdf.DeclaracaoSaudePdfService>();

        // === EXCEL IMPORT SERVICE (EPPlus - Terapias Bioenergéticas) ===
        services.AddScoped<BioDesk.Services.Excel.IExcelImportService, BioDesk.Services.Excel.ExcelImportService>();

        // === BACKUP SERVICE (Sistema de Backup/Restore Automático) 🔥 CRÍTICO ===
        services.AddSingleton<BioDesk.Services.Backup.IBackupService, BioDesk.Services.Backup.BackupService>();
        Console.WriteLine("💾 Backup Service: REGISTRADO (Backup automático + Restore)");

        // === HTTP CLIENT FACTORY (para Random.org atmospheric RNG) ===
        services.AddHttpClient("RandomOrg", client =>
        {
            client.BaseAddress = new Uri("https://www.random.org/");
            client.Timeout = TimeSpan.FromSeconds(10);
        });

        // === RNG SERVICE (True Random Number Generator - Terapias Bioenergéticas) ===
        services.AddSingleton<BioDesk.Services.Rng.IRngService, BioDesk.Services.Rng.RngService>();

        // === VALUE SCANNING SERVICE (CoRe 5.0 Algorithm - Value % Scanning) ===
        services.AddSingleton<BioDesk.Services.Terapias.IValueScanningService, BioDesk.Services.Terapias.ValueScanningService>();
        Console.WriteLine("🔍 Value Scanning Service: REGISTRADO (CoRe 5.0 Algorithm)");

        // === TIEPIE HARDWARE SERVICE (Handyscope HS5 - Gerador de Sinais) ===
        // � TOGGLE: Ler configuração appsettings.json para decidir Dummy vs Real
        var configuration = services.BuildServiceProvider().GetRequiredService<IConfiguration>();
        var useDummyTiePie = configuration.GetValue<bool>("Hardware:UseDummyTiePie", defaultValue: false);

        if (useDummyTiePie)
        {
            // ⚡ MODO DUMMY: Para testes sem hardware
            services.AddSingleton<BioDesk.Services.Hardware.ITiePieHardwareService, BioDesk.Services.Hardware.DummyTiePieHardwareService>();
            Console.WriteLine("🎭 TiePie Hardware: DUMMY mode (appsettings.json: UseDummyTiePie=true)");
        }
        else
        {
            // 🔴 MODO REAL: Hardware físico conectado via USB (LibTiePie SDK)
            // Com tratamento de erro - NÃO crash se SDK/hardware não disponível
            services.AddSingleton<BioDesk.Services.Hardware.ITiePieHardwareService, BioDesk.Services.Hardware.RealTiePieHardwareService>();
            Console.WriteLine("⚡ TiePie Hardware: REAL mode (appsettings.json: UseDummyTiePie=false ou não definido)");
        }

        // === MEDIÇÃO SERVICE (Biofeedback INPUT - Oscilloscope) ===
        // 🔄 TOGGLE: Ler configuração appsettings.json para decidir Dummy vs Real
        var useDummyMedicao = configuration.GetValue<bool>("Hardware:UseDummyMedicao", defaultValue: false);

        if (useDummyMedicao)
        {
            // ⚡ MODO DUMMY: Simulação para testes sem hardware
            services.AddSingleton<BioDesk.Services.Medicao.IMedicaoService, BioDesk.Services.Medicao.DummyMedicaoService>();
            Console.WriteLine("🎭 Medição Hardware: DUMMY mode (appsettings.json: UseDummyMedicao=true)");
        }
        else
        {
            // 🔴 MODO REAL: TiePie Oscilloscope INPUT (LibTiePie SDK)
            // Com tratamento de erro - NÃO crash se SDK/hardware não disponível
            services.AddSingleton<BioDesk.Services.Medicao.IMedicaoService, BioDesk.Services.Medicao.RealMedicaoService>();
            Console.WriteLine("⚡ Medição Hardware: REAL mode (appsettings.json: UseDummyMedicao=false ou não definido)");
        }

        // === FLUENTVALIDATION VALIDATORS (Regras de Negócio) 🔒 ===
        services.AddScoped<FluentValidation.IValidator<BioDesk.Domain.Entities.ProtocoloTerapeutico>, BioDesk.Domain.Validators.ProtocoloTerapeuticoValidator>();
        services.AddScoped<FluentValidation.IValidator<BioDesk.Domain.DTOs.TerapiaFilaItem>, BioDesk.Domain.Validators.TerapiaFilaItemValidator>();
        Console.WriteLine("🔒 FluentValidation: REGISTRADO (ProtocoloTerapeutico + TerapiaFilaItem)");

        // === VIEWMODELS ===
        services.AddTransient<DashboardViewModel>();
        services.AddTransient<FichaPacienteViewModel>();
        services.AddTransient<ListaPacientesViewModel>(); // ✅ LISTA DE PACIENTES
        services.AddTransient<ConfiguracoesViewModel>(); // ✅ CONFIGURAÇÕES (Email SMTP)
        services.AddTransient<ConfiguracaoClinicaViewModel>(); // ✅ CONFIGURAÇÃO CLÍNICA

        // ViewModels das Abas
        services.AddTransient<DeclaracaoSaudeViewModel>();
        services.AddTransient<ConsentimentosViewModel>();
        services.AddTransient<RegistoConsultasViewModel>(); // ABA 4: Registo de Sessões
        services.AddTransient<IrisdiagnosticoViewModel>(); // ✅ ABA 5: Irisdiagnóstico
        services.AddTransient<ComunicacaoViewModel>(); // ✅ ABA 6: Comunicação
        services.AddTransient<TerapiasBioenergeticasUserControlViewModel>(); // ✅ ABA 8: Terapias (RNG + TiePie)
        services.AddTransient<SelecionarTemplatesViewModel>(); // ⭐ NOVO: Pop-up de templates PDF

        // UserControls (precisam de DI para construtores parametrizados)
        services.AddTransient<Views.Abas.TerapiasBioenergeticasUserControl>(); // ✅ ABA 8: Terapias

        // Views - SISTEMA LIMPO
        services.AddSingleton<MainWindow>();
        services.AddTransient<Views.DashboardView>();
        services.AddTransient<Views.ConsultasView>();
        services.AddTransient<Views.Dialogs.ConfiguracoesWindow>(); // ✅ JANELA CONFIGURAÇÕES CLÍNICA
        services.AddTransient<Views.FichaPacienteView>();
        services.AddTransient<Views.ListaPacientesView>(); // ✅ LISTA DE PACIENTES
        services.AddTransient<Views.ConfiguracoesView>(); // ✅ CONFIGURAÇÕES
    }
}
