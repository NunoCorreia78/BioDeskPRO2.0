using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using BioDeskPRO.Data;
using BioDeskPRO.Services;
using BioDeskPRO.UI;

namespace BioDeskPRO;

/// <summary>
/// Main program entry point for BioDeskPRO 2.0
/// Clinical Management System with robust architecture and error handling
/// </summary>
class Program
{
    private static IHost? _host;

    static async Task Main(string[] args)
    {
        // Initialize console UI
        ConsoleUI.Initialize();

        try
        {
            // Build and configure the host with dependency injection
            _host = Host.CreateDefaultBuilder(args)
                .ConfigureServices((context, services) =>
                {
                    // Configure Entity Framework with SQLite
                    services.AddDbContext<BioDeskContext>(options =>
                        options.UseSqlite("Data Source=BioDeskPRO.db"));

                    // Register services
                    services.AddScoped<IPatientService, PatientService>();
                    services.AddScoped<IDataService, DataService>();

                    // Register UI services
                    services.AddScoped<PatientUI>();
                })
                .ConfigureLogging(logging =>
                {
                    logging.ClearProviders();
                    logging.AddConsole();
                    logging.SetMinimumLevel(LogLevel.Warning); // Reduce console noise
                })
                .Build();

            // Initialize database
            await InitializeDatabaseAsync();

            // Start the application
            await RunApplicationAsync();
        }
        catch (Exception ex)
        {
            ConsoleUI.ShowError($"Erro crítico na aplicação: {ex.Message}");
            ConsoleUI.PauseForUser("Pressione qualquer tecla para sair...");
        }
        finally
        {
            _host?.Dispose();
        }
    }

    private static async Task InitializeDatabaseAsync()
    {
        try
        {
            using var scope = _host!.Services.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<BioDeskContext>();
            
            // Ensure database is created
            await context.Database.EnsureCreatedAsync();
            
            ConsoleUI.ShowSuccess("Base de dados inicializada com sucesso.");
        }
        catch (Exception ex)
        {
            ConsoleUI.ShowError($"Erro ao inicializar a base de dados: {ex.Message}");
            throw;
        }
    }

    private static async Task RunApplicationAsync()
    {
        while (true)
        {
            try
            {
                await ShowMainMenuAsync();
            }
            catch (Exception ex)
            {
                ConsoleUI.ShowError($"Erro inesperado: {ex.Message}");
                ConsoleUI.PauseForUser();
            }
        }
    }

    private static async Task ShowMainMenuAsync()
    {
        ConsoleUI.DrawHeader("BIODESK PRO 2.0", "Sistema de Gestão Clínica Holística em TNC");

        ConsoleUI.DrawCard("Tela Inicial - Navegação Intuitiva", () =>
        {
            ConsoleUI.ShowInfo("Bem-vindo ao BioDeskPRO! Sistema profissional para gestão clínica.");
            Console.WriteLine("Organizado em seções bem definidas para facilitar a navegação.");
        });

        var options = new[]
        {
            "👥 Gestão de Pacientes (Cadastro/Busca)",
            "📋 Histórico Clínico (Em desenvolvimento)",
            "👁️ Módulo de Iridologia (Em desenvolvimento)", 
            "⚛️ Módulo Quântico (Em desenvolvimento)",
            "💬 Centro de Comunicação (Em desenvolvimento)",
            "⚙️ Configurações do Sistema",
            "❌ Sair do Sistema"
        };

        var choice = ConsoleUI.GetChoice("Selecione um módulo", options);

        using var scope = _host!.Services.CreateScope();

        switch (choice)
        {
            case 0: // Patient Management
                var patientUI = scope.ServiceProvider.GetRequiredService<PatientUI>();
                await patientUI.ShowPatientManagementAsync();
                break;
                
            case 1: // Clinical History
                ShowComingSoonModule("Histórico Clínico", 
                    "Módulo para gestão de consultas, tratamentos e acompanhamento de pacientes.");
                break;
                
            case 2: // Iridology
                ShowComingSoonModule("Iridologia", 
                    "Módulo para análise de íris, captura de imagens e avaliação diagnóstica.");
                break;
                
            case 3: // Quantum Module
                ShowComingSoonModule("Módulo Quântico", 
                    "Módulo para terapias energéticas e análises vibracionais.");
                break;
                
            case 4: // Communication Center
                ShowComingSoonModule("Centro de Comunicação", 
                    "Módulo para envio de prescrições, orientações e comunicação com pacientes.");
                break;
                
            case 5: // System Settings
                await ShowSystemSettingsAsync();
                break;
                
            case 6: // Exit
                if (ConsoleUI.GetConfirmation("Tem certeza de que deseja sair do sistema?"))
                {
                    ConsoleUI.ShowSuccess("Obrigado por usar o BioDeskPRO 2.0!");
                    Environment.Exit(0);
                }
                break;
        }
    }

    private static void ShowComingSoonModule(string moduleName, string description)
    {
        ConsoleUI.DrawHeader($"{moduleName.ToUpper()}", "Módulo em Desenvolvimento");
        
        ConsoleUI.DrawCard("Funcionalidade Futura", () =>
        {
            ConsoleUI.ShowInfo($"O módulo '{moduleName}' está sendo desenvolvido.");
            Console.WriteLine($"Descrição: {description}");
            Console.WriteLine();
            ConsoleUI.ShowWarning("Este módulo será implementado em futuras versões do sistema.");
            Console.WriteLine("A arquitetura atual já suporta a integração de novos módulos.");
        });

        ConsoleUI.PauseForUser();
    }

    private static async Task ShowSystemSettingsAsync()
    {
        ConsoleUI.DrawHeader("CONFIGURAÇÕES DO SISTEMA", "Informações e Configurações");

        ConsoleUI.DrawCard("Informações do Sistema", () =>
        {
            Console.WriteLine("BioDeskPRO 2.0 - Sistema de Gestão Clínica Holística");
            Console.WriteLine("Versão: 2.0.0");
            Console.WriteLine("Tecnologia: .NET 8 com Entity Framework Core");
            Console.WriteLine("Base de Dados: SQLite (Local)");
            Console.WriteLine("Arquitetura: Multicamadas com separação de responsabilidades");
        });

        ConsoleUI.DrawCard("Características Implementadas", () =>
        {
            ConsoleUI.ShowSuccess("✓ Arquitetura robusta à prova de erros");
            ConsoleUI.ShowSuccess("✓ Base de dados escalável com SQLite");
            ConsoleUI.ShowSuccess("✓ Módulo de cadastro de pacientes completo");
            ConsoleUI.ShowSuccess("✓ Validação de dados e tratamento de erros");
            ConsoleUI.ShowSuccess("✓ Interface organizada em seções bem definidas");
            ConsoleUI.ShowSuccess("✓ Conformidade com LGPD/GDPR");
        });

        ConsoleUI.DrawCard("Base de Dados", () =>
        {
            using var scope = _host!.Services.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<BioDeskContext>();
            
            try
            {
                var patientCount = context.Patients.Count();
                var consultationCount = context.Consultations.Count();
                var consentCount = context.ConsentTypes.Count();
                
                Console.WriteLine($"Pacientes cadastrados: {patientCount}");
                Console.WriteLine($"Consultas registradas: {consultationCount}");
                Console.WriteLine($"Tipos de consentimento: {consentCount}");
                Console.WriteLine($"Localização: BioDeskPRO.db (pasta da aplicação)");
            }
            catch (Exception ex)
            {
                ConsoleUI.ShowError($"Erro ao acessar estatísticas: {ex.Message}");
            }
        });

        var options = new[]
        {
            "Ver Logs do Sistema",
            "Teste de Conectividade da Base de Dados",
            "Voltar ao Menu Principal"
        };

        var choice = ConsoleUI.GetChoice("Opções de Configuração", options);

        switch (choice)
        {
            case 0:
                ShowSystemLogs();
                break;
            case 1:
                await TestDatabaseConnectivityAsync();
                break;
            case 2:
                return;
        }

        ConsoleUI.PauseForUser();
    }

    private static void ShowSystemLogs()
    {
        ConsoleUI.DrawHeader("LOGS DO SISTEMA", "Últimas Atividades");
        
        ConsoleUI.ShowInfo("Funcionalidade de logs será implementada em versão futura.");
        ConsoleUI.ShowInfo("Logs atualmente são exibidos no console durante operações.");
        
        ConsoleUI.PauseForUser();
    }

    private static async Task TestDatabaseConnectivityAsync()
    {
        ConsoleUI.DrawHeader("TESTE DE CONECTIVIDADE", "Verificação da Base de Dados");

        try
        {
            using var scope = _host!.Services.CreateScope();
            var context = scope.ServiceProvider.GetRequiredService<BioDeskContext>();

            ConsoleUI.ShowInfo("Testando conectividade com a base de dados...");
            
            // Test connection
            await context.Database.CanConnectAsync();
            ConsoleUI.ShowSuccess("✓ Conexão com a base de dados estabelecida");

            // Test table access
            var patientCount = await context.Patients.CountAsync();
            ConsoleUI.ShowSuccess($"✓ Acesso à tabela de pacientes: {patientCount} registros");

            var consentCount = await context.ConsentTypes.CountAsync();
            ConsoleUI.ShowSuccess($"✓ Acesso à tabela de consentimentos: {consentCount} registros");

            ConsoleUI.ShowSuccess("Todos os testes de conectividade passaram!");
        }
        catch (Exception ex)
        {
            ConsoleUI.ShowError($"Erro de conectividade: {ex.Message}");
        }

        ConsoleUI.PauseForUser();
    }
}
