using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using BioDeskPro.Data.Contexts;
using BioDeskPro.Data.Services;

namespace BioDeskPro.Data;

public static class DataServiceExtensions
{
    public static IServiceCollection AddBioDeskData(this IServiceCollection services)
    {
        services.AddDbContext<BioDeskContext>(options =>
        {
            var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            var bioDeskPath = Path.Combine(appDataPath, "BioDesk", "data");
            Directory.CreateDirectory(bioDeskPath);
            
            var dbPath = Path.Combine(bioDeskPath, "biodesk.db");
            
            options.UseSqlite($"Data Source={dbPath}", sqliteOptions =>
            {
                // Configurações específicas do SQLite
                sqliteOptions.CommandTimeout(30);
            });
            
            // Configurações de desenvolvimento
#if DEBUG
            options.EnableSensitiveDataLogging();
            options.EnableDetailedErrors();
#endif
        });
        
        // Registrar serviços de dados
        services.AddScoped<IPacienteService, PacienteService>();
        
        return services;
    }
    
    public static async Task InitializeDatabaseAsync(this IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<BioDeskContext>();
        
        // Garantir que o diretório existe
        var appDataPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var bioDeskPath = Path.Combine(appDataPath, "BioDesk", "data");
        Directory.CreateDirectory(bioDeskPath);
        
        // Criar a base de dados se não existir
        await context.Database.EnsureCreatedAsync();
        
        // Configurar SQLite com as opções necessárias
        await ConfigureSqliteOptionsAsync(context);
        
        // Seed inicial se necessário
        await SeedInitialDataAsync(context);
    }
    
    private static async Task ConfigureSqliteOptionsAsync(BioDeskContext context)
    {
        // PRAGMA foreign_keys=ON
        await context.Database.ExecuteSqlRawAsync("PRAGMA foreign_keys=ON");
        
        // PRAGMA journal_mode=WAL (Write-Ahead Logging)
        await context.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL");
        
        // Outras configurações de performance
        await context.Database.ExecuteSqlRawAsync("PRAGMA synchronous=NORMAL");
        await context.Database.ExecuteSqlRawAsync("PRAGMA cache_size=10000");
        await context.Database.ExecuteSqlRawAsync("PRAGMA temp_store=MEMORY");
        
        // Configurar timeout para operações de bloqueio
        await context.Database.ExecuteSqlRawAsync("PRAGMA busy_timeout=5000");
        
        // Ativar FTS5 para pesquisa full-text (será configurado posteriormente)
        // await context.Database.ExecuteSqlRawAsync("PRAGMA compile_options");
    }
    
    private static async Task SeedInitialDataAsync(BioDeskContext context)
    {
        // Verificar se já existe dados
        if (await context.ConsentimentoTipos.AnyAsync())
            return;
        
        // Seed de tipos de consentimento básicos
        var consentimentosTipo = new[]
        {
            new BioDeskPro.Core.Entities.ConsentimentoTipo
            {
                Nome = "Consentimento Geral de Tratamento",
                ConteudoTemplate = "Eu, {NOME_PACIENTE}, autorizo o tratamento conforme descrito...",
                Categoria = "Geral",
                Obrigatorio = true,
                Ativo = true,
                Versao = "1.0"
            },
            new BioDeskPro.Core.Entities.ConsentimentoTipo
            {
                Nome = "Consentimento para Iridologia",
                ConteudoTemplate = "Eu, {NOME_PACIENTE}, autorizo a realização de exame de iridologia...",
                Categoria = "Iridologia",
                Obrigatorio = false,
                Ativo = true,
                Versao = "1.0"
            },
            new BioDeskPro.Core.Entities.ConsentimentoTipo
            {
                Nome = "Consentimento para Terapia Quântica",
                ConteudoTemplate = "Eu, {NOME_PACIENTE}, autorizo a aplicação de terapia quântica...",
                Categoria = "Quantum",
                Obrigatorio = false,
                Ativo = true,
                Versao = "1.0"
            }
        };
        
        context.ConsentimentoTipos.AddRange(consentimentosTipo);
        
        // Seed de protocolos quânticos básicos
        var protocolosQuantum = new[]
        {
            new BioDeskPro.Core.Entities.QuantumProtocol
            {
                Nome = "Protocolo Relaxamento Básico",
                Descricao = "Protocolo básico para indução de relaxamento",
                Categoria = "Relaxamento",
                TipoProtocolo = "Frequencial",
                DuracaoMinutos = 30,
                Parametros = "{ \"frequencia\": 432, \"intensidade\": 50 }",
                Indicacoes = "Stress, ansiedade, tensão muscular",
                Ativo = true
            },
            new BioDeskPro.Core.Entities.QuantumProtocol
            {
                Nome = "Protocolo Energização",
                Descricao = "Protocolo para aumento de energia vital",
                Categoria = "Energização",
                TipoProtocolo = "Vibracional",
                DuracaoMinutos = 20,
                Parametros = "{ \"frequencia\": 528, \"intensidade\": 70 }",
                Indicacoes = "Fadiga, baixa energia, recuperação",
                Ativo = true
            }
        };
        
        context.QuantumProtocols.AddRange(protocolosQuantum);
        
        await context.SaveChangesAsync();
    }
}