using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using BioDesk.Services.Cache;
using BioDesk.Services.FuzzySearch;
using BioDesk.Services.Notifications;
using BioDesk.Services.AutoSave;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Navigation;
using BioDesk.Services.Dashboard;
using BioDesk.Services.Activity;
using BioDesk.Services.Consultas;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BioDesk.Tests.Base;

/// <summary>
/// Classe base para testes de ViewModels
/// Fornece infraestrutura completa: DI Container, InMemory Database, Mocks
/// 
/// Características:
/// - ServiceProvider configurado com todos os serviços
/// - BioDeskContext InMemory para testes isolados
/// - Seed de dados de teste padronizado
/// - Cleanup automático após cada teste
/// - Logger com NullLogger para performance
/// - Serviços reais (não mocks) para testes de integração
/// </summary>
public abstract class ViewModelTestBase : IDisposable
{
    protected ServiceProvider ServiceProvider { get; private set; }
    protected BioDeskContext Context { get; private set; }

    /// <summary>
    /// Configuração padrão para todos os testes de ViewModels
    /// </summary>
    protected ViewModelTestBase()
    {
        var services = new ServiceCollection();
        ConfigureServices(services);
        ServiceProvider = services.BuildServiceProvider();
        Context = ServiceProvider.GetRequiredService<BioDeskContext>();
        
        // Garantir que o banco está criado e limpo
        Context.Database.EnsureCreated();
        SeedTestData().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Configuração dos serviços do DI Container
    /// Override em classes filhas para adicionar serviços específicos
    /// </summary>
    protected virtual void ConfigureServices(IServiceCollection services)
    {
        // Database InMemory com nome único por teste
        var dbName = $"TestDb_{Guid.NewGuid()}";
        services.AddDbContext<BioDeskContext>(options =>
            options.UseInMemoryDatabase(dbName));

        // Logging com NullLogger para performance
        services.AddSingleton<ILoggerFactory, NullLoggerFactory>();
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        // Cache em memória
        services.AddMemoryCache();
        services.AddSingleton<ICacheService, CacheService>();

        // Serviços core
        services.AddSingleton<IFuzzySearchService, FuzzySearchService>();
        services.AddSingleton<INotificationService, NotificationService>();
        services.AddSingleton(typeof(IAutoSaveService<>), typeof(AutoSaveService<>));
        services.AddSingleton<INavigationService, NavigationService>();
        services.AddScoped<IPacienteService, PacienteService>();
        
        // Dashboard services
        services.AddSingleton<IDashboardStatsService, DashboardStatsService>();
        services.AddScoped<IActivityService, ActivityService>();
        services.AddScoped<IConsultaService, ConsultaService>(); // 🩺 Consulta Service
    }

    /// <summary>
    /// Seed de dados padronizado para testes
    /// 3 pacientes com dados representativos
    /// </summary>
    protected virtual async Task SeedTestData()
    {
        // Limpar dados existentes
        Context.Pacientes.RemoveRange(Context.Pacientes);
        await Context.SaveChangesAsync();

        var pacientes = new List<Paciente>
        {
            new()
            {
                Id = 1,
                Nome = "João Silva Santos",
                Email = "joao.silva@teste.com",
                Telefone = "11999888777",
                DataNascimento = new DateTime(1985, 3, 15)
            },
            new()
            {
                Id = 2, 
                Nome = "Maria Oliveira Costa",
                Email = "maria.oliveira@teste.com",
                Telefone = "11888777666",
                DataNascimento = new DateTime(1990, 7, 22)
            },
            new()
            {
                Id = 3,
                Nome = "Pedro Souza Lima",
                Email = "pedro.souza@teste.com", 
                Telefone = "11777666555",
                DataNascimento = new DateTime(1978, 12, 3)
            }
        };

        Context.Pacientes.AddRange(pacientes);
        await Context.SaveChangesAsync();
    }

    /// <summary>
    /// Helper para obter serviço do DI Container
    /// </summary>
    protected T GetService<T>() where T : notnull
    {
        return ServiceProvider.GetRequiredService<T>();
    }

    /// <summary>
    /// Helper para criar ViewModel com dependências injetadas
    /// </summary>
    protected T CreateViewModel<T>() where T : class
    {
        return ActivatorUtilities.CreateInstance<T>(ServiceProvider);
    }

    /// <summary>
    /// Limpar dados de teste após cada teste
    /// </summary>
    protected async Task ClearTestData()
    {
        Context.Pacientes.RemoveRange(Context.Pacientes);
        await Context.SaveChangesAsync();
    }

    /// <summary>
    /// Adicionar paciente de teste específico
    /// </summary>
    protected async Task<Paciente> AddTestPaciente(string nome, string email = "")
    {
        var paciente = new Paciente
        {
            Nome = nome,
            Email = string.IsNullOrEmpty(email) ? $"{nome.ToLower().Replace(" ", ".")}@teste.com" : email,
            Telefone = "11999999999",
            DataNascimento = DateTime.Now.AddYears(-30)
        };

        Context.Pacientes.Add(paciente);
        await Context.SaveChangesAsync();
        return paciente;
    }

    /// <summary>
    /// Verificar se paciente existe no contexto
    /// </summary>
    protected async Task<bool> PacienteExists(int id)
    {
        return await Context.Pacientes.AnyAsync(p => p.Id == id);
    }

    public virtual void Dispose()
    {
        Context?.Dispose();
        ServiceProvider?.Dispose();
        GC.SuppressFinalize(this);
    }
}