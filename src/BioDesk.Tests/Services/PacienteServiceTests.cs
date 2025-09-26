using System;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using BioDesk.Data;
using BioDesk.Services.Pacientes;
using BioDesk.Domain.Entities;

namespace BioDesk.Tests.Services;

/// <summary>
/// Testes âncora que definem contratos para PacienteService
/// Estes testes garantem que o comportamento esperado está sempre funcional
/// </summary>
public class PacienteServiceTests : IDisposable
{
    private readonly TestBioDeskContext _context;
    private readonly TestPacienteService _service;

    public PacienteServiceTests()
    {
        var options = new DbContextOptionsBuilder<TestBioDeskContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;

        _context = new TestBioDeskContext(options);
        _context.Database.EnsureCreated();

        var logger = new LoggerFactory().CreateLogger<TestPacienteService>();
        _service = new TestPacienteService(_context, logger);
    }

    /// <summary>
    /// Teste âncora: SearchAsync deve devolver resultados baseados no termo
    /// Comportamento esperado: Pesquisa por nome, email ou número de utente
    /// </summary>
    [Fact]
    public async Task SearchAsync_DevolveResultados()
    {
        // Arrange
        var paciente = new Paciente
        {
            Nome = "João Silva",
            DataNascimento = new DateTime(1985, 5, 15),
            Email = "joao.silva@teste.com"
        };
        
        await _service.GravarAsync(paciente);

        // Act - Pesquisar por nome
        var resultadoNome = await _service.SearchAsync("João");
        
        // Act - Pesquisar por email
        var resultadoEmail = await _service.SearchAsync("joao.silva");

        // Assert
        Assert.Single(resultadoNome);
        Assert.Equal("João Silva", resultadoNome.First().Nome);
        
        Assert.Single(resultadoEmail);
        Assert.Equal("joao.silva@teste.com", resultadoEmail.First().Email);
    }

    /// <summary>
    /// Teste âncora: GravarAsync deve gravar paciente e permitir SetPacienteAtivo
    /// Comportamento esperado: Gravar → SetPacienteAtivo → disponível para navegação
    /// </summary>
    [Fact]
    public async Task GravarPaciente_PermiteSetPacienteAtivo()
    {
        // Arrange
        var paciente = new Paciente
        {
            Nome = "Maria Costa",
            DataNascimento = new DateTime(1990, 8, 20),
            Email = "maria.costa@teste.com"
        };

        // Act
        var pacienteGravado = await _service.GravarAsync(paciente);
        _service.SetPacienteAtivo(pacienteGravado);
        var pacienteAtivo = _service.GetPacienteAtivo();

        // Assert
        Assert.NotNull(pacienteGravado);
        Assert.True(pacienteGravado.Id > 0);
        Assert.NotNull(pacienteAtivo);
        Assert.Equal(pacienteGravado.Id, pacienteAtivo.Id);
        Assert.Equal("Maria Costa", pacienteAtivo.Nome);
    }

    /// <summary>
    /// Teste âncora: GetRecentesAsync deve devolver pacientes ordenados por data de atualização
    /// Comportamento esperado: Últimos atualizados primeiro
    /// </summary>
    [Fact]
    public async Task GetRecentesAsync_DevolvePacientesOrdenadosPorDataAtualizacao()
    {
        // Arrange
        var paciente1 = new Paciente
        {
            Nome = "Ana Silva",
            DataNascimento = new DateTime(1988, 3, 10),
            AtualizadoEm = DateTime.Now.AddDays(-2)
        };

        var paciente2 = new Paciente
        {
            Nome = "João Ferreira",
            DataNascimento = new DateTime(1992, 7, 25),
            AtualizadoEm = DateTime.Now.AddDays(-1)
        };

        await _service.GravarAsync(paciente1);
        await _service.GravarAsync(paciente2);

        // Act
        var recentes = await _service.GetRecentesAsync(2);

        // Assert
        Assert.Equal(2, recentes.Count);
        Assert.Equal("João Ferreira", recentes.First().Nome); // Mais recente primeiro
        Assert.Equal("Ana Silva", recentes.Last().Nome);
    }

    /// <summary>
    /// Teste âncora: Evento PacienteAtivoChanged deve ser disparado
    /// Comportamento esperado: SetPacienteAtivo dispara evento para atualizar UI
    /// </summary>
    [Fact]
    public async Task SetPacienteAtivo_DisparaEvento()
    {
        // Arrange
        var paciente = new Paciente
        {
            Nome = "Carlos Santos",
            DataNascimento = new DateTime(1987, 12, 5)
        };

        var pacienteGravado = await _service.GravarAsync(paciente);
        
        Paciente? pacienteRecebido = null;
        _service.PacienteAtivoChanged += (sender, p) => pacienteRecebido = p;

        // Act
        _service.SetPacienteAtivo(pacienteGravado);

        // Assert
        Assert.NotNull(pacienteRecebido);
        Assert.Equal(pacienteGravado.Id, pacienteRecebido.Id);
        Assert.Equal("Carlos Santos", pacienteRecebido.Nome);
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}