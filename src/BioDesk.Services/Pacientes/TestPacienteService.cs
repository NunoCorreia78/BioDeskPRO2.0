using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Data;

namespace BioDesk.Services.Pacientes;

/// <summary>
/// Implementação do serviço de pacientes para testes
/// Utiliza TestBioDeskContext sem dados de seed
/// </summary>
public class TestPacienteService : IPacienteService
{
    private readonly TestBioDeskContext _context;
    private readonly ILogger<TestPacienteService> _logger;
    private Paciente? _pacienteAtivo;

    public event EventHandler<Paciente?>? PacienteAtivoChanged;

    public TestPacienteService(TestBioDeskContext context, ILogger<TestPacienteService> logger)
    {
        _context = context;
        _logger = logger;
    }

    public void SetPacienteAtivo(Paciente paciente)
    {
        if (paciente == null)
        {
            _logger.LogWarning("Tentativa de definir paciente ativo como null - ignorando");
            return;
        }
        
        _logger.LogInformation("Definindo paciente ativo: {Nome} (ID: {Id})", 
            paciente.Nome, paciente.Id);
        
        _pacienteAtivo = paciente;
        PacienteAtivoChanged?.Invoke(this, paciente);
    }

    public Paciente? GetPacienteAtivo()
    {
        return _pacienteAtivo;
    }

    public async Task<List<Paciente>> SearchAsync(string termo)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(termo))
            {
                return await GetTodosAsync();
            }

            var termoLower = termo.ToLower();

            var resultado = await _context.Pacientes
                .Where(p => p.Nome.ToLower().Contains(termoLower) ||
                           (p.Email != null && p.Email.ToLower().Contains(termoLower)))
                .OrderBy(p => p.Nome)
                .ToListAsync();

            _logger.LogInformation("Pesquisa por '{Termo}' retornou {Quantidade} resultados", 
                termo, resultado.Count);

            return resultado;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao pesquisar pacientes com termo '{Termo}'", termo);
            return new List<Paciente>();
        }
    }

    public async Task<List<Paciente>> GetTodosAsync()
    {
        try
        {
            return await _context.Pacientes
                .OrderBy(p => p.Nome)
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter todos os pacientes");
            return new List<Paciente>();
        }
    }

    public async Task<List<Paciente>> GetRecentesAsync(int quantidade = 5)
    {
        try
        {
            return await _context.Pacientes
                .OrderByDescending(p => p.AtualizadoEm)
                .Take(quantidade)
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter pacientes recentes");
            return new List<Paciente>();
        }
    }

    public async Task<Paciente> GravarAsync(Paciente paciente)
    {
        try
        {
            var isNovo = paciente.Id == 0;

            if (isNovo)
            {
                paciente.CriadoEm = DateTime.Now;
                _context.Pacientes.Add(paciente);
                _logger.LogInformation("Criando novo paciente: {Nome}", paciente.Nome);
            }
            else
            {
                paciente.AtualizadoEm = DateTime.Now;
                _context.Pacientes.Update(paciente);
                _logger.LogInformation("Atualizando paciente: {Nome} (ID: {Id})", 
                    paciente.Nome, paciente.Id);
            }

            await _context.SaveChangesAsync();

            _logger.LogInformation("Paciente gravado com sucesso: {Nome} (ID: {Id})", 
                paciente.Nome, paciente.Id);

            return paciente;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gravar paciente: {Nome}", paciente.Nome);
            throw;
        }
    }

    public async Task<Paciente?> GetByIdAsync(int id)
    {
        try
        {
            return await _context.Pacientes.FindAsync(id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter paciente com ID {Id}", id);
            return null;
        }
    }
}