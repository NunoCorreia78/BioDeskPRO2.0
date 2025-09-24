using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Data;
using BioDesk.Services.Cache;
using BioDesk.Services.FuzzySearch;

namespace BioDesk.Services.Pacientes;

/// <summary>
/// Implementação do serviço de pacientes usando Entity Framework Core
/// Otimizado com sistema de cache para melhor performance
/// Integrado com FuzzySearch para pesquisa tolerante a erros
/// Guardas anti-erro: try/catch + ILogger, validação robusta
/// </summary>
public class PacienteService : IPacienteService
{
    private readonly BioDeskContext _context;
    private readonly ILogger<PacienteService> _logger;
    private readonly ICacheService _cacheService;
    private readonly IFuzzySearchService _fuzzySearchService;
    private Paciente? _pacienteAtivo;

    public event EventHandler<Paciente?>? PacienteAtivoChanged;

    public PacienteService(
        BioDeskContext context, 
        ILogger<PacienteService> logger, 
        ICacheService cacheService,
        IFuzzySearchService fuzzySearchService)
    {
        _context = context;
        _logger = logger;
        _cacheService = cacheService;
        _fuzzySearchService = fuzzySearchService;
    }

    public void SetPacienteAtivo(Paciente paciente)
    {
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

            // Tentar obter do cache primeiro
            var cacheKey = CacheKeys.GetSearchKey(termo);
            return await _cacheService.GetOrSetAsync(cacheKey, async () =>
            {
                // Buscar todos os pacientes e aplicar fuzzy search
                var todosPacientes = await _context.Pacientes.ToListAsync();
                
                // Aplicar fuzzy search com score mínimo 65  
                var resultadosFuzzy = _fuzzySearchService.SearchPacientes(todosPacientes, termo, limiteScore: 65);
                
                // Se fuzzy search não encontrou nada, tentar busca tradicional (backup)
                if (!resultadosFuzzy.Any())
                {
                    var termoLower = termo.ToLower();
                    resultadosFuzzy = todosPacientes
                        .Where(p => p.Nome.ToLower().Contains(termoLower) ||
                                   (p.Email != null && p.Email.ToLower().Contains(termoLower)))
                        .OrderBy(p => p.Nome)
                        .ToList();
                        
                    _logger.LogInformation(
                        "Fuzzy search sem resultados para '{Termo}', usando busca tradicional: {Quantidade} resultados", 
                        termo, resultadosFuzzy.Count);
                }
                else
                {
                    _logger.LogInformation(
                        "Fuzzy search para '{Termo}' retornou {Quantidade} resultados (não cachado)", 
                        termo, resultadosFuzzy.Count);
                }

                return resultadosFuzzy;
            });
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
            return await _cacheService.GetOrSetAsync(CacheKeys.PACIENTES_ALL, async () =>
            {
                var resultado = await _context.Pacientes
                    .OrderBy(p => p.Nome)
                    .ToListAsync();

                _logger.LogInformation("Lista completa de pacientes obtida da BD: {Quantidade} registos", resultado.Count);
                return resultado;
            });
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
            var cacheKey = CacheKeys.GetRecentKey(quantidade);
            return await _cacheService.GetOrSetAsync(cacheKey, async () =>
            {
                var resultado = await _context.Pacientes
                    .OrderByDescending(p => p.AtualizadoEm)
                    .Take(quantidade)
                    .ToListAsync();

                _logger.LogInformation("Pacientes recentes obtidos da BD: {Quantidade} registos", resultado.Count);
                return resultado;
            });
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

            // Invalidar cache após gravação
            InvalidarCacheAposGravacao(paciente);

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
            var cacheKey = CacheKeys.GetPacienteKey(id);
            var cachedPaciente = _cacheService.Get<Paciente>(cacheKey);
            
            if (cachedPaciente != null)
            {
                _logger.LogDebug("Paciente obtido do cache por ID: {Id}", id);
                return cachedPaciente;
            }

            // Se não estiver no cache, buscar na BD
            var resultado = await _context.Pacientes.FindAsync(id);
            
            if (resultado != null)
            {
                // Guardar no cache se encontrado
                _cacheService.Set(cacheKey, resultado);
                _logger.LogDebug("Paciente obtido da BD por ID: {Id}", id);
            }
            
            return resultado;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter paciente com ID {Id}", id);
            return null;
        }
    }

    /// <summary>
    /// Invalida cache após operações de gravação/atualização
    /// </summary>
    private void InvalidarCacheAposGravacao(Paciente paciente)
    {
        try
        {
            // Invalidar listas gerais
            _cacheService.Remove(CacheKeys.PACIENTES_ALL);
            _cacheService.RemoveByPattern(CacheKeys.PACIENTES_RECENT);
            
            // Invalidar pesquisas que possam incluir este paciente
            _cacheService.RemoveByPattern(CacheKeys.SEARCH_PREFIX);
            
            // Invalidar cache individual se existir
            if (paciente.Id > 0)
            {
                _cacheService.Remove(CacheKeys.GetPacienteKey(paciente.Id));
            }
            
            _logger.LogDebug("Cache invalidado após gravação do paciente: {Nome} (ID: {Id})", 
                paciente.Nome, paciente.Id);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro ao invalidar cache após gravação - continuando...");
        }
    }
}