using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;
using BioDesk.Services.Cache;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Core;

/// <summary>
/// Implementação do service para itens do Banco Core
/// </summary>
public class ItemBancoCoreService : IItemBancoCoreService
{
    private readonly IItemBancoCoreRepository _repository;
    private readonly ICacheService _cacheService;
    private readonly ILogger<ItemBancoCoreService> _logger;

    private const string CACHE_KEY_ALL = "ItemBancoCore:All";
    private const int CACHE_MINUTES = 5;

    public ItemBancoCoreService(
        IItemBancoCoreRepository repository,
        ICacheService cacheService,
        ILogger<ItemBancoCoreService> logger)
    {
        _repository = repository ?? throw new ArgumentNullException(nameof(repository));
        _cacheService = cacheService ?? throw new ArgumentNullException(nameof(cacheService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<List<ItemBancoCore>> GetItensDisponiveisAsync()
    {
        var cached = _cacheService.Get<List<ItemBancoCore>>(CACHE_KEY_ALL);
        if (cached != null)
        {
            _logger.LogDebug("Itens Banco Core retornados do cache ({Count} itens)", cached.Count);
            return cached;
        }

        var itens = await _repository.GetAllAsync();
        _cacheService.Set(CACHE_KEY_ALL, itens, TimeSpan.FromMinutes(CACHE_MINUTES));

        _logger.LogInformation("Carregados {Count} itens do Banco Core da BD", itens.Count);
        return itens;
    }

    public async Task<List<ItemBancoCore>> GetItensPorCategoriaAsync(CategoriaCore categoria)
    {
        _logger.LogDebug("Filtrando itens por categoria: {Categoria}", categoria);
        return await _repository.GetByCategoriaAsync(categoria);
    }

    public async Task<ItemBancoCore?> GetItemAsync(Guid externalId)
    {
        return await _repository.GetByExternalIdAsync(externalId);
    }

    public async Task<List<ItemBancoCore>> PesquisarAsync(string termo)
    {
        if (string.IsNullOrWhiteSpace(termo))
        {
            _logger.LogDebug("Pesquisa vazia, retornando todos os itens");
            return await GetItensDisponiveisAsync();
        }

        _logger.LogDebug("Pesquisando itens com termo: {Termo}", termo);
        return await _repository.SearchAsync(termo);
    }

    public async Task<ValidationResult> ValidarIntegridadeAsync()
    {
        var result = new ValidationResult();

        try
        {
            var countPorCategoria = await _repository.GetCountPorCategoriaAsync();
            result.CountPorCategoria = countPorCategoria;
            result.TotalItens = countPorCategoria.Values.Sum();

            // Validar contagens esperadas (seed de 156 itens)
            var esperados = new Dictionary<CategoriaCore, int>
            {
                { CategoriaCore.FloraisBach, 38 },
                { CategoriaCore.Chakra, 28 },
                { CategoriaCore.Meridiano, 20 },
                { CategoriaCore.Orgao, 70 }
            };

            foreach (var (categoria, esperado) in esperados)
            {
                if (!countPorCategoria.TryGetValue(categoria, out var atual))
                {
                    result.Erros.Add($"{categoria}: esperado {esperado}, encontrado 0");
                }
                else if (atual != esperado)
                {
                    result.Erros.Add($"{categoria}: esperado {esperado}, encontrado {atual}");
                }
            }

            if (result.TotalItens != 156)
            {
                result.Erros.Add($"Total: esperado 156, encontrado {result.TotalItens}");
            }

            result.IsValido = result.Erros.Count == 0;

            _logger.LogInformation(
                "Validação Banco Core: {Status} - Total: {Total}, BachFlorais: {BachFlorais}, Chakras: {Chakras}, Meridianos: {Meridianos}, Orgaos: {Orgaos}",
                result.IsValido ? "OK" : "FALHOU",
                result.TotalItens,
                countPorCategoria.GetValueOrDefault(CategoriaCore.FloraisBach, 0),
                countPorCategoria.GetValueOrDefault(CategoriaCore.Chakra, 0),
                countPorCategoria.GetValueOrDefault(CategoriaCore.Meridiano, 0),
                countPorCategoria.GetValueOrDefault(CategoriaCore.Orgao, 0)
            );
        }
        catch (Exception ex)
        {
            result.IsValido = false;
            result.Erros.Add($"Erro ao validar: {ex.Message}");
            _logger.LogError(ex, "Erro ao validar integridade do Banco Core");
        }

        return result;
    }

    public void InvalidarCache()
    {
        _cacheService.Remove(CACHE_KEY_ALL);
        _logger.LogDebug("Cache do Banco Core invalidado");
    }
}
