using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Cache;

/// <summary>
/// Implementação do serviço de cache usando MemoryCache
/// Otimizado para listas de pacientes e pesquisas frequentes
/// </summary>
public class CacheService : ICacheService, IDisposable
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<CacheService> _logger;
    private readonly ConcurrentDictionary<string, DateTime> _cacheKeys;

    // Configurações padrão de cache
    private readonly TimeSpan _defaultExpiry = TimeSpan.FromMinutes(10);
    private readonly TimeSpan _searchExpiry = TimeSpan.FromMinutes(5);

    public CacheService(IMemoryCache memoryCache, ILogger<CacheService> logger)
    {
        _memoryCache = memoryCache ?? throw new ArgumentNullException(nameof(memoryCache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _cacheKeys = new ConcurrentDictionary<string, DateTime>();
    }

    /// <summary>
    /// Obtém um item do cache
    /// </summary>
    public T? Get<T>(string key) where T : class
    {
        try
        {
            if (_memoryCache.TryGetValue(key, out var value))
            {
                _logger.LogDebug("Cache HIT para chave: {Key}", key);
                return value as T;
            }

            _logger.LogDebug("Cache MISS para chave: {Key}", key);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter item do cache: {Key}", key);
            return null;
        }
    }

    /// <summary>
    /// Obtém um item do cache ou executa a função para obtê-lo
    /// </summary>
    public async Task<T> GetOrSetAsync<T>(string key, Func<Task<T>> getItem, TimeSpan? expiry = null) where T : class
    {
        try
        {
            // Tentar obter do cache primeiro
            var cachedItem = Get<T>(key);
            if (cachedItem != null)
            {
                return cachedItem;
            }

            // Se não estiver no cache, obter o item
            _logger.LogDebug("Executando função para obter item: {Key}", key);
            var item = await getItem();

            // Guardar no cache
            Set(key, item, expiry);

            return item;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter ou definir item no cache: {Key}", key);
            
            // Em caso de erro, tentar executar a função diretamente
            return await getItem();
        }
    }

    /// <summary>
    /// Define um item no cache
    /// </summary>
    public void Set<T>(string key, T item, TimeSpan? expiry = null) where T : class
    {
        try
        {
            var expiryTime = expiry ?? GetDefaultExpiry(key);
            
            var cacheOptions = new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = expiryTime,
                SlidingExpiration = TimeSpan.FromMinutes(2), // Renovar se acessado
                Priority = GetPriority(key)
            };

            // Callback para limpeza quando expirar
            cacheOptions.PostEvictionCallbacks.Add(new PostEvictionCallbackRegistration
            {
                EvictionCallback = OnItemEvicted
            });

            _memoryCache.Set(key, item, cacheOptions);
            _cacheKeys.TryAdd(key, DateTime.UtcNow);
            
            _logger.LogDebug("Item adicionado ao cache: {Key}, expira em: {Expiry}", key, expiryTime);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao adicionar item ao cache: {Key}", key);
        }
    }

    /// <summary>
    /// Remove um item do cache
    /// </summary>
    public void Remove(string key)
    {
        try
        {
            _memoryCache.Remove(key);
            _cacheKeys.TryRemove(key, out _);
            
            _logger.LogDebug("Item removido do cache: {Key}", key);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao remover item do cache: {Key}", key);
        }
    }

    /// <summary>
    /// Remove todos os itens do cache que começam com o padrão especificado
    /// </summary>
    public void RemoveByPattern(string pattern)
    {
        try
        {
            var keysToRemove = _cacheKeys.Keys
                .Where(key => key.StartsWith(pattern, StringComparison.OrdinalIgnoreCase))
                .ToList();

            foreach (var key in keysToRemove)
            {
                Remove(key);
            }
            
            _logger.LogDebug("Removidos {Count} itens do cache com padrão: {Pattern}", keysToRemove.Count, pattern);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao remover itens por padrão: {Pattern}", pattern);
        }
    }

    /// <summary>
    /// Limpa todo o cache
    /// </summary>
    public void Clear()
    {
        try
        {
            if (_memoryCache is MemoryCache mc)
            {
                mc.Compact(1.0);
            }
            
            _cacheKeys.Clear();
            _logger.LogInformation("Cache completamente limpo");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao limpar cache");
        }
    }

    /// <summary>
    /// Verifica se existe um item no cache
    /// </summary>
    public bool Exists(string key)
    {
        return _memoryCache.TryGetValue(key, out _);
    }

    /// <summary>
    /// Obtém a expiração padrão baseada no tipo de chave
    /// </summary>
    private TimeSpan GetDefaultExpiry(string key)
    {
        if (key.StartsWith("search:", StringComparison.OrdinalIgnoreCase))
            return _searchExpiry;
        
        return _defaultExpiry;
    }

    /// <summary>
    /// Obtém a prioridade baseada no tipo de chave
    /// </summary>
    private CacheItemPriority GetPriority(string key)
    {
        if (key.StartsWith("pacientes:all", StringComparison.OrdinalIgnoreCase))
            return CacheItemPriority.High;
        
        if (key.StartsWith("pacientes:recent", StringComparison.OrdinalIgnoreCase))
            return CacheItemPriority.Normal;
        
        if (key.StartsWith("search:", StringComparison.OrdinalIgnoreCase))
            return CacheItemPriority.Low;
        
        return CacheItemPriority.Normal;
    }

    /// <summary>
    /// Callback quando item é removido do cache
    /// </summary>
    private void OnItemEvicted(object key, object value, EvictionReason reason, object state)
    {
        if (key is string keyStr)
        {
            _cacheKeys.TryRemove(keyStr, out _);
            _logger.LogDebug("Item removido do cache por {Reason}: {Key}", reason, keyStr);
        }
    }

    /// <summary>
    /// Liberta recursos
    /// </summary>
    public void Dispose()
    {
        Clear();
        _memoryCache?.Dispose();
    }
}