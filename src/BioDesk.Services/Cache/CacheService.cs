using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Cache;

/// <summary>
/// Serviço de cache em memória com TTL e invalidação inteligente
/// Otimiza performance reduzindo queries repetidas à BD
/// </summary>
public interface ICacheService
{
    /// <summary>
    /// Obtém valor do cache ou executa factory se não existe
    /// </summary>
    Task<T> GetOrCreateAsync<T>(string key, Func<Task<T>> factory, TimeSpan? expiration = null);

    /// <summary>
    /// Adiciona/atualiza valor no cache
    /// </summary>
    void Set<T>(string key, T value, TimeSpan? expiration = null);

    /// <summary>
    /// Obtém valor do cache
    /// </summary>
    T? Get<T>(string key);

    /// <summary>
    /// Remove valor do cache
    /// </summary>
    void Remove(string key);

    /// <summary>
    /// Remove todos os valores com prefixo específico
    /// </summary>
    void RemoveByPrefix(string prefix);

    /// <summary>
    /// Limpa todo o cache
    /// </summary>
    void Clear();
}

public class CacheService : ICacheService, IDisposable
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<CacheService> _logger;
    private readonly ConcurrentDictionary<string, bool> _cacheKeys;
    private readonly SemaphoreSlim _semaphore;
    private readonly TimeSpan _defaultExpiration = TimeSpan.FromMinutes(5);
    private bool _disposed = false;

    public CacheService(IMemoryCache cache, ILogger<CacheService> logger)
    {
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _cacheKeys = new ConcurrentDictionary<string, bool>();
        _semaphore = new SemaphoreSlim(1, 1);
    }

    public async Task<T> GetOrCreateAsync<T>(string key, Func<Task<T>> factory, TimeSpan? expiration = null)
    {
        // Tentar obter do cache primeiro
        if (_cache.TryGetValue(key, out T? cachedValue) && cachedValue != null)
        {
            _logger.LogTrace("✅ Cache HIT: {Key}", key);
            return cachedValue;
        }

        // Cache MISS - precisa executar factory
        _logger.LogTrace("❌ Cache MISS: {Key} - executando factory...", key);

        // Usar semaphore para evitar múltiplas execuções simultâneas da mesma factory
        await _semaphore.WaitAsync();
        try
        {
            // Double-check após adquirir lock
            if (_cache.TryGetValue(key, out cachedValue) && cachedValue != null)
            {
                _logger.LogTrace("✅ Cache HIT (após wait): {Key}", key);
                return cachedValue;
            }

            // Executar factory
            var value = await factory();

            // Armazenar no cache
            Set(key, value, expiration);

            _logger.LogDebug("📦 Valor adicionado ao cache: {Key}", key);
            return value;
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public void Set<T>(string key, T value, TimeSpan? expiration = null)
    {
        var actualExpiration = expiration ?? _defaultExpiration;

        var cacheEntryOptions = new MemoryCacheEntryOptions()
            .SetAbsoluteExpiration(actualExpiration)
            .RegisterPostEvictionCallback((k, v, reason, state) =>
            {
                _cacheKeys.TryRemove(k.ToString()!, out _);
                _logger.LogTrace("🗑️ Item removido do cache: {Key} (Razão: {Reason})", k, reason);
            });

        _cache.Set(key, value, cacheEntryOptions);
        _cacheKeys.TryAdd(key, true);

        _logger.LogTrace("✅ Set cache: {Key} (Expira em: {Expiration})", key, actualExpiration);
    }

    public T? Get<T>(string key)
    {
        if (_cache.TryGetValue(key, out T? value))
        {
            _logger.LogTrace("✅ Get cache HIT: {Key}", key);
            return value;
        }

        _logger.LogTrace("❌ Get cache MISS: {Key}", key);
        return default;
    }

    public void Remove(string key)
    {
        _cache.Remove(key);
        _cacheKeys.TryRemove(key, out _);
        _logger.LogDebug("🗑️ Removido do cache: {Key}", key);
    }

    public void RemoveByPrefix(string prefix)
    {
        var keysToRemove = _cacheKeys.Keys
            .Where(k => k.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var key in keysToRemove)
        {
            Remove(key);
        }

        _logger.LogInformation("🗑️ Removidos {Count} itens do cache com prefixo '{Prefix}'", keysToRemove.Count, prefix);
    }

    public void Clear()
    {
        var keys = _cacheKeys.Keys.ToList();
        foreach (var key in keys)
        {
            _cache.Remove(key);
        }
        _cacheKeys.Clear();

        _logger.LogInformation("🗑️ Cache completamente limpo ({Count} itens removidos)", keys.Count);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _semaphore?.Dispose();
        }
        _disposed = true;
    }
}

/// <summary>
/// Constantes para chaves de cache (evitar typos)
/// </summary>
public static class CacheKeys
{
    // Dashboard
    public const string TotalPacientes = "Dashboard:TotalPacientes";
    public const string ConsultasHoje = "Dashboard:ConsultasHoje";
    public const string EmailsPendentes = "Dashboard:EmailsPendentes";

    // Pacientes
    public static string Paciente(int id) => $"Paciente:{id}";
    public static string PacienteCompleto(int id) => $"Paciente:Complete:{id}";
    public static string PacienteContacto(int id) => $"Paciente:Contacto:{id}";

    // Sessões
    public static string SessoesPaciente(int pacienteId) => $"Sessoes:Paciente:{pacienteId}";
    public static string Sessao(int id) => $"Sessao:{id}";

    // Prefixos para invalidação em lote
    public const string PrefixPacientes = "Paciente:";
    public const string PrefixSessoes = "Sessoes:";
    public const string PrefixDashboard = "Dashboard:";
}
