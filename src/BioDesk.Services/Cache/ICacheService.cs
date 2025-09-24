using System;
using System.Threading.Tasks;

namespace BioDesk.Services.Cache;

/// <summary>
/// Interface para serviço de cache genérico
/// </summary>
public interface ICacheService
{
    /// <summary>
    /// Obtém um item do cache
    /// </summary>
    T? Get<T>(string key) where T : class;

    /// <summary>
    /// Obtém um item do cache ou executa a função para obtê-lo
    /// </summary>
    Task<T> GetOrSetAsync<T>(string key, Func<Task<T>> getItem, TimeSpan? expiry = null) where T : class;

    /// <summary>
    /// Define um item no cache
    /// </summary>
    void Set<T>(string key, T item, TimeSpan? expiry = null) where T : class;

    /// <summary>
    /// Remove um item do cache
    /// </summary>
    void Remove(string key);

    /// <summary>
    /// Remove todos os itens do cache que começam com o prefixo especificado
    /// </summary>
    void RemoveByPattern(string pattern);

    /// <summary>
    /// Limpa todo o cache
    /// </summary>
    void Clear();

    /// <summary>
    /// Verifica se existe um item no cache
    /// </summary>
    bool Exists(string key);
}