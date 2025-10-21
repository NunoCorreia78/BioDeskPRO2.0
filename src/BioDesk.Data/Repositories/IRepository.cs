using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Threading;
using System.Threading.Tasks;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Interface genérica para todos os repositórios
/// Implementa padrão Repository para abstração de acesso a dados
/// </summary>
public interface IRepository<TEntity> where TEntity : class
{
    // === QUERIES ===
    Task<TEntity?> GetByIdAsync(int id, CancellationToken cancellationToken = default);
    Task<IEnumerable<TEntity>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IEnumerable<TEntity>> FindAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default);
    Task<TEntity?> FirstOrDefaultAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(Expression<Func<TEntity, bool>> predicate, CancellationToken cancellationToken = default);
    Task<int> CountAsync(Expression<Func<TEntity, bool>>? predicate = null, CancellationToken cancellationToken = default);

    // === COMMANDS ===
    Task<TEntity> AddAsync(TEntity entity);
    Task<IEnumerable<TEntity>> AddRangeAsync(IEnumerable<TEntity> entities);
    void Update(TEntity entity);
    void UpdateRange(IEnumerable<TEntity> entities);
    void Remove(TEntity entity);
    void RemoveRange(IEnumerable<TEntity> entities);
}
