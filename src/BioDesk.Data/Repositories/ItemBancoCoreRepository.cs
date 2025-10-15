using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação do repository para itens do Banco Core
/// </summary>
public class ItemBancoCoreRepository : IItemBancoCoreRepository
{
    private readonly BioDeskDbContext _context;

    public ItemBancoCoreRepository(BioDeskDbContext context)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
    }

    public async Task<List<ItemBancoCore>> GetAllAsync()
    {
        return await _context.ItensBancoCore
            .Where(i => i.IsActive)
            .OrderBy(i => i.Categoria)
            .ThenBy(i => i.Nome)
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task<List<ItemBancoCore>> GetByCategoriaAsync(CategoriaCore categoria)
    {
        return await _context.ItensBancoCore
            .Where(i => i.IsActive && i.Categoria == categoria)
            .OrderBy(i => i.Nome)
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task<ItemBancoCore?> GetByExternalIdAsync(Guid externalId)
    {
        return await _context.ItensBancoCore
            .AsNoTracking()
            .FirstOrDefaultAsync(i => i.ExternalId == externalId);
    }

    public async Task<List<ItemBancoCore>> SearchAsync(string termo)
    {
        if (string.IsNullOrWhiteSpace(termo))
            return await GetAllAsync();

        var termoLower = termo.ToLower().Trim();

        return await _context.ItensBancoCore
            .Where(i => i.IsActive &&
                   (i.Nome.ToLower().Contains(termoLower) ||
                    (i.DescricaoBreve != null && i.DescricaoBreve.ToLower().Contains(termoLower))))
            .OrderBy(i => i.Categoria)
            .ThenBy(i => i.Nome)
            .AsNoTracking()
            .ToListAsync();
    }

    public async Task<Dictionary<CategoriaCore, int>> GetCountPorCategoriaAsync()
    {
        return await _context.ItensBancoCore
            .Where(i => i.IsActive)
            .GroupBy(i => i.Categoria)
            .Select(g => new { Categoria = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Categoria, x => x.Count);
    }
}
