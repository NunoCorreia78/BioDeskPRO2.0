using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação do repository para Templates Globais
/// </summary>
public class TemplateGlobalRepository : Repository<TemplateGlobal>, ITemplateGlobalRepository
{
    public TemplateGlobalRepository(BioDeskDbContext context) : base(context)
    {
    }

    /// <summary>
    /// Obter templates disponíveis para anexar em emails
    /// </summary>
    public async Task<IEnumerable<TemplateGlobal>> GetTemplatesDisponiveisEmailAsync()
    {
        return await _dbSet
            .Where(t => t.DisponivelEmail && !t.IsDeleted)
            .OrderBy(t => t.Categoria)
            .ThenBy(t => t.Nome)
            .ToListAsync();
    }

    /// <summary>
    /// Obter templates por categoria
    /// </summary>
    public async Task<IEnumerable<TemplateGlobal>> GetByCategoriaAsync(string categoria)
    {
        return await _dbSet
            .Where(t => t.Categoria == categoria && !t.IsDeleted)
            .OrderBy(t => t.Nome)
            .ToListAsync();
    }

    /// <summary>
    /// Obter templates por tipo (TemplateApp | DocumentoExterno)
    /// </summary>
    public async Task<IEnumerable<TemplateGlobal>> GetByTipoAsync(string tipo)
    {
        return await _dbSet
            .Where(t => t.Tipo == tipo && !t.IsDeleted)
            .OrderBy(t => t.Nome)
            .ToListAsync();
    }

    /// <summary>
    /// Pesquisar templates por nome
    /// </summary>
    public async Task<IEnumerable<TemplateGlobal>> SearchByNomeAsync(string termo)
    {
        if (string.IsNullOrWhiteSpace(termo))
        {
            return await GetAllAsync();
        }

        return await _dbSet
            .Where(t => t.Nome.Contains(termo) && !t.IsDeleted)
            .OrderBy(t => t.Nome)
            .ToListAsync();
    }

    /// <summary>
    /// Obter todos (sem soft-deleted)
    /// </summary>
    public override async Task<IEnumerable<TemplateGlobal>> GetAllAsync()
    {
        return await _dbSet
            .Where(t => !t.IsDeleted)
            .OrderBy(t => t.Categoria)
            .ThenBy(t => t.Nome)
            .ToListAsync();
    }
}
