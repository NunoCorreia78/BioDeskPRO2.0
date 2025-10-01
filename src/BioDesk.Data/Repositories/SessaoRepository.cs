using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação do repositório de Sessões
/// </summary>
public class SessaoRepository : Repository<Sessao>, ISessaoRepository
{
    public SessaoRepository(BioDeskDbContext context) : base(context)
    {
    }

    public async Task<IEnumerable<Sessao>> GetByPacienteIdAsync(int pacienteId, bool includeDeleted = false)
    {
        var query = _dbSet
            .Include(s => s.Abordagens)
            .Where(s => s.PacienteId == pacienteId);

        if (!includeDeleted)
            query = query.Where(s => !s.IsDeleted);

        return await query
            .OrderByDescending(s => s.DataHora)
            .ToListAsync();
    }

    public async Task<Sessao?> GetCompleteByIdAsync(int id)
    {
        return await _dbSet
            .Include(s => s.Abordagens)
            .Include(s => s.Paciente)
            .FirstOrDefaultAsync(s => s.Id == id);
    }

    public async Task<int> CountHojeAsync()
    {
        var hoje = DateTime.Today;
        var amanha = hoje.AddDays(1);

        return await _dbSet
            .Where(s => s.DataHora >= hoje && s.DataHora < amanha && !s.IsDeleted)
            .CountAsync();
    }

    public async Task<int> CountByPeriodoAsync(DateTime dataInicio, DateTime dataFim)
    {
        return await _dbSet
            .Where(s => s.DataHora >= dataInicio && s.DataHora < dataFim && !s.IsDeleted)
            .CountAsync();
    }

    public async Task<IEnumerable<Sessao>> GetUltimasAsync(int pacienteId, int count = 5)
    {
        return await _dbSet
            .Include(s => s.Abordagens)
            .Where(s => s.PacienteId == pacienteId && !s.IsDeleted)
            .OrderByDescending(s => s.DataHora)
            .Take(count)
            .ToListAsync();
    }

    public async Task SoftDeleteAsync(int id)
    {
        var sessao = await _dbSet.FindAsync(id);
        if (sessao != null)
        {
            sessao.IsDeleted = true;
            _dbSet.Update(sessao);
        }
    }
}
