using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação do repositório de histórico de sessões terapêuticas
/// </summary>
public class SessionHistoricoRepository : Repository<SessionHistorico>, ISessionHistoricoRepository
{
    public SessionHistoricoRepository(BioDeskDbContext context) : base(context)
    {
    }

    public new async Task<IEnumerable<SessionHistorico>> GetAllAsync()
    {
        return await _dbSet
            .Include(s => s.Paciente)
            .OrderByDescending(s => s.DataHoraInicio)
            .ToListAsync();
    }

    public async Task<IEnumerable<SessionHistorico>> GetByPacienteIdAsync(int pacienteId)
    {
        return await _dbSet
            .Include(s => s.Paciente)
            .Where(s => s.PacienteId == pacienteId)
            .OrderByDescending(s => s.DataHoraInicio)
            .ToListAsync();
    }

    public async Task<IEnumerable<SessionHistorico>> GetByDateRangeAsync(DateTime dataInicio, DateTime dataFim)
    {
        return await _dbSet
            .Include(s => s.Paciente)
            .Where(s => s.DataHoraInicio >= dataInicio && s.DataHoraInicio < dataFim)
            .OrderByDescending(s => s.DataHoraInicio)
            .ToListAsync();
    }

    public async Task<IEnumerable<SessionHistorico>> GetByTipoTerapiaAsync(TipoTerapia tipoTerapia)
    {
        return await _dbSet
            .Include(s => s.Paciente)
            .Where(s => s.TipoTerapia == tipoTerapia)
            .OrderByDescending(s => s.DataHoraInicio)
            .ToListAsync();
    }

    public async Task<IEnumerable<SessionHistorico>> GetUltimasAsync(int count = 10)
    {
        return await _dbSet
            .Include(s => s.Paciente)
            .OrderByDescending(s => s.DataHoraInicio)
            .Take(count)
            .ToListAsync();
    }
}
