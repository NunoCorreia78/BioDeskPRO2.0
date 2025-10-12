using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.EntityFrameworkCore;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Implementação do repositório de Pacientes
/// Queries otimizadas com Include estratégico
/// </summary>
public class PacienteRepository : Repository<Paciente>, IPacienteRepository
{
    public PacienteRepository(BioDeskDbContext context) : base(context)
    {
    }

    public async Task<Paciente?> GetCompleteByIdAsync(int id)
    {
        return await _dbSet
            .Include(p => p.Contacto)
            .Include(p => p.DeclaracaoSaude) // ⭐ Aba 2 - Declaração de Saúde
            .Include(p => p.Consultas)
            .Include(p => p.Consentimentos)
            .Include(p => p.IrisAnalises)
            .AsSplitQuery() // ⚡ CRITICAL: Evita cartesian explosion
            .FirstOrDefaultAsync(p => p.Id == id);
    }

    public async Task<Paciente?> GetWithContactoAsync(int id)
    {
        return await _dbSet
            .Include(p => p.Contacto)
            .FirstOrDefaultAsync(p => p.Id == id);
    }

    public async Task<IEnumerable<Paciente>> SearchByNomeAsync(string nome)
    {
        var nomeNormalizado = nome.ToLowerInvariant().Trim();
        
        return await _dbSet
            .Where(p => p.NomeCompleto.ToLower().Contains(nomeNormalizado))
            .OrderBy(p => p.NomeCompleto)
            .Take(50) // Limitar resultados
            .ToListAsync();
    }

    public async Task<Paciente?> GetByNumeroProcessoAsync(string numeroProcesso)
    {
        return await _dbSet
            .Include(p => p.Contacto)
            .FirstOrDefaultAsync(p => p.NumeroProcesso == numeroProcesso);
    }

    public async Task<IEnumerable<Paciente>> GetRecentesAsync(int count = 10)
    {
        return await _dbSet
            .OrderByDescending(p => p.DataUltimaAtualizacao ?? p.DataCriacao)
            .Take(count)
            .ToListAsync();
    }

    /// <summary>
    /// Obtém TODOS os pacientes ordenados alfabeticamente
    /// Útil para Lista de Pacientes completa
    /// </summary>
    public async Task<IEnumerable<Paciente>> GetAllOrderedByNomeAsync()
    {
        return await _dbSet
            .OrderBy(p => p.NomeCompleto)
            .ToListAsync();
    }

    public async Task<int> CountTotalAsync()
    {
        return await _dbSet.CountAsync();
    }
}
