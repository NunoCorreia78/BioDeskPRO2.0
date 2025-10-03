using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Repositório especializado para Sessões (Consultas)
/// </summary>
public interface ISessaoRepository : IRepository<Sessao>
{
    /// <summary>
    /// Carrega sessões de um paciente com abordagens (Aba 4)
    /// </summary>
    Task<IEnumerable<Sessao>> GetByPacienteIdAsync(int pacienteId, bool includeDeleted = false);

    /// <summary>
    /// Carrega sessão completa com abordagens
    /// </summary>
    Task<Sessao?> GetCompleteByIdAsync(int id);

    /// <summary>
    /// Conta consultas do dia (Dashboard)
    /// </summary>
    Task<int> CountHojeAsync();

    /// <summary>
    /// Conta consultas por período
    /// </summary>
    Task<int> CountByPeriodoAsync(DateTime dataInicio, DateTime dataFim);

    /// <summary>
    /// Últimas N sessões de um paciente
    /// </summary>
    Task<IEnumerable<Sessao>> GetUltimasAsync(int pacienteId, int count = 5);

    /// <summary>
    /// Soft delete (IsDeleted = true)
    /// </summary>
    Task SoftDeleteAsync(int id);
}
