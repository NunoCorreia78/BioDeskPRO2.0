using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Repositório especializado para histórico de sessões terapêuticas
/// </summary>
public interface ISessionHistoricoRepository : IRepository<SessionHistorico>
{
    /// <summary>
    /// Carrega todas as sessões (mais recentes primeiro)
    /// </summary>
    new Task<IEnumerable<SessionHistorico>> GetAllAsync();

    /// <summary>
    /// Carrega sessões de um paciente específico
    /// </summary>
    Task<IEnumerable<SessionHistorico>> GetByPacienteIdAsync(int pacienteId);

    /// <summary>
    /// Carrega sessões num intervalo de datas
    /// </summary>
    Task<IEnumerable<SessionHistorico>> GetByDateRangeAsync(DateTime dataInicio, DateTime dataFim);

    /// <summary>
    /// Carrega sessões de um tipo específico (Remota/Local/Biofeedback)
    /// </summary>
    Task<IEnumerable<SessionHistorico>> GetByTipoTerapiaAsync(TipoTerapia tipoTerapia);

    /// <summary>
    /// Carrega últimas N sessões globais
    /// </summary>
    Task<IEnumerable<SessionHistorico>> GetUltimasAsync(int count = 10);
}
