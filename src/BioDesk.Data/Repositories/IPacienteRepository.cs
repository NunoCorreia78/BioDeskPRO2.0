using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Repositório especializado para Pacientes
/// Métodos otimizados para operações comuns
/// </summary>
public interface IPacienteRepository : IRepository<Paciente>
{
    /// <summary>
    /// Carrega paciente com TODAS as entidades relacionadas (Contacto, Consultas, etc.)
    /// </summary>
    Task<Paciente?> GetCompleteByIdAsync(int id);

    /// <summary>
    /// Carrega paciente apenas com Contacto (mais rápido para Aba 1)
    /// </summary>
    Task<Paciente?> GetWithContactoAsync(int id);

    /// <summary>
    /// Busca pacientes por nome (case-insensitive, partial match)
    /// </summary>
    Task<IEnumerable<Paciente>> SearchByNomeAsync(string nome);

    /// <summary>
    /// Busca paciente por número de processo (único)
    /// </summary>
    Task<Paciente?> GetByNumeroProcessoAsync(string numeroProcesso);

    /// <summary>
    /// Retorna pacientes criados/modificados recentemente (para Dashboard)
    /// </summary>
    Task<IEnumerable<Paciente>> GetRecentesAsync(int count = 10);

    /// <summary>
    /// Obtém TODOS os pacientes ordenados alfabeticamente por nome
    /// </summary>
    Task<IEnumerable<Paciente>> GetAllOrderedByNomeAsync();

    /// <summary>
    /// Conta total de pacientes (cached no Dashboard)
    /// </summary>
    Task<int> CountTotalAsync();
}
