using System;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Unit of Work Pattern - Coordena transações entre repositórios
/// Garante consistência transacional (ACID)
/// </summary>
public interface IUnitOfWork : IDisposable
{
    // Repositórios
    IPacienteRepository Pacientes { get; }
    ISessaoRepository Sessoes { get; }
    IRepository<Contacto> Contactos { get; }
    IRepository<Consentimento> Consentimentos { get; }
    IRepository<Comunicacao> Comunicacoes { get; }
    IRepository<HistoricoMedico> HistoricoMedico { get; }

    /// <summary>
    /// Salva todas as alterações em uma transação atômica
    /// </summary>
    Task<int> SaveChangesAsync();

    /// <summary>
    /// Inicia transação explícita para operações complexas
    /// </summary>
    Task BeginTransactionAsync();

    /// <summary>
    /// Confirma transação
    /// </summary>
    Task CommitTransactionAsync();

    /// <summary>
    /// Reverte transação
    /// </summary>
    Task RollbackTransactionAsync();
}
