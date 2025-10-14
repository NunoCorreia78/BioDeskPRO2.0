using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Repository para ProtocoloTerapeutico (protocolos de frequências)
/// </summary>
public interface IProtocoloRepository
{
    /// <summary>
    /// Busca protocolo por ID
    /// </summary>
    Task<ProtocoloTerapeutico?> GetByIdAsync(int id);

    /// <summary>
    /// Busca protocolo por ExternalId (GUID)
    /// </summary>
    Task<ProtocoloTerapeutico?> GetByExternalIdAsync(string externalId);

    /// <summary>
    /// Lista todos protocolos ativos
    /// </summary>
    Task<List<ProtocoloTerapeutico>> GetAllActiveAsync();

    /// <summary>
    /// Busca protocolos por categoria
    /// </summary>
    Task<List<ProtocoloTerapeutico>> GetByCategoriaAsync(string categoria);

    /// <summary>
    /// Pesquisa protocolos por nome (contains)
    /// </summary>
    Task<List<ProtocoloTerapeutico>> SearchByNameAsync(string searchTerm);

    /// <summary>
    /// Adiciona ou atualiza protocolo (upsert por ExternalId)
    /// </summary>
    Task<ProtocoloTerapeutico> UpsertAsync(ProtocoloTerapeutico protocolo);

    /// <summary>
    /// Adiciona múltiplos protocolos em batch
    /// </summary>
    Task<int> BulkInsertAsync(List<ProtocoloTerapeutico> protocolos);

    /// <summary>
    /// Desativa protocolo (soft delete)
    /// </summary>
    Task<bool> DeactivateAsync(int id);

    /// <summary>
    /// Conta total de protocolos ativos
    /// </summary>
    Task<int> CountActiveAsync();

    /// <summary>
    /// Regista log de importação Excel
    /// </summary>
    Task AddImportLogAsync(string nomeArquivo, int totalLinhas, int sucessos, int erros, string? mensagemErro = null);
}
