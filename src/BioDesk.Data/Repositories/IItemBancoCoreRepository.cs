using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Data.Repositories;

/// <summary>
/// Repository para acesso aos 156 itens do Banco Core (Inergetix-inspired)
/// </summary>
public interface IItemBancoCoreRepository
{
    /// <summary>
    /// Retorna todos os 156 itens ativos do Banco Core
    /// </summary>
    Task<List<ItemBancoCore>> GetAllAsync();

    /// <summary>
    /// Retorna itens filtrados por categoria (ex: só Bach Florais = 38 itens)
    /// </summary>
    Task<List<ItemBancoCore>> GetByCategoriaAsync(CategoriaCore categoria);

    /// <summary>
    /// Busca item específico por ExternalId (Guid único)
    /// </summary>
    Task<ItemBancoCore?> GetByExternalIdAsync(Guid externalId);

    /// <summary>
    /// Pesquisa por nome ou notas (case-insensitive)
    /// Exemplo: "chakra" retorna todos os 28 chakras
    /// </summary>
    Task<List<ItemBancoCore>> SearchAsync(string termo);

    /// <summary>
    /// Conta total de itens por categoria (validação de integridade)
    /// Resultado esperado: BachFlorais=38, Chakras=28, Meridianos=20, Orgaos=70
    /// </summary>
    Task<Dictionary<CategoriaCore, int>> GetCountPorCategoriaAsync();

    /// <summary>
    /// Retorna itens filtrando por género do paciente (crítico para órgãos reprodutores)
    /// </summary>
    /// <param name="generoPaciente">"Masculino", "Feminino" ou null (retorna todos)</param>
    Task<List<ItemBancoCore>> GetAllWithGenderFilterAsync(string? generoPaciente);
}
