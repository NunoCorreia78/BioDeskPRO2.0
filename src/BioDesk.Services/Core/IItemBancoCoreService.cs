using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Services.Core;

/// <summary>
/// Service para lógica de negócio dos itens do Banco Core
/// </summary>
public interface IItemBancoCoreService
{
    /// <summary>
    /// Retorna todos os itens disponíveis (com cache de 5 minutos)
    /// </summary>
    Task<List<ItemBancoCore>> GetItensDisponiveisAsync();

    /// <summary>
    /// Retorna itens de uma categoria específica
    /// </summary>
    Task<List<ItemBancoCore>> GetItensPorCategoriaAsync(CategoriaCore categoria);

    /// <summary>
    /// Busca item por ExternalId
    /// </summary>
    Task<ItemBancoCore?> GetItemAsync(Guid externalId);

    /// <summary>
    /// Pesquisa com termo (nome, notas)
    /// </summary>
    Task<List<ItemBancoCore>> PesquisarAsync(string termo);

    /// <summary>
    /// Valida integridade do seed (156 itens: 38+28+20+70)
    /// </summary>
    Task<ValidationResult> ValidarIntegridadeAsync();

    /// <summary>
    /// Invalida cache (forçar reload)
    /// </summary>
    void InvalidarCache();
}

/// <summary>
/// Resultado da validação de integridade do Banco Core
/// </summary>
public class ValidationResult
{
    public bool IsValido { get; set; }
    public int TotalItens { get; set; }
    public Dictionary<CategoriaCore, int> CountPorCategoria { get; set; } = new();
    public List<string> Erros { get; set; } = new();

    public override string ToString()
    {
        if (IsValido)
            return $"✅ Validação OK - {TotalItens} itens";

        return $"❌ Validação FALHOU:\n{string.Join("\n", Erros)}";
    }
}
