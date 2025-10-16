using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Application.Terapia;
using BioDesk.Core.Domain.Terapia;
using BioDesk.Data.Repositories;

namespace BioDesk.Services.Core.Infrastructure;

public sealed class CoreCatalogProvider : ICoreCatalogProvider
{
    private readonly IItemBancoCoreRepository _repository;

    public CoreCatalogProvider(IItemBancoCoreRepository repository)
    {
        _repository = repository;
    }

    public async Task<IReadOnlyList<CoreCatalogItem>> GetCatalogAsync(ItemFilter filter, CancellationToken ct)
    {
        // TODO: Obter género do paciente ativo do contexto (por enquanto null = todos)
        var items = await _repository.GetAllWithGenderFilterAsync(generoPaciente: null);

        // Normaliza strings removendo acentos para comparação robusta (Órgão → Orgao)
        static string Normalize(string s) => s.Trim()
            .Replace("ã", "a").Replace("á", "a").Replace("à", "a")
            .Replace("é", "e").Replace("ê", "e")
            .Replace("í", "i").Replace("ó", "o").Replace("õ", "o")
            .Replace("ú", "u").Replace("ç", "c");

        var include = filter.IncludeCategories?.Select(c => Normalize(c)).Where(c => c.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var exclude = filter.ExcludeCategories?.Select(c => Normalize(c)).Where(c => c.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool ShouldInclude(string category)
        {
            var normalized = Normalize(category);
            if (exclude is not null && exclude.Contains(normalized))
            {
                return false;
            }

            return include is null || include.Count == 0 || include.Contains(normalized);
        }

        var filtered = items
            .Where(item => ShouldInclude(item.Categoria.ToString()))
            .Select(item => new CoreCatalogItem(
                item.Id,
                item.ExternalId.ToString(),
                item.Nome,
                item.Categoria.ToString()))
            .ToList();

        return filtered;
    }
}
