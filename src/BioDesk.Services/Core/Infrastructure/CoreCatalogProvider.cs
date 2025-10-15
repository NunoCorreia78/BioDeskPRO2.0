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
        var items = await _repository.GetAllAsync();

        var include = filter.IncludeCategories?.Select(c => c.Trim()).Where(c => c.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var exclude = filter.ExcludeCategories?.Select(c => c.Trim()).Where(c => c.Length > 0).ToHashSet(StringComparer.OrdinalIgnoreCase);

        bool ShouldInclude(string category)
        {
            if (exclude is not null && exclude.Contains(category))
            {
                return false;
            }

            return include is null || include.Contains(category);
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
