using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia;

public sealed record CoreCatalogItem(int ItemId, string Code, string Name, string Category);

public interface ICoreCatalogProvider
{
    Task<IReadOnlyList<CoreCatalogItem>> GetCatalogAsync(ItemFilter filter, CancellationToken ct);
}
