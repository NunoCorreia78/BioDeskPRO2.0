using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia;

public interface IResonanceEngine
{
    Task<IReadOnlyList<ScanResultItem>> RunScanAsync(ScanConfig cfg, CancellationToken ct);
}
