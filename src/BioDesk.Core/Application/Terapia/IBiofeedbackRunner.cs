using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia;

public interface IBiofeedbackRunner
{
    Task RunLocalAsync(IReadOnlyList<ScanResultItem> items, LocalEmissionConfig cfg, CancellationToken ct);
    Task RunRemoteAsync(IReadOnlyList<ScanResultItem> items, RemoteEmissionConfig cfg, CancellationToken ct);
}
