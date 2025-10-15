using System.Collections.Generic;
using System.Threading;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia;

public interface IResonantFrequencyFinder
{
    IAsyncEnumerable<(double Hz, double Score)> RunAsync(SweepConfig cfg, CancellationToken ct);
}
