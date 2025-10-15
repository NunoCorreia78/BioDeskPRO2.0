using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia.Impl;

public sealed class ResonantFrequencyFinder : IResonantFrequencyFinder
{
    public async IAsyncEnumerable<(double Hz, double Score)> RunAsync(
        SweepConfig cfg,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct)
    {
        var step = Math.Max(0.0001, cfg.StepHz);

        for (var hz = cfg.StartHz; hz <= cfg.StopHz; hz += step)
        {
            ct.ThrowIfCancellationRequested();

            var score = Math.Round((hz % 13) / 12.0 * 100.0, 2); // Stub heurística
            yield return (Math.Round(hz, 4), score);

            if (cfg.DwellMs > 0)
            {
                await Task.Delay(cfg.DwellMs, ct);
            }
        }
    }
}
