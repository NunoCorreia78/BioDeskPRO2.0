using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia.Impl;

public sealed class ResonanceEngine : IResonanceEngine
{
    private readonly ISeedProvider _seedProvider;
    private readonly IPatternValidator _validator;
    private readonly ICoreCatalogProvider _catalogProvider;
    private readonly IRng _rng;

    public ResonanceEngine(
        ISeedProvider seedProvider,
        IPatternValidator validator,
        ICoreCatalogProvider catalogProvider,
        IRng? rng = null)
    {
        _seedProvider = seedProvider;
        _validator = validator;
        _catalogProvider = catalogProvider;
        _rng = rng ?? new XorShift128PlusRng(1);
    }

    public async Task<IReadOnlyList<ScanResultItem>> RunScanAsync(ScanConfig cfg, CancellationToken ct)
    {
        var catalog = await _catalogProvider.GetCatalogAsync(cfg.Filter, ct).ConfigureAwait(false);
        if (catalog.Count == 0)
        {
            return Array.Empty<ScanResultItem>();
        }

        _rng.Reseed(cfg.Seed);

        var hits = new int[catalog.Count];

        for (var iteration = 0; iteration < cfg.Iterations; iteration++)
        {
            ct.ThrowIfCancellationRequested();
            var index = _rng.NextInt(catalog.Count);
            hits[index]++;
        }

        var validated = _validator.Validate(
            hits,
            cfg.Iterations,
            catalog.Count,
            cfg.Validation,
            (i, _) => catalog[i].Name,
            (i, _) => catalog[i].Code,
            (i, _) => catalog[i].Category);

        return validated;
    }
}
