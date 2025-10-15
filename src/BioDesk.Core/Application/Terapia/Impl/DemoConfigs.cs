using System;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia.Impl;

public static class DemoConfigs
{
    private static readonly ISeedProvider SeedProvider = new SeedProvider();

    public static ScanConfig BuildScanConfig(string seedSource, string sessionSalt, string rngEngine, int iterations)
    {
        var anchor = $"{seedSource}:{rngEngine}";
        var seed = SeedProvider.BuildSeed(new SeedInputs(anchor, sessionSalt));

        var filter = new ItemFilter(
            IncludeCategories: new[] { "Florais", "Órgão", "Meridiano", "Chakra", "Vitamina" },
            ExcludeCategories: Array.Empty<string>());

        var validation = new PatternValidationConfig(
            NullModelRuns: 128,
            MinZ: 1.25,
            MinScorePercent: 25,
            MaxQValue: 0.25,
            Replicas: 3,
            SaltJitter: 0.05);

        return new ScanConfig(seed, iterations, filter, validation);
    }
}
