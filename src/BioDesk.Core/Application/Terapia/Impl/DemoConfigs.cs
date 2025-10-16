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

        // NUNCA passar filtro default - sempre null (ViewModels controlam filtros)
        var filter = new ItemFilter(
            IncludeCategories: Array.Empty<string>(),
            ExcludeCategories: Array.Empty<string>());

        var validation = new PatternValidationConfig(
            NullModelRuns: 128,
            MinZ: 0.5,           // Reduzido de 1.25 para permitir mais resultados
            MinScorePercent: 10,  // Reduzido de 25 para permitir mais resultados
            MaxQValue: 0.35,      // Aumentado de 0.25 para ser menos restritivo
            Replicas: 3,
            SaltJitter: 0.05);

        return new ScanConfig(seed, iterations, filter, validation);
    }
}
