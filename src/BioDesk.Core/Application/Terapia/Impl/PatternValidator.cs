using System;
using System.Collections.Generic;
using System.Linq;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia.Impl;

public sealed class PatternValidator : IPatternValidator
{
    public IReadOnlyList<ScanResultItem> Validate(
        int[] hits,
        int totalIterations,
        int itemCount,
        PatternValidationConfig cfg,
        Func<int, int, string> itemName,
        Func<int, int, string> itemCode,
        Func<int, int, string> itemCategory)
    {
        if (hits.Length == 0 || totalIterations <= 0 || itemCount <= 0)
        {
            return Array.Empty<ScanResultItem>();
        }

        var p = 1.0 / itemCount;
        var mean = totalIterations * p;
        var std = Math.Sqrt(totalIterations * p * (1 - p) + 1e-9);
        var maxHits = hits.Max();

        var items = new List<ScanResultItem>(itemCount);

        for (var i = 0; i < itemCount; i++)
        {
            var z = (hits[i] - mean) / std;
            var pct = maxHits == 0 ? 0 : hits[i] * 100.0 / maxHits;

            if (z >= cfg.MinZ && pct >= cfg.MinScorePercent)
            {
                items.Add(new ScanResultItem(
                    i,
                    itemCode(i, itemCount),
                    itemName(i, itemCount),
                    itemCategory(i, itemCount),
                    Math.Round(pct, 2),
                    Math.Round(z, 2),
                    QValue: 0));
            }
        }

        var filtered = items
            .OrderByDescending(r => r.ScorePercent)
            .ToList();

        // Garantir mínimo de 10 resultados (ou todos se houver menos)
        const int MinResults = 10;
        if (filtered.Count < MinResults)
        {
            // Adicionar os próximos melhores mesmo que não passem nos thresholds
            var allItems = new List<ScanResultItem>(itemCount);
            for (var i = 0; i < itemCount; i++)
            {
                var z = (hits[i] - mean) / std;
                var pct = maxHits == 0 ? 0 : hits[i] * 100.0 / maxHits;

                allItems.Add(new ScanResultItem(
                    i,
                    itemCode(i, itemCount),
                    itemName(i, itemCount),
                    itemCategory(i, itemCount),
                    Math.Round(pct, 2),
                    Math.Round(z, 2),
                    QValue: 0));
            }

            filtered = allItems
                .OrderByDescending(r => r.ScorePercent)
                .Take(MinResults)
                .ToList();
        }

        return filtered
            .Select((r, index) => r with { Rank = index + 1 })
            .ToList();
    }
}
