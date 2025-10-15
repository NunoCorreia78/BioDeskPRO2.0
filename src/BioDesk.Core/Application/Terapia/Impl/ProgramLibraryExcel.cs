using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace BioDesk.Core.Application.Terapia.Impl;

public sealed class ProgramLibraryExcel : IProgramLibrary
{
    public Task<int> ImportExcelAsync(string path, CancellationToken ct)
    {
        // TODO: Integrar ClosedXML; stub devolve zero para indicar sucesso
        return Task.FromResult(0);
    }

    public Task<IReadOnlyList<string>> ListProgramsAsync(string? search, CancellationToken ct)
    {
        IReadOnlyList<string> items = new[]
        {
            "PROTO::DetoxFigado",
            "PROTO::AntiViral",
            "PROTO::EquilibrioEmocional"
        };

        if (string.IsNullOrWhiteSpace(search))
        {
            return Task.FromResult(items);
        }

        var filtered = items.Where(p => p.Contains(search, StringComparison.OrdinalIgnoreCase)).ToList();
        return Task.FromResult((IReadOnlyList<string>)filtered);
    }

    public Task<IReadOnlyList<ProgramStep>> GetProgramAsync(string code, CancellationToken ct)
    {
        IReadOnlyList<ProgramStep> steps = new[]
        {
            new ProgramStep(728, 50, 30, "Frequência base Rife"),
            new ProgramStep(880, 50, 25, "Harmonização órgão alvo"),
            new ProgramStep(1500, 35, 20, "Elevação energética")
        };

        return Task.FromResult(steps);
    }
}
