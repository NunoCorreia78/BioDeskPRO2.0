using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace BioDesk.Core.Application.Terapia.Impl;

/// <summary>
/// Resultado simplificado de importação Excel para uso em BioDesk.Core
/// </summary>
public record ExcelImportResultCore(bool Sucesso, int LinhasImportadas, string? Erro);

public sealed class ProgramLibraryExcel : IProgramLibrary
{
    private readonly Func<string, Task<ExcelImportResultCore>> _importFunction;

    /// <summary>
    /// Constructor com delegate para evitar dependência circular
    /// </summary>
    /// <param name="importFunction">Função que executa a importação Excel (injetada via DI wrapper)</param>
    public ProgramLibraryExcel(Func<string, Task<ExcelImportResultCore>> importFunction)
    {
        _importFunction = importFunction;
    }

    public async Task<int> ImportExcelAsync(string path, CancellationToken ct)
    {
        var result = await _importFunction(path);
        if (!result.Sucesso)
        {
            throw new InvalidOperationException($"Falha na importação: {result.Erro}");
        }
        return result.LinhasImportadas;
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
