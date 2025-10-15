using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace BioDesk.Core.Application.Terapia;

public sealed record ProgramStep(double Hz, double Duty, int Seconds, string? Notes = null);

public interface IProgramLibrary
{
    Task<int> ImportExcelAsync(string path, CancellationToken ct);
    Task<IReadOnlyList<string>> ListProgramsAsync(string? search, CancellationToken ct);
    Task<IReadOnlyList<ProgramStep>> GetProgramAsync(string code, CancellationToken ct);
}
