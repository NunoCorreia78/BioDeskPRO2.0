using System;
using System.Threading;
using System.Threading.Tasks;

namespace BioDesk.Core.Application.Terapia;

public interface IEmissionDevice : IAsyncDisposable
{
    Task EmitFrequencyAsync(double hz, double vpp, double duty, TimeSpan duration, CancellationToken ct);
    Task EmitNoiseAsync(TimeSpan duration, CancellationToken ct);
    double? LastCurrentmA { get; }
    double? LastVoltageV { get; }
}
