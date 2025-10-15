using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Core.Domain.Terapia;

namespace BioDesk.Core.Application.Terapia.Impl;

public sealed class LogisticImprovementModel : IImprovementModel
{
    public double Next(double current, double z, double scorePct, TimeSpan dt)
    {
        var baseStep = 0.6 + Math.Min(1.4, z / 3.0) + (scorePct / 100.0) * 0.8;
        return Math.Clamp(current + baseStep * dt.TotalSeconds, 0, 100);
    }
}

public sealed class NullInformationalEmitter : IEmissionDevice
{
    public double? LastCurrentmA => null;
    public double? LastVoltageV => null;

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    public Task EmitFrequencyAsync(double hz, double vpp, double duty, TimeSpan duration, CancellationToken ct) =>
        Task.Delay(duration, ct);

    public Task EmitNoiseAsync(TimeSpan duration, CancellationToken ct) =>
        Task.Delay(duration, ct);
}

public sealed class BiofeedbackRunner : IBiofeedbackRunner
{
    private readonly IEmissionDevice _device;
    private readonly IImprovementModel _improvement;

    public BiofeedbackRunner(IEmissionDevice device, IImprovementModel improvement)
    {
        _device = device;
        _improvement = improvement;
    }

    public async Task RunLocalAsync(IReadOnlyList<ScanResultItem> items, LocalEmissionConfig cfg, CancellationToken ct)
    {
        foreach (var item in items)
        {
            var start = DateTime.UtcNow;
            while (DateTime.UtcNow - start < cfg.PerItem)
            {
                await _device.EmitFrequencyAsync(cfg.FrequencyHz, cfg.Vpp, cfg.Duty, TimeSpan.FromMilliseconds(800), ct);
                await Task.Delay(200, ct);
            }
        }
    }

    public async Task RunRemoteAsync(IReadOnlyList<ScanResultItem> items, RemoteEmissionConfig cfg, CancellationToken ct)
    {
        foreach (var item in items)
        {
            for (var cycle = 0; cycle < cfg.Cycles; cycle++)
            {
                await _device.EmitNoiseAsync(TimeSpan.FromMilliseconds(cfg.OnMs), ct);
                await Task.Delay(cfg.OffMs, ct);
            }

            if (cfg.RescanLightEvery is { } pause)
            {
                await Task.Delay(pause, ct);
            }
        }
    }
}
