using System;

namespace BioDesk.Core.Domain.Terapia;

public sealed record ItemFilter(string[] IncludeCategories, string[] ExcludeCategories);

public sealed record PatternValidationConfig(
    int NullModelRuns,
    double MinZ,
    double MinScorePercent,
    double MaxQValue,
    int Replicas,
    double SaltJitter);

public sealed record ScanConfig(
    ulong Seed,
    int Iterations,
    ItemFilter Filter,
    PatternValidationConfig Validation);

public sealed record ScanResultItem(
    int ItemId,
    string Code,
    string Name,
    string Category,
    double ScorePercent,
    double ZScore,
    double QValue,
    double ImprovementPercent = 0,
    int Rank = 0);

public sealed record SweepConfig(double StartHz, double StopHz, double StepHz, int DwellMs);

public sealed record LocalEmissionConfig(
    string Waveform,
    double FrequencyHz,
    double Duty,
    double Vpp,
    double CurrentLimitmA,
    double ComplianceV,
    TimeSpan PerItem);

public sealed record RemoteEmissionConfig(
    string Anchor,
    string HashAlgo,
    string Modulation,
    int Cycles,
    TimeSpan PerItem,
    int OnMs,
    int OffMs,
    bool NullDriftCheck,
    TimeSpan? RescanLightEvery);
