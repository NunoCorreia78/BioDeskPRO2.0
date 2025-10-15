namespace BioDesk.Core.Application.Terapia;

public sealed record SeedInputs(string Anchor, string SessionSalt);

public interface ISeedProvider
{
    ulong BuildSeed(SeedInputs inputs);
}
