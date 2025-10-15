namespace BioDesk.Core.Application.Terapia;

public interface IRng
{
    int NextInt(int maxExclusive);
    ulong NextU64();
    void Reseed(ulong seed);
}
