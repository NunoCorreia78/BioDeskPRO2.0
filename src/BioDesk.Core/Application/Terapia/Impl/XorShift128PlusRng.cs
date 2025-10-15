namespace BioDesk.Core.Application.Terapia.Impl;

public sealed class XorShift128PlusRng : IRng
{
    private ulong _s0;
    private ulong _s1;

    public XorShift128PlusRng(ulong seed) => Reseed(seed);

    public void Reseed(ulong seed)
    {
        _s0 = SplitMix64(ref seed);
        _s1 = SplitMix64(ref seed);

        if (_s0 == 0 && _s1 == 0)
        {
            _s1 = 0x9E3779B97F4A7C15UL;
        }
    }

    public ulong NextU64()
    {
        var s1 = _s0;
        var s0 = _s1;
        _s0 = s0;
        s1 ^= s1 << 23;
        _s1 = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5);
        return _s1 + s0;
    }

    public int NextInt(int maxExclusive)
    {
        if (maxExclusive <= 0) return 0;
        return (int)(NextU64() % (uint)maxExclusive);
    }

    private static ulong SplitMix64(ref ulong x)
    {
        x += 0x9E3779B97F4A7C15UL;
        var z = x;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
        return z ^ (z >> 31);
    }
}
