using System;
using System.Security.Cryptography;
using System.Text;

namespace BioDesk.Core.Application.Terapia.Impl;

public sealed class SeedProvider : ISeedProvider
{
    public ulong BuildSeed(SeedInputs inputs)
    {
        var payload = Encoding.UTF8.GetBytes($"{inputs.Anchor}::{inputs.SessionSalt}");
        var hash = SHA256.HashData(payload);
        return BitConverter.ToUInt64(hash, 0);
    }
}
