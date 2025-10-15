using System;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Core;

/// <summary>
/// Implementação de RNG usando gerador pseudo-aleatório do sistema
/// Rápido mas previsível - adequado para desenvolvimento e testes
/// </summary>
public class SystemRngService : IRngService
{
    private readonly Random _random;
    private readonly ILogger<SystemRngService> _logger;

    public TipoRng Tipo => TipoRng.SystemRandom;
    public bool IsAvailable => true;

    public SystemRngService(ILogger<SystemRngService> logger)
    {
        _logger = logger;
        _random = new Random();
        _logger.LogInformation("✅ SystemRngService inicializado");
    }

    public int Next(int minValue, int maxValue)
    {
        return _random.Next(minValue, maxValue);
    }

    public double NextDouble()
    {
        return _random.NextDouble();
    }

    public void NextBytes(byte[] buffer)
    {
        _random.NextBytes(buffer);
    }

    public int NextWithSeed(int seed, int minValue, int maxValue)
    {
        var seededRandom = new Random(seed);
        return seededRandom.Next(minValue, maxValue);
    }
}

/// <summary>
/// Implementação de RNG usando gerador criptográfico
/// Alta qualidade e não-previsível - recomendado para produção
/// </summary>
public class CryptographicRngService : IRngService
{
    private readonly ILogger<CryptographicRngService> _logger;

    public TipoRng Tipo => TipoRng.Cryptographic;
    public bool IsAvailable => true;

    public CryptographicRngService(ILogger<CryptographicRngService> logger)
    {
        _logger = logger;
        _logger.LogInformation("✅ CryptographicRngService inicializado");
    }

    public int Next(int minValue, int maxValue)
    {
        if (minValue >= maxValue)
            throw new ArgumentException("minValue deve ser menor que maxValue");

        uint range = (uint)(maxValue - minValue);
        uint result = GetRandomUInt32() % range;
        return (int)(minValue + result);
    }

    public double NextDouble()
    {
        // Gera double entre 0.0 e 1.0 usando bytes criptográficos
        byte[] bytes = new byte[8];
        RandomNumberGenerator.Fill(bytes);
        ulong value = BitConverter.ToUInt64(bytes, 0);
        return (double)value / ulong.MaxValue;
    }

    public void NextBytes(byte[] buffer)
    {
        RandomNumberGenerator.Fill(buffer);
    }

    public int NextWithSeed(int seed, int minValue, int maxValue)
    {
        // Geradores criptográficos não suportam seed fixo (por design)
        // Usamos seed para criar variação determinística limitada
        _logger.LogWarning("CryptographicRng não suporta seed verdadeiro - usando variação XOR");

        int cryptoValue = Next(minValue, maxValue);
        return (cryptoValue ^ seed) % (maxValue - minValue) + minValue;
    }

    private uint GetRandomUInt32()
    {
        byte[] bytes = new byte[4];
        RandomNumberGenerator.Fill(bytes);
        return BitConverter.ToUInt32(bytes, 0);
    }
}

/// <summary>
/// Implementação de RNG usando hardware TiePie (quantum/térmico)
/// Máxima qualidade - uso em análises críticas
/// NOTA: Requer hardware TiePie conectado
/// </summary>
public class HardwareTiePieRngService : IRngService
{
    private readonly ILogger<HardwareTiePieRngService> _logger;
    private readonly Random _fallbackRandom;
    private bool _hardwareAvailable;

    public TipoRng Tipo => TipoRng.HardwareTiePie;
    public bool IsAvailable => _hardwareAvailable;

    public HardwareTiePieRngService(ILogger<HardwareTiePieRngService> logger)
    {
        _logger = logger;
        _fallbackRandom = new Random();

        // Verificar disponibilidade de hardware
        _hardwareAvailable = CheckHardwareAvailability();

        if (_hardwareAvailable)
        {
            _logger.LogInformation("✅ HardwareTiePieRngService inicializado (hardware detectado)");
        }
        else
        {
            _logger.LogWarning("⚠️ Hardware TiePie não detectado - usando fallback SystemRandom");
        }
    }

    public int Next(int minValue, int maxValue)
    {
        if (!_hardwareAvailable)
        {
            return _fallbackRandom.Next(minValue, maxValue);
        }

        // TODO: Implementar leitura real do hardware TiePie
        // Por agora, simula com noise térmico via Crypto + variação
        byte[] buffer = new byte[4];
        RandomNumberGenerator.Fill(buffer);
        uint value = BitConverter.ToUInt32(buffer, 0);

        uint range = (uint)(maxValue - minValue);
        return (int)(minValue + (value % range));
    }

    public double NextDouble()
    {
        if (!_hardwareAvailable)
        {
            return _fallbackRandom.NextDouble();
        }

        // TODO: Implementar leitura real do hardware TiePie
        byte[] bytes = new byte[8];
        RandomNumberGenerator.Fill(bytes);
        ulong value = BitConverter.ToUInt64(bytes, 0);
        return (double)value / ulong.MaxValue;
    }

    public void NextBytes(byte[] buffer)
    {
        if (!_hardwareAvailable)
        {
            _fallbackRandom.NextBytes(buffer);
            return;
        }

        // TODO: Implementar leitura real do hardware TiePie
        RandomNumberGenerator.Fill(buffer);
    }

    public int NextWithSeed(int seed, int minValue, int maxValue)
    {
        // Hardware RNG não suporta seed (é físico!)
        _logger.LogWarning("HardwareTiePie RNG não suporta seed - ignorando");
        return Next(minValue, maxValue);
    }

    private bool CheckHardwareAvailability()
    {
        try
        {
            // TODO: Implementar verificação real de hardware TiePie
            // Por agora, retorna false (hardware não disponível)
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao verificar hardware TiePie");
            return false;
        }
    }
}

/// <summary>
/// Factory para criar instância apropriada de IRngService
/// </summary>
public class RngServiceFactory
{
    private readonly ILogger<RngServiceFactory> _logger;
    private readonly ILogger<SystemRngService> _systemLogger;
    private readonly ILogger<CryptographicRngService> _cryptoLogger;
    private readonly ILogger<HardwareTiePieRngService> _hardwareLogger;

    public RngServiceFactory(
        ILogger<RngServiceFactory> logger,
        ILogger<SystemRngService> systemLogger,
        ILogger<CryptographicRngService> cryptoLogger,
        ILogger<HardwareTiePieRngService> hardwareLogger)
    {
        _logger = logger;
        _systemLogger = systemLogger;
        _cryptoLogger = cryptoLogger;
        _hardwareLogger = hardwareLogger;
    }

    public IRngService Create(TipoRng tipo)
    {
        _logger.LogInformation($"Criando RNG do tipo: {tipo}");

        return tipo switch
        {
            TipoRng.SystemRandom => new SystemRngService(_systemLogger),
            TipoRng.Cryptographic => new CryptographicRngService(_cryptoLogger),
            TipoRng.HardwareTiePie => new HardwareTiePieRngService(_hardwareLogger),
            _ => throw new ArgumentException($"Tipo de RNG inválido: {tipo}")
        };
    }

    /// <summary>
    /// Cria melhor RNG disponível no sistema
    /// Ordem de preferência: Hardware > Cryptographic > System
    /// </summary>
    public IRngService CreateBest()
    {
        // Tentar hardware primeiro
        var hardware = new HardwareTiePieRngService(_hardwareLogger);
        if (hardware.IsAvailable)
        {
            _logger.LogInformation("✅ Usando HardwareTiePie RNG (melhor qualidade)");
            return hardware;
        }

        // Fallback para cryptographic (sempre disponível)
        _logger.LogInformation("✅ Usando Cryptographic RNG (alta qualidade)");
        return new CryptographicRngService(_cryptoLogger);
    }
}
