using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Rng;

/// <summary>
/// Implementação do serviço RNG com múltiplas fontes de entropia
/// </summary>
public class RngService : IRngService
{
    private readonly ILogger<RngService> _logger;
    private readonly HttpClient _httpClient;
    private readonly Random _fallbackRandom;

    public EntropySource CurrentSource { get; set; }

    public RngService(ILogger<RngService> logger, IHttpClientFactory httpClientFactory)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpClient = httpClientFactory.CreateClient("RandomOrg");
        _fallbackRandom = new Random();

        // Iniciar com HardwareCrypto (mais confiável que PseudoRandom)
        CurrentSource = EntropySource.HardwareCrypto;
    }

    public async Task<double[]> SelectRandomFrequenciesAsync(ProtocoloTerapeutico protocolo, int count)
    {
        if (protocolo == null)
            throw new ArgumentNullException(nameof(protocolo));

        var frequencias = protocolo.GetFrequencias();
        if (frequencias.Length == 0)
            throw new InvalidOperationException($"Protocolo '{protocolo.Nome}' não contém frequências");

        if (count <= 0 || count > frequencias.Length)
            throw new ArgumentOutOfRangeException(nameof(count),
                $"Count deve estar entre 1 e {frequencias.Length}");

        try
        {
            // Gerar índices únicos aleatórios
            var indices = await GenerateUniqueRandomIntsAsync(0, frequencias.Length - 1, count);

            // Seleccionar frequências pelos índices
            var selectedFreqs = indices.Select(i => frequencias[i]).ToArray();

            _logger.LogInformation(
                "Seleccionadas {Count} frequências de '{Protocolo}' usando {Source}: [{Freqs}]",
                count, protocolo.Nome, CurrentSource, string.Join(", ", selectedFreqs.Select(f => f.ToString("F2"))));

            return selectedFreqs;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao seleccionar frequências de '{Protocolo}'", protocolo.Nome);
            throw;
        }
    }

    public async Task<int> GenerateRandomIntAsync(int minValue, int maxValue)
    {
        if (minValue > maxValue)
            throw new ArgumentException("minValue deve ser <= maxValue");

        try
        {
            return CurrentSource switch
            {
                EntropySource.HardwareCrypto => GenerateRandomIntCrypto(minValue, maxValue),
                EntropySource.AtmosphericNoise => await GenerateRandomIntAtmosphericAsync(minValue, maxValue),
                _ => _fallbackRandom.Next(minValue, maxValue + 1)
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha em {Source}, usando fallback PseudoRandom", CurrentSource);
            return _fallbackRandom.Next(minValue, maxValue + 1);
        }
    }

    public async Task<double> GenerateRandomDoubleAsync()
    {
        try
        {
            return CurrentSource switch
            {
                EntropySource.HardwareCrypto => GenerateRandomDoubleCrypto(),
                EntropySource.AtmosphericNoise => await GenerateRandomDoubleAtmosphericAsync(),
                _ => _fallbackRandom.NextDouble()
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Falha em {Source}, usando fallback", CurrentSource);
            return _fallbackRandom.NextDouble();
        }
    }

    public async Task<int[]> GenerateUniqueRandomIntsAsync(int minValue, int maxValue, int count)
    {
        if (count > (maxValue - minValue + 1))
            throw new ArgumentException("Count excede range disponível");

        var uniqueNumbers = new HashSet<int>();
        int attempts = 0;
        int maxAttempts = count * 10; // Prevenir loop infinito

        while (uniqueNumbers.Count < count && attempts < maxAttempts)
        {
            var num = await GenerateRandomIntAsync(minValue, maxValue);
            uniqueNumbers.Add(num);
            attempts++;
        }

        if (uniqueNumbers.Count < count)
        {
            _logger.LogWarning(
                "Apenas {Generated}/{Requested} números únicos gerados após {Attempts} tentativas",
                uniqueNumbers.Count, count, attempts);
        }

        return uniqueNumbers.ToArray();
    }

    public async Task<bool> TestEntropySourceAsync()
    {
        try
        {
            // Testar gerando um número simples
            _ = await GenerateRandomIntAsync(0, 100);
            _logger.LogInformation("✅ Fonte {Source} operacional", CurrentSource);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Fonte {Source} indisponível", CurrentSource);
            return false;
        }
    }

    #region Hardware Crypto (RNGCryptoServiceProvider)

    private int GenerateRandomIntCrypto(int minValue, int maxValue)
    {
        var range = (uint)(maxValue - minValue + 1);
        var bytes = new byte[4];

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        var randomValue = BitConverter.ToUInt32(bytes, 0);
        return (int)(randomValue % range) + minValue;
    }

    private double GenerateRandomDoubleCrypto()
    {
        var bytes = new byte[4];

        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(bytes);

        var randomValue = BitConverter.ToUInt32(bytes, 0);
        return randomValue / (double)uint.MaxValue;
    }

    #endregion

    #region Atmospheric Noise (Random.org API)

    private async Task<int> GenerateRandomIntAtmosphericAsync(int minValue, int maxValue)
    {
        try
        {
            // Random.org API: https://www.random.org/integers/?num=1&min=X&max=Y&col=1&base=10&format=plain
            var url = $"https://www.random.org/integers/?num=1&min={minValue}&max={maxValue}&col=1&base=10&format=plain&rnd=new";

            var response = await _httpClient.GetStringAsync(url);
            var trimmed = response.Trim();

            if (int.TryParse(trimmed, out int result))
            {
                _logger.LogDebug("Random.org retornou: {Result}", result);
                return result;
            }

            throw new InvalidOperationException($"Resposta inválida de Random.org: {trimmed}");
        }
        catch (HttpRequestException ex)
        {
            _logger.LogWarning(ex, "Random.org indisponível, usando fallback");
            throw;
        }
    }

    private async Task<double> GenerateRandomDoubleAtmosphericAsync()
    {
        try
        {
            // Gerar inteiro entre 0 e 1000000 e dividir
            var randomInt = await GenerateRandomIntAtmosphericAsync(0, 1000000);
            return randomInt / 1000000.0;
        }
        catch
        {
            throw;
        }
    }

    #endregion
}
