using System.Threading.Tasks;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Rng;

/// <summary>
/// Serviço de geração de números aleatórios verdadeiros (True RNG)
/// Inspirado no sistema Inergetix-CoRe v5.0
/// </summary>
public interface IRngService
{
    /// <summary>
    /// Fonte de entropia actual
    /// </summary>
    EntropySource CurrentSource { get; set; }

    /// <summary>
    /// Selecciona N frequências aleatórias de um protocolo
    /// </summary>
    /// <param name="protocolo">Protocolo com frequências disponíveis</param>
    /// <param name="count">Número de frequências a seleccionar (ex: 5)</param>
    /// <returns>Array de frequências seleccionadas aleatoriamente</returns>
    Task<double[]> SelectRandomFrequenciesAsync(ProtocoloTerapeutico protocolo, int count);

    /// <summary>
    /// Gera um inteiro aleatório no intervalo [minValue, maxValue]
    /// </summary>
    Task<int> GenerateRandomIntAsync(int minValue, int maxValue);

    /// <summary>
    /// Gera um double aleatório no intervalo [0.0, 1.0)
    /// </summary>
    Task<double> GenerateRandomDoubleAsync();

    /// <summary>
    /// Gera múltiplos inteiros aleatórios únicos (sem repetição)
    /// </summary>
    Task<int[]> GenerateUniqueRandomIntsAsync(int minValue, int maxValue, int count);

    /// <summary>
    /// Testa disponibilidade da fonte de entropia actual
    /// </summary>
    Task<bool> TestEntropySourceAsync();
}
