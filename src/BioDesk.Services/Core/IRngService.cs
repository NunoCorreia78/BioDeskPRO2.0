using System;

namespace BioDesk.Services.Core;

/// <summary>
/// Tipos de geradores de números aleatórios disponíveis
/// </summary>
public enum TipoRng
{
    /// <summary>
    /// Gerador pseudo-aleatório do sistema (.NET Random)
    /// Rápido mas previsível - uso em desenvolvimento
    /// </summary>
    SystemRandom = 1,

    /// <summary>
    /// Gerador criptográfico (RandomNumberGenerator)
    /// Alta qualidade, não-previsível - recomendado para produção
    /// </summary>
    Cryptographic = 2,

    /// <summary>
    /// Gerador baseado em hardware TiePie (quantum/térmico)
    /// Máxima qualidade, não-local - uso em análises críticas
    /// Requer hardware TiePie conectado
    /// </summary>
    HardwareTiePie = 3
}

/// <summary>
/// Interface para serviços de geração de números aleatórios
/// Inspirado no sistema Inergetix CoRe 5.0 para análise de ressonância
/// </summary>
public interface IRngService
{
    /// <summary>
    /// Gera um número inteiro aleatório entre min (inclusivo) e max (exclusivo)
    /// </summary>
    int Next(int minValue, int maxValue);

    /// <summary>
    /// Gera um número double aleatório entre 0.0 (inclusivo) e 1.0 (exclusivo)
    /// </summary>
    double NextDouble();

    /// <summary>
    /// Preenche array de bytes com valores aleatórios
    /// </summary>
    void NextBytes(byte[] buffer);

    /// <summary>
    /// Gera número aleatório com seed específico (para reprodutibilidade)
    /// </summary>
    int NextWithSeed(int seed, int minValue, int maxValue);

    /// <summary>
    /// Tipo de RNG em uso
    /// </summary>
    TipoRng Tipo { get; }

    /// <summary>
    /// Indica se o gerador está disponível e funcional
    /// </summary>
    bool IsAvailable { get; }
}
