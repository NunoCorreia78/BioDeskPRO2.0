using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using BioDesk.Services.Rng;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Terapias;

/// <summary>
/// Serviço para Value % scanning - algoritmo CoRe 5.0
/// Gera valores percentuais (0-100%) para cada protocolo usando RNG
/// Permite identificar protocolos com maior "ressonância" para o paciente
/// </summary>
public interface IValueScanningService
{
    /// <summary>
    /// Escaneia um protocolo e calcula seu Value %
    /// </summary>
    /// <param name="protocolo">Protocolo a escanear</param>
    /// <returns>Value % (0-100)</returns>
    Task<double> ScanearProtocoloAsync(ProtocoloTerapeutico protocolo);

    /// <summary>
    /// Escaneia múltiplos protocolos em batch
    /// </summary>
    /// <param name="protocolos">Lista de protocolos</param>
    /// <returns>Dicionário com ProtocoloId → Value %</returns>
    Task<Dictionary<int, double>> ScanearProtocolosAsync(IEnumerable<ProtocoloTerapeutico> protocolos);

    /// <summary>
    /// Escaneia e retorna protocolos ordenados por Value % descendente
    /// </summary>
    /// <param name="protocolos">Lista de protocolos</param>
    /// <param name="topN">Número de protocolos a retornar (0 = todos)</param>
    /// <returns>Lista de tuplas (Protocolo, Value %) ordenada</returns>
    Task<List<(ProtocoloTerapeutico Protocolo, double ValuePercent)>> ScanearEOrdenarAsync(
        IEnumerable<ProtocoloTerapeutico> protocolos,
        int topN = 0);
}

public class ValueScanningService : IValueScanningService
{
    private readonly IRngService _rngService;
    private readonly ILogger<ValueScanningService> _logger;

    // Constantes do algoritmo CoRe 5.0
    private const int NUM_SAMPLES = 10; // Número de amostras RNG por protocolo
    private const double VALUE_MIN = 0.0;
    private const double VALUE_MAX = 100.0;

    public ValueScanningService(IRngService rngService, ILogger<ValueScanningService> logger)
    {
        _rngService = rngService ?? throw new ArgumentNullException(nameof(rngService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task<double> ScanearProtocoloAsync(ProtocoloTerapeutico protocolo)
    {
        if (protocolo == null)
            throw new ArgumentNullException(nameof(protocolo));

        try
        {
            // Gerar NUM_SAMPLES valores RNG entre 0.0 e 1.0
            var samples = new List<double>();
            for (int i = 0; i < NUM_SAMPLES; i++)
            {
                var randomValue = await _rngService.GenerateRandomDoubleAsync();
                samples.Add(randomValue);
            }

            // Calcular média dos samples
            var average = samples.Average();

            // Normalizar para 0-100%
            var valuePercent = average * 100.0;

            // Arredondar para 2 casas decimais
            valuePercent = Math.Round(valuePercent, 2);

            // Clampar para range válido (garantia extra)
            valuePercent = Math.Max(VALUE_MIN, Math.Min(VALUE_MAX, valuePercent));

            _logger.LogDebug(
                "Protocolo '{Nome}' escaneado: {Samples} samples → média {Avg:F4} → Value% {Value:F2}%",
                protocolo.Nome, NUM_SAMPLES, average, valuePercent);

            return valuePercent;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao escanear protocolo '{Nome}'", protocolo.Nome);
            throw;
        }
    }

    public async Task<Dictionary<int, double>> ScanearProtocolosAsync(IEnumerable<ProtocoloTerapeutico> protocolos)
    {
        if (protocolos == null)
            throw new ArgumentNullException(nameof(protocolos));

        var protocolosList = protocolos.ToList();
        if (protocolosList.Count == 0)
        {
            _logger.LogWarning("Nenhum protocolo fornecido para scanning");
            return new Dictionary<int, double>();
        }

        _logger.LogInformation("🔍 Iniciando Value % scanning de {Count} protocolos usando {Source}...",
            protocolosList.Count, _rngService.CurrentSource);

        var resultados = new Dictionary<int, double>();
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        foreach (var protocolo in protocolosList)
        {
            try
            {
                var valuePercent = await ScanearProtocoloAsync(protocolo);
                resultados[protocolo.Id] = valuePercent;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Falha ao escanear protocolo ID {Id}", protocolo.Id);
                // Continuar com próximo protocolo (não falhar batch inteiro)
            }
        }

        stopwatch.Stop();
        _logger.LogInformation(
            "✅ Scanning completo: {Sucesso}/{Total} protocolos em {Elapsed:F2}s ({Taxa:F1} protocolos/s)",
            resultados.Count, protocolosList.Count, stopwatch.Elapsed.TotalSeconds,
            resultados.Count / stopwatch.Elapsed.TotalSeconds);

        return resultados;
    }

    public async Task<List<(ProtocoloTerapeutico Protocolo, double ValuePercent)>> ScanearEOrdenarAsync(
        IEnumerable<ProtocoloTerapeutico> protocolos,
        int topN = 0)
    {
        if (protocolos == null)
            throw new ArgumentNullException(nameof(protocolos));

        var protocolosList = protocolos.ToList();
        var valuesDict = await ScanearProtocolosAsync(protocolosList);

        // Criar lista de tuplas (Protocolo, Value %)
        var results = protocolosList
            .Where(p => valuesDict.ContainsKey(p.Id)) // Apenas protocolos com sucesso
            .Select(p => (Protocolo: p, ValuePercent: valuesDict[p.Id]))
            .OrderByDescending(tuple => tuple.ValuePercent) // Ordenar por Value % desc
            .ToList();

        // Se topN especificado, retornar apenas top N
        if (topN > 0 && results.Count > topN)
        {
            results = results.Take(topN).ToList();
            _logger.LogInformation("📊 Retornando top {TopN} protocolos (Value% mais alto)", topN);
        }

        // Log dos top 5 para debug
        var top5 = results.Take(5);
        _logger.LogInformation("🏆 Top 5 Value %:");
        foreach (var (protocolo, valuePercent) in top5)
        {
            _logger.LogInformation("   {Value:F2}% - {Nome}", valuePercent, protocolo.Nome);
        }

        return results;
    }
}
