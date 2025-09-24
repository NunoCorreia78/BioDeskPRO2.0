using BioDesk.Domain.Entities;
using FuzzySharp;
using FuzzySharp.SimilarityRatio;
using FuzzySharp.SimilarityRatio.Scorer.StrategySensitive;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace BioDesk.Services.FuzzySearch;

/// <summary>
/// Implementação de pesquisa fuzzy utilizando FuzzySharp
/// Algoritmo Levenshtein distance para tolerância a erros de digitação
/// 
/// Características:
/// - Score 0-100 (100 = match exato)
/// - Normalização de texto (remove acentos, case-insensitive)
/// - Múltiplos algoritmos (Token Sort Ratio para maior flexibilidade)
/// - Pesquisa em Nome + Email dos pacientes
/// </summary>
public class FuzzySearchService : IFuzzySearchService
{
    private readonly ILogger<FuzzySearchService> _logger;

    public FuzzySearchService(ILogger<FuzzySearchService> logger)
    {
        _logger = logger;
    }

    public List<Paciente> SearchPacientes(List<Paciente> pacientes, string termo, int limiteScore = 65)
    {
        if (string.IsNullOrWhiteSpace(termo))
        {
            return pacientes.ToList();
        }

        var termoNormalizado = NormalizarTexto(termo);
        var resultados = new List<(Paciente Paciente, int Score)>();

        foreach (var paciente in pacientes)
        {
            var scoreNome = CalcularScoreNormalizado(paciente.Nome, termoNormalizado);
            var scoreEmail = 0;

            // Também pesquisar no email se existir
            if (!string.IsNullOrWhiteSpace(paciente.Email))
            {
                scoreEmail = CalcularScoreNormalizado(paciente.Email, termoNormalizado);
            }

            // Usar o maior score entre nome e email
            var scoreFinal = Math.Max(scoreNome, scoreEmail);

            if (scoreFinal >= limiteScore)
            {
                resultados.Add((paciente, scoreFinal));
            }
        }

        // Ordenar por score (maior primeiro)
        var pacientesOrdenados = resultados
            .OrderByDescending(r => r.Score)
            .ThenBy(r => r.Paciente.Nome)
            .Select(r => r.Paciente)
            .ToList();

        _logger.LogInformation(
            "Fuzzy search '{Termo}' encontrou {Quantidade} resultados (limite score: {Score})", 
            termo, pacientesOrdenados.Count, limiteScore);

        return pacientesOrdenados;
    }

    public int CalcularScore(string texto1, string texto2)
    {
        if (string.IsNullOrWhiteSpace(texto1) || string.IsNullOrWhiteSpace(texto2))
        {
            return 0;
        }

        var texto1Norm = NormalizarTexto(texto1);
        var texto2Norm = NormalizarTexto(texto2);

        return CalcularScoreNormalizado(texto1Norm, texto2Norm);
    }

    public bool SaoSimilares(string texto1, string texto2, int limiteScore = 65)
    {
        return CalcularScore(texto1, texto2) >= limiteScore;
    }

    /// <summary>
    /// Calcula score usando Token Sort Ratio (melhor para nomes com ordem diferente)
    /// Ex: "João Silva" vs "Silva João" = score alto
    /// </summary>
    private int CalcularScoreNormalizado(string texto1, string texto2)
    {
        try
        {
            // Token Sort Ratio é melhor para nomes completos
            var scoreTokenSort = Fuzz.TokenSortRatio(texto1, texto2);
            
            // Ratio simples para matches exatos
            var scoreRatio = Fuzz.Ratio(texto1, texto2);
            
            // Usar o maior score
            return Math.Max(scoreTokenSort, scoreRatio);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Erro ao calcular fuzzy score entre '{Texto1}' e '{Texto2}'", 
                texto1, texto2);
            return 0;
        }
    }

    /// <summary>
    /// Normaliza texto: remove acentos, converte para minúsculas, remove espaços extras
    /// </summary>
    private static string NormalizarTexto(string texto)
    {
        if (string.IsNullOrWhiteSpace(texto))
            return string.Empty;

        // Remover acentos
        var textoNormalizado = texto.Normalize(NormalizationForm.FormD);
        var sb = new StringBuilder();

        foreach (var c in textoNormalizado)
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) != UnicodeCategory.NonSpacingMark)
            {
                sb.Append(c);
            }
        }

        return sb.ToString()
                 .Normalize(NormalizationForm.FormC)
                 .ToLowerInvariant()
                 .Trim();
    }
}