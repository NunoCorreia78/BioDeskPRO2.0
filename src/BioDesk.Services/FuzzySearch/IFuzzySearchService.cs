using BioDesk.Domain.Entities;
using System.Collections.Generic;

namespace BioDesk.Services.FuzzySearch;

/// <summary>
/// Serviço para pesquisa fuzzy (tolerante a erros de digitação)
/// Utiliza algoritmo de distância de strings para encontrar matches aproximados
/// </summary>
public interface IFuzzySearchService
{
    /// <summary>
    /// Pesquisa fuzzy em lista de pacientes
    /// </summary>
    /// <param name="pacientes">Lista de pacientes para pesquisar</param>
    /// <param name="termo">Termo de pesquisa</param>
    /// <param name="limiteScore">Score mínimo (0-100, default 65)</param>
    /// <returns>Lista ordenada por relevância (score DESC)</returns>
    List<Paciente> SearchPacientes(List<Paciente> pacientes, string termo, int limiteScore = 65);

    /// <summary>
    /// Calcula score de similaridade entre duas strings
    /// </summary>
    /// <param name="texto1">Primeira string</param>
    /// <param name="texto2">Segunda string</param>
    /// <returns>Score de 0-100 (100 = match exato)</returns>
    int CalcularScore(string texto1, string texto2);

    /// <summary>
    /// Verifica se dois textos são similares
    /// </summary>
    /// <param name="texto1">Primeira string</param>
    /// <param name="texto2">Segunda string</param>
    /// <param name="limiteScore">Score mínimo para considerar similar</param>
    /// <returns>True se similares</returns>
    bool SaoSimilares(string texto1, string texto2, int limiteScore = 65);
}