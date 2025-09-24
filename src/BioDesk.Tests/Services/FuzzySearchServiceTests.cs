using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using BioDesk.Domain.Entities;
using BioDesk.Services.FuzzySearch;

namespace BioDesk.Tests.Services;

/// <summary>
/// Testes para FuzzySearchService
/// Verifica algoritmos fuzzy (Levenshtein distance)
/// </summary>
public class FuzzySearchServiceTests
{
    private readonly FuzzySearchService _service;

    public FuzzySearchServiceTests()
    {
        var logger = NullLogger<FuzzySearchService>.Instance;
        _service = new FuzzySearchService(logger);
    }

    [Fact]
    public void CalcularScore_MatchExato_DeveRetornar100()
    {
        // Arrange
        var nome1 = "João Silva";
        var nome2 = "João Silva";

        // Act
        var score = _service.CalcularScore(nome1, nome2);

        // Assert
        Assert.Equal(100, score);
    }

    [Fact]
    public void CalcularScore_NomesSimilares_DeveRetornarScoreAlto()
    {
        // Arrange
        var nome1 = "João Silva";
        var nome2 = "Joao Silva"; // Sem acento

        // Act
        var score = _service.CalcularScore(nome1, nome2);

        // Assert
        Assert.True(score >= 80, $"Score esperado >= 80, obtido: {score}");
    }

    [Fact]
    public void CalcularScore_ErroDeDigitacao_DeveRetornarScoreRazoavel()
    {
        // Arrange
        var nome1 = "João Silva";
        var nome2 = "Joao Silv"; // Erro de digitação

        // Act
        var score = _service.CalcularScore(nome1, nome2);

        // Assert
        Assert.True(score >= 70, $"Score esperado >= 70 para erro de digitação, obtido: {score}");
    }

    [Fact]
    public void SearchPacientes_EncontraNomeComErroDigitacao()
    {
        // Arrange
        var pacientes = new List<Paciente>
        {
            new() { Id = 1, Nome = "João Silva Santos", Email = "joao@teste.com" },
            new() { Id = 2, Nome = "Maria Oliveira", Email = "maria@teste.com" },
            new() { Id = 3, Nome = "Pedro Souza", Email = "pedro@teste.com" }
        };

        // Act - buscar com erro de digitação (limite mais baixo)
        var resultados = _service.SearchPacientes(pacientes, "Joao Silv", limiteScore: 50);

        // Assert
        Assert.NotEmpty(resultados);
        Assert.Contains(resultados, p => p.Nome.Contains("João Silva"));
    }

    [Fact]
    public void SearchPacientes_PesquisarPorEmail_DeveEncontrar()
    {
        // Arrange
        var pacientes = new List<Paciente>
        {
            new() { Id = 1, Nome = "João Silva", Email = "joao.silva@teste.com" },
            new() { Id = 2, Nome = "Maria Oliveira", Email = "maria@teste.com" }
        };

        // Act - pesquisar por email parcial
        var resultados = _service.SearchPacientes(pacientes, "joao.silva", limiteScore: 65);

        // Assert
        Assert.NotEmpty(resultados);
        Assert.Equal("João Silva", resultados.First().Nome);
    }

    [Fact]
    public void SearchPacientes_OrdenaPorScore_MelhorMatchPrimeiro()
    {
        // Arrange
        var pacientes = new List<Paciente>
        {
            new() { Id = 1, Nome = "João Pedro", Email = "joao.pedro@teste.com" },
            new() { Id = 2, Nome = "João Silva", Email = "joao.silva@teste.com" },
            new() { Id = 3, Nome = "João Santos", Email = "joao.santos@teste.com" }
        };

        // Act - termo que deve dar match exato com João Silva
        var resultados = _service.SearchPacientes(pacientes, "João Silva", limiteScore: 50);

        // Assert
        Assert.NotEmpty(resultados);
        // O match exato deve vir primeiro
        Assert.Equal("João Silva", resultados.First().Nome);
    }

    [Theory]
    [InlineData("João", "Joao", 65)]
    [InlineData("Silva", "Silv", 65)]
    [InlineData("Maria", "Mraia", 50)] // Troca de letras
    public void SaoSimilares_DeveDeterminarCorretamente(string texto1, string texto2, int limiteEsperado)
    {
        // Act
        var saoSimilares = _service.SaoSimilares(texto1, texto2, limiteEsperado);

        // Assert
        Assert.True(saoSimilares);
    }
}