using Xunit;
using FluentValidation.TestHelper;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Validators;
using System;

namespace BioDesk.Tests.Validators;

/// <summary>
/// Testes unitários para ProtocoloTerapeuticoValidator
/// Valida todas as regras de negócio de ProtocoloTerapeutico
/// </summary>
public class ProtocoloTerapeuticoValidatorTests
{
    private readonly ProtocoloTerapeuticoValidator _validator;

    public ProtocoloTerapeuticoValidatorTests()
    {
        _validator = new ProtocoloTerapeuticoValidator();
    }

    #region Testes Nome

    [Fact]
    public void Nome_DeveSerObrigatorio()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Nome = "";

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.Nome)
            .WithErrorMessage("Nome do protocolo é obrigatório");
    }

    [Fact]
    public void Nome_DeveTerMinimo3Caracteres()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Nome = "AB";

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.Nome)
            .WithErrorMessage("Nome deve ter no mínimo 3 caracteres");
    }

    [Fact]
    public void Nome_DeveTerMaximo200Caracteres()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Nome = new string('A', 201);

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.Nome);
    }

    [Fact]
    public void Nome_Valido_NaoDeveGerarErro()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Nome = "Protocolo Válido";

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.Nome);
    }

    #endregion

    #region Testes FrequenciasJson

    [Fact]
    public void FrequenciasJson_DeveSerObrigatorio()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.FrequenciasJson = "";

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.FrequenciasJson);
    }

    [Fact]
    public void FrequenciasJson_DeveSerArrayJSONValido()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.FrequenciasJson = "invalid json";

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.FrequenciasJson)
            .WithErrorMessage("FrequenciasJson deve ser um array JSON válido de números");
    }

    [Fact]
    public void FrequenciasJson_DeveTerPeloMenos1Frequencia()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.FrequenciasJson = "[]";

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.FrequenciasJson)
            .WithErrorMessage("Deve haver pelo menos 1 frequência definida");
    }

    [Fact]
    public void FrequenciasJson_Valido_NaoDeveGerarErro()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.FrequenciasJson = "[528, 396, 285]";

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.FrequenciasJson);
    }

    #endregion

    #region Testes AmplitudeV

    [Theory]
    [InlineData(0.0)]
    [InlineData(0.05)]
    [InlineData(10.1)]
    [InlineData(20.0)]
    public void AmplitudeV_ForaDoRange_DeveGerarErro(double amplitude)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.AmplitudeV = amplitude;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.AmplitudeV);
    }

    [Theory]
    [InlineData(0.1)]
    [InlineData(5.0)]
    [InlineData(10.0)]
    public void AmplitudeV_DentroDoRange_NaoDeveGerarErro(double amplitude)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.AmplitudeV = amplitude;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.AmplitudeV);
    }

    #endregion

    #region Testes LimiteCorrenteMa

    [Theory]
    [InlineData(0.0)]
    [InlineData(50.1)]
    [InlineData(100.0)]
    public void LimiteCorrenteMa_ForaDoRange_DeveGerarErro(double corrente)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.LimiteCorrenteMa = corrente;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.LimiteCorrenteMa);
    }

    [Theory]
    [InlineData(0.1)]
    [InlineData(10.0)]
    [InlineData(50.0)]
    public void LimiteCorrenteMa_DentroDoRange_NaoDeveGerarErro(double corrente)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.LimiteCorrenteMa = corrente;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.LimiteCorrenteMa);
    }

    #endregion

    #region Testes DuracaoMinPorFrequencia

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(61)]
    [InlineData(120)]
    public void DuracaoMinPorFrequencia_ForaDoRange_DeveGerarErro(int duracao)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.DuracaoMinPorFrequencia = duracao;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.DuracaoMinPorFrequencia);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(60)]
    public void DuracaoMinPorFrequencia_DentroDoRange_NaoDeveGerarErro(int duracao)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.DuracaoMinPorFrequencia = duracao;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.DuracaoMinPorFrequencia);
    }

    #endregion

    #region Testes FormaOnda

    [Theory]
    [InlineData("Invalid")]
    [InlineData("")]
    [InlineData("Cosine")]
    public void FormaOnda_Invalida_DeveGerarErro(string formaOnda)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.FormaOnda = formaOnda;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.FormaOnda);
    }

    [Theory]
    [InlineData("Sine")]
    [InlineData("Square")]
    [InlineData("Triangle")]
    [InlineData("Saw")]
    [InlineData("sine")] // Case insensitive
    public void FormaOnda_Valida_NaoDeveGerarErro(string formaOnda)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.FormaOnda = formaOnda;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.FormaOnda);
    }

    #endregion

    #region Testes Modulacao

    [Theory]
    [InlineData("Invalid")]
    [InlineData("")]
    [InlineData("PM")]
    public void Modulacao_Invalida_DeveGerarErro(string modulacao)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Modulacao = modulacao;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.Modulacao);
    }

    [Theory]
    [InlineData("None")]
    [InlineData("AM")]
    [InlineData("FM")]
    [InlineData("Burst")]
    [InlineData("none")] // Case insensitive
    public void Modulacao_Valida_NaoDeveGerarErro(string modulacao)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Modulacao = modulacao;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.Modulacao);
    }

    #endregion

    #region Testes Canal

    [Theory]
    [InlineData("Invalid")]
    [InlineData("")]
    [InlineData("3")]
    [InlineData("All")]
    public void Canal_Invalido_DeveGerarErro(string canal)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Canal = canal;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldHaveValidationErrorFor(p => p.Canal);
    }

    [Theory]
    [InlineData("1")]
    [InlineData("2")]
    [InlineData("Both")]
    [InlineData("both")] // Case insensitive
    public void Canal_Valido_NaoDeveGerarErro(string canal)
    {
        // Arrange
        var protocolo = CriarProtocoloValido();
        protocolo.Canal = canal;

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveValidationErrorFor(p => p.Canal);
    }

    #endregion

    #region Testes Integração

    [Fact]
    public void ProtocoloValido_NaoDeveGerarErros()
    {
        // Arrange
        var protocolo = CriarProtocoloValido();

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void ProtocoloInvalido_DeveGerarMultiplosErros()
    {
        // Arrange
        var protocolo = new ProtocoloTerapeutico
        {
            Nome = "", // Inválido
            ExternalId = "",
            Categoria = "",
            FrequenciasJson = "invalid", // Inválido
            AmplitudeV = 20.0, // Inválido
            FormaOnda = "Invalid" // Inválido
        };

        // Act
        var result = _validator.TestValidate(protocolo);

        // Assert
        Assert.True(result.Errors.Count >= 4); // Pelo menos 4 erros
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Cria protocolo válido para testes
    /// </summary>
    private ProtocoloTerapeutico CriarProtocoloValido()
    {
        return new ProtocoloTerapeutico
        {
            Id = 1,
            ExternalId = Guid.NewGuid().ToString(),
            Nome = "Protocolo Teste",
            Categoria = "Teste",
            FrequenciasJson = "[528, 396, 285]",
            AmplitudeV = 5.0,
            LimiteCorrenteMa = 10.0,
            FormaOnda = "Sine",
            Modulacao = "None",
            DuracaoMinPorFrequencia = 5,
            Canal = "1",
            Ativo = true
        };
    }

    #endregion
}
