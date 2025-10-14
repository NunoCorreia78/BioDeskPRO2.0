using Xunit;
using FluentValidation.TestHelper;
using BioDesk.Domain.DTOs;
using BioDesk.Domain.Validators;

namespace BioDesk.Tests.Validators;

/// <summary>
/// Testes unitários para TerapiaFilaItemValidator
/// Valida todas as regras de negócio de TerapiaFilaItem
/// </summary>
public class TerapiaFilaItemValidatorTests
{
    private readonly TerapiaFilaItemValidator _validator;

    public TerapiaFilaItemValidatorTests()
    {
        _validator = new TerapiaFilaItemValidator();
    }

    #region Testes ProtocoloId

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void ProtocoloId_DeveSerMaiorQueZero(int protocoloId)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.ProtocoloId = protocoloId;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.ProtocoloId)
            .WithErrorMessage("ProtocoloId deve ser maior que 0");
    }

    [Fact]
    public void ProtocoloId_Valido_NaoDeveGerarErro()
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.ProtocoloId = 42;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.ProtocoloId);
    }

    #endregion

    #region Testes Ordem

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-10)]
    public void Ordem_DeveSerMaiorQueZero(int ordem)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.Ordem = ordem;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.Ordem);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(100)]
    public void Ordem_Valida_NaoDeveGerarErro(int ordem)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.Ordem = ordem;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.Ordem);
    }

    #endregion

    #region Testes Nome

    [Fact]
    public void Nome_DeveSerObrigatorio()
    {
        // Arrange
        var item = new TerapiaFilaItem(1, "", 50.0, 1);

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.Nome)
            .WithErrorMessage("Nome do protocolo é obrigatório");
    }

    [Fact]
    public void Nome_DeveTerMinimo3Caracteres()
    {
        // Arrange
        var item = new TerapiaFilaItem(1, "AB", 50.0, 1);

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.Nome)
            .WithErrorMessage("Nome deve ter no mínimo 3 caracteres");
    }

    [Fact]
    public void Nome_Valido_NaoDeveGerarErro()
    {
        // Arrange
        var item = new TerapiaFilaItem(1, "Protocolo Válido", 50.0, 1);

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.Nome);
    }

    #endregion

    #region Testes ValuePercent

    [Theory]
    [InlineData(-1)]
    [InlineData(-50)]
    [InlineData(101)]
    [InlineData(200)]
    public void ValuePercent_ForaDoRange_DeveGerarErro(double value)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.ValuePercent = value;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.ValuePercent);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(50)]
    [InlineData(100)]
    public void ValuePercent_DentroDoRange_NaoDeveGerarErro(double value)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.ValuePercent = value;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.ValuePercent);
    }

    #endregion

    #region Testes ImprovementPercent

    [Theory]
    [InlineData(-101)]
    [InlineData(-200)]
    [InlineData(201)]
    [InlineData(500)]
    public void ImprovementPercent_ForaDoRange_DeveGerarErro(double improvement)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.ImprovementPercent = improvement;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.ImprovementPercent);
    }

    [Theory]
    [InlineData(-100)]
    [InlineData(0)]
    [InlineData(50)]
    [InlineData(95)]
    [InlineData(200)]
    public void ImprovementPercent_DentroDoRange_NaoDeveGerarErro(double improvement)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.ImprovementPercent = improvement;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.ImprovementPercent);
    }

    #endregion

    #region Testes AlvoMelhoria

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(101)]
    [InlineData(150)]
    public void AlvoMelhoria_ForaDoRange_DeveGerarErro(double alvo)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.AlvoMelhoria = alvo;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.AlvoMelhoria);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(80)]
    [InlineData(95)]
    [InlineData(100)]
    public void AlvoMelhoria_DentroDoRange_NaoDeveGerarErro(double alvo)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.AlvoMelhoria = alvo;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.AlvoMelhoria);
    }

    #endregion

    #region Testes Estado

    [Theory]
    [InlineData("Invalid")]
    [InlineData("")]
    [InlineData("Running")]
    [InlineData("Finalizada")]
    public void Estado_Invalido_DeveGerarErro(string estado)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.Estado = estado;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.Estado);
    }

    [Theory]
    [InlineData("Aguardando")]
    [InlineData("Em Execução")]
    [InlineData("Concluída")]
    [InlineData("Auto-Stop")]
    [InlineData("Parada")]
    [InlineData("aguardando")] // Case insensitive
    public void Estado_Valido_NaoDeveGerarErro(string estado)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.Estado = estado;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.Estado);
    }

    #endregion

    #region Testes DuracaoSegundos

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-100)]
    public void DuracaoSegundos_SeDefinida_DeveSerPositiva(int duracao)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.DuracaoSegundos = duracao;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldHaveValidationErrorFor(t => t.DuracaoSegundos);
    }

    [Fact]
    public void DuracaoSegundos_Null_NaoDeveGerarErro()
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.DuracaoSegundos = null;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.DuracaoSegundos);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(60)]
    [InlineData(3600)]
    public void DuracaoSegundos_Positiva_NaoDeveGerarErro(int duracao)
    {
        // Arrange
        var item = CriarFilaItemValido();
        item.DuracaoSegundos = duracao;

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveValidationErrorFor(t => t.DuracaoSegundos);
    }

    #endregion

    #region Testes Integração

    [Fact]
    public void FilaItemValido_NaoDeveGerarErros()
    {
        // Arrange
        var item = CriarFilaItemValido();

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        result.ShouldNotHaveAnyValidationErrors();
    }

    [Fact]
    public void FilaItemInvalido_DeveGerarMultiplosErros()
    {
        // Arrange
        var item = new TerapiaFilaItem(0, "", -10, 0) // Todos inválidos
        {
            AlvoMelhoria = 150, // Inválido
            Estado = "Invalid", // Inválido
            DuracaoSegundos = -1 // Inválido
        };

        // Act
        var result = _validator.TestValidate(item);

        // Assert
        Assert.True(result.Errors.Count >= 5); // Pelo menos 5 erros
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Cria TerapiaFilaItem válido para testes
    /// </summary>
    private TerapiaFilaItem CriarFilaItemValido()
    {
        return new TerapiaFilaItem(42, "Protocolo Teste", 75.5, 1)
        {
            ImprovementPercent = 50.0,
            AlvoMelhoria = 95.0,
            Estado = "Aguardando"
        };
    }

    #endregion
}
