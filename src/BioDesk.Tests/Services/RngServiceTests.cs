using System;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using BioDesk.Services.Rng;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using Xunit;

namespace BioDesk.Tests.Services;

public class RngServiceTests
{
    private readonly Mock<ILogger<RngService>> _mockLogger;
    private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;

    public RngServiceTests()
    {
        _mockLogger = new Mock<ILogger<RngService>>();
        _mockHttpClientFactory = new Mock<IHttpClientFactory>();
    }

    #region HardwareCrypto Tests

    [Fact]
    public async Task GenerateRandomInt_HardwareCrypto_RetornaNúmeroNoIntervalo()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.HardwareCrypto
        };

        // Act - Gerar 100 números e verificar se todos estão no intervalo
        for (int i = 0; i < 100; i++)
        {
            var result = await rngService.GenerateRandomIntAsync(0, 100);

            // Assert
            Assert.InRange(result, 0, 100);
        }
    }

    [Fact]
    public async Task GenerateRandomDouble_HardwareCrypto_RetornaEntre0e1()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.HardwareCrypto
        };

        // Act - Gerar 50 números e verificar intervalo
        for (int i = 0; i < 50; i++)
        {
            var result = await rngService.GenerateRandomDoubleAsync();

            // Assert
            Assert.InRange(result, 0.0, 1.0);
        }
    }

    [Fact]
    public async Task GenerateUniqueRandomInts_HardwareCrypto_RetornaNumerosUnicos()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.HardwareCrypto
        };

        // Act
        var result = await rngService.GenerateUniqueRandomIntsAsync(0, 50, 10);

        // Assert
        Assert.Equal(10, result.Length);
        Assert.Equal(10, result.Distinct().Count()); // Sem duplicados
        Assert.All(result, num => Assert.InRange(num, 0, 50));
    }

    #endregion

    #region SelectRandomFrequencies Tests

    [Fact]
    public async Task SelectRandomFrequencies_HardwareCrypto_RetornaFrequenciasValidas()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.HardwareCrypto
        };

        var protocolo = new ProtocoloTerapeutico
        {
            Nome = "Teste Protocolo",
            FrequenciasJson = "[2720.0, 2489.0, 2170.0, 1800.0, 1600.0, 1500.0, 1234.5, 987.6]"
        };

        // Act
        var result = await rngService.SelectRandomFrequenciesAsync(protocolo, 5);

        // Assert
        Assert.Equal(5, result.Length);
        Assert.All(result, freq =>
        {
            Assert.Contains(freq, protocolo.GetFrequencias());
        });
    }

    [Fact]
    public async Task SelectRandomFrequencies_ProtocoloSemFrequencias_ThrowsInvalidOperationException()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object);

        var protocolo = new ProtocoloTerapeutico
        {
            Nome = "Protocolo Vazio",
            FrequenciasJson = "[]"
        };

        // Act & Assert
        await Assert.ThrowsAsync<InvalidOperationException>(
            () => rngService.SelectRandomFrequenciesAsync(protocolo, 5));
    }

    [Fact]
    public async Task SelectRandomFrequencies_CountMaiorQueDisponivel_ThrowsArgumentOutOfRangeException()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object);

        var protocolo = new ProtocoloTerapeutico
        {
            Nome = "Protocolo Pequeno",
            FrequenciasJson = "[100.0, 200.0, 300.0]"
        };

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => rngService.SelectRandomFrequenciesAsync(protocolo, 10));
    }

    #endregion

    #region PseudoRandom Fallback Tests

    [Fact]
    public async Task GenerateRandomInt_PseudoRandom_RetornaNúmeroNoIntervalo()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.PseudoRandom
        };

        // Act
        var result = await rngService.GenerateRandomIntAsync(10, 20);

        // Assert
        Assert.InRange(result, 10, 20);
    }

    #endregion

    #region TestEntropySource Tests

    [Fact]
    public async Task TestEntropySource_HardwareCrypto_RetornaTrue()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.HardwareCrypto
        };

        // Act
        var result = await rngService.TestEntropySourceAsync();

        // Assert
        Assert.True(result);
    }

    [Fact]
    public async Task TestEntropySource_PseudoRandom_RetornaTrue()
    {
        // Arrange
        var mockHttpClient = new HttpClient();
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.PseudoRandom
        };

        // Act
        var result = await rngService.TestEntropySourceAsync();

        // Assert
        Assert.True(result);
    }

    #endregion

    #region AtmosphericNoise Tests (Mock HTTP)

    [Fact]
    public async Task GenerateRandomInt_AtmosphericNoise_ComRespostaSucesso_RetornaNúmero()
    {
        // Arrange
        var mockHttpMessageHandler = new Mock<HttpMessageHandler>();
        mockHttpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ReturnsAsync(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                Content = new StringContent("42\n") // Random.org retorna número + newline
            });

        var mockHttpClient = new HttpClient(mockHttpMessageHandler.Object);
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.AtmosphericNoise
        };

        // Act
        var result = await rngService.GenerateRandomIntAsync(0, 100);

        // Assert
        Assert.Equal(42, result);
    }

    [Fact]
    public async Task GenerateRandomInt_AtmosphericNoise_ComFalha_UsaFallback()
    {
        // Arrange
        var mockHttpMessageHandler = new Mock<HttpMessageHandler>();
        mockHttpMessageHandler
            .Protected()
            .Setup<Task<HttpResponseMessage>>(
                "SendAsync",
                ItExpr.IsAny<HttpRequestMessage>(),
                ItExpr.IsAny<CancellationToken>())
            .ThrowsAsync(new HttpRequestException("API offline"));

        var mockHttpClient = new HttpClient(mockHttpMessageHandler.Object);
        _mockHttpClientFactory.Setup(x => x.CreateClient("RandomOrg")).Returns(mockHttpClient);

        var rngService = new RngService(_mockLogger.Object, _mockHttpClientFactory.Object)
        {
            CurrentSource = EntropySource.AtmosphericNoise
        };

        // Act
        var result = await rngService.GenerateRandomIntAsync(0, 100);

        // Assert (fallback para PseudoRandom deve funcionar)
        Assert.InRange(result, 0, 100);
    }

    #endregion
}
