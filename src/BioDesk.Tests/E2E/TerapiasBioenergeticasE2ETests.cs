using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using BioDesk.Data;
using BioDesk.Data.Repositories;
using BioDesk.Domain.DTOs;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Validators;
using BioDesk.Services.Hardware;
using BioDesk.Services.Medicao;
using BioDesk.Services.Rng;
using BioDesk.Services.Terapias;
using BioDesk.ViewModels.UserControls;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Xunit.Abstractions;

namespace BioDesk.Tests.E2E;

/// <summary>
/// Logger simples para xUnit ITestOutputHelper
/// </summary>
internal class XUnitLogger<T> : ILogger<T>
{
    private readonly ITestOutputHelper _output;
    public XUnitLogger(ITestOutputHelper output) => _output = output;
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        _output.WriteLine($"[{logLevel}] {formatter(state, exception)}");
        if (exception != null)
            _output.WriteLine($"Exception: {exception}");
    }
}

/// <summary>
/// Testes End-to-End para Terapias Bioenergéticas
/// Valida fluxo: Scan → Queue → Apply → Monitor → Auto-Stop
/// NOTA: Usa serviços DUMMY para simular hardware (amanhã testaremos com hardware real)
/// </summary>
public sealed class TerapiasBioenergeticasE2ETests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private bool _disposed = false;

    public TerapiasBioenergeticasE2ETests(ITestOutputHelper output)
    {
        _output = output;
        _output.WriteLine("✅ Setup E2E - Testes prontos");
    }

    #region HELPER: Criar ViewModel com Mocks

    private (TerapiasBioenergeticasUserControlViewModel vm, BioDeskDbContext context) CreateViewModelWithMocks()
    {
        // === BD in-memory ===
        var options = new DbContextOptionsBuilder<BioDeskDbContext>()
            .UseInMemoryDatabase(databaseName: $"TestDb_{Guid.NewGuid()}")
            .Options;

        var context = new BioDeskDbContext(options);
        var protocoloRepository = new ProtocoloRepository(context);

        // === Popular BD com protocolos de teste ===
        SeedTestProtocolos(context);

        // === Mock HttpClientFactory para RngService ===
        var httpClientFactory = new Mock<IHttpClientFactory>();
        var httpClient = new HttpClient();
        httpClientFactory.Setup(f => f.CreateClient(It.IsAny<string>())).Returns(httpClient);

        // === Criar serviços DUMMY ===
        var rngService = new RngService(new XUnitLogger<RngService>(_output), httpClientFactory.Object);
        var tiePieService = new DummyTiePieHardwareService(new XUnitLogger<DummyTiePieHardwareService>(_output));
        var valueScanningService = new ValueScanningService(rngService, new XUnitLogger<ValueScanningService>(_output));
        var medicaoService = new DummyMedicaoService(new XUnitLogger<DummyMedicaoService>(_output));

        // === FluentValidation Validators ===
        var protocoloValidator = new ProtocoloTerapeuticoValidator();
        var filaItemValidator = new TerapiaFilaItemValidator();

        // === Criar ViewModel ===
        var viewModel = new TerapiasBioenergeticasUserControlViewModel(
            protocoloRepository,
            rngService,
            tiePieService,
            valueScanningService,
            medicaoService,
            new XUnitLogger<TerapiasBioenergeticasUserControlViewModel>(_output),
            protocoloValidator,
            filaItemValidator
        );

        return (viewModel, context);
    }

    private void SeedTestProtocolos(BioDeskDbContext context)
    {
        var protocolos = new[]
        {
            new ProtocoloTerapeutico
            {
                ExternalId = Guid.NewGuid().ToString(),
                Nome = "Protocolo A - Alta Eficácia",
                Categoria = "Test",
                FrequenciasJson = "[100,200,300,400,500]",
                AmplitudeV = 5.0,
                FormaOnda = "Sine",
                DuracaoMinPorFrequencia = 1
            },
            new ProtocoloTerapeutico
            {
                ExternalId = Guid.NewGuid().ToString(),
                Nome = "Protocolo B - Média Eficácia",
                Categoria = "Test",
                FrequenciasJson = "[150,250,350]",
                AmplitudeV = 5.0,
                FormaOnda = "Sine",
                DuracaoMinPorFrequencia = 1
            },
            new ProtocoloTerapeutico
            {
                ExternalId = Guid.NewGuid().ToString(),
                Nome = "Protocolo C - Baixa Eficácia",
                Categoria = "Test",
                FrequenciasJson = "[50,100]",
                AmplitudeV = 5.0,
                FormaOnda = "Sine",
                DuracaoMinPorFrequencia = 1
            },
            new ProtocoloTerapeutico
            {
                ExternalId = Guid.NewGuid().ToString(),
                Nome = "Protocolo D - Holístico",
                Categoria = "Test",
                FrequenciasJson = "[7.83,14.1,20.8]", // Frequências Schumann
                AmplitudeV = 5.0,
                FormaOnda = "Sine",
                DuracaoMinPorFrequencia = 1
            }
        };

        context.ProtocolosTerapeuticos.AddRange(protocolos);
        context.SaveChanges();

        _output.WriteLine($"✅ {protocolos.Length} protocolos de teste adicionados à BD");
    }

    #endregion

    #region TESTES CRÍTICOS (PRIORIDADE 1)

    [Fact]
    public void Test01_AlvoMelhoriaGlobal_DeveAtualizarFilaExistente()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 01: Slider AlvoMelhoriaGlobal deve atualizar fila existente");
        var (vm, context) = CreateViewModelWithMocks();

        // Adicionar 3 protocolos à fila
        for (int i = 1; i <= 3; i++)
        {
            vm.FilaTerapias.Add(new TerapiaFilaItem(i, $"Protocolo {i}", 70.0, i)
            {
                AlvoMelhoria = 95.0 // Alvo inicial
            });
        }

        // Act
        vm.AlvoMelhoriaGlobal = 80.0; // Mudar slider

        // Assert
        Assert.Equal(3, vm.FilaTerapias.Count);
        Assert.All(vm.FilaTerapias, item => Assert.Equal(80.0, item.AlvoMelhoria));

        _output.WriteLine($"✅ {vm.FilaTerapias.Count} protocolos atualizados para AlvoMelhoria = 80%");

        // Cleanup
        context.Dispose();
    }

    [Fact]
    public void Test02_AddToQueue_DeveAplicarAlvoMelhoriaGlobal()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 02: AddToQueue deve aplicar AlvoMelhoriaGlobal");
        var (vm, context) = CreateViewModelWithMocks();

        vm.AlvoMelhoriaGlobal = 85.0;

        // Criar protocolo mock e adicionar ao scan
        var protocolo = new ProtocoloTerapeutico
        {
            Id = 999,
            ExternalId = Guid.NewGuid().ToString(),
            Nome = "Mock Protocolo",
            FrequenciasJson = "[100]",
            AmplitudeV = 5.0
        };

        var protocoloComValue = new ProtocoloComValue(protocolo, 75.0)
        {
            IsSelected = true
        };

        vm.ProtocolosScanned.Add(protocoloComValue);

        // Act
        vm.AddToQueueCommand.Execute(null);

        // Assert
        Assert.Single(vm.FilaTerapias);
        var item = vm.FilaTerapias[0];
        Assert.Equal(85.0, item.AlvoMelhoria);

        _output.WriteLine($"✅ Item na fila tem AlvoMelhoria = {item.AlvoMelhoria}% (esperado: 85%)");

        // Cleanup
        context.Dispose();
    }

    [Fact]
    public void Test03_AddToQueue_DevePrevenirDuplicados()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 03: AddToQueue deve prevenir duplicados");
        var (vm, context) = CreateViewModelWithMocks();

        var protocolo = new ProtocoloTerapeutico
        {
            Id = 999,
            ExternalId = Guid.NewGuid().ToString(),
            Nome = "Protocolo A",
            FrequenciasJson = "[100]",
            AmplitudeV = 5.0
        };

        var protocoloComValue = new ProtocoloComValue(protocolo, 80.0)
        {
            IsSelected = true
        };

        vm.ProtocolosScanned.Add(protocoloComValue);

        // Act
        vm.AddToQueueCommand.Execute(null); // 1ª vez
        protocoloComValue.IsSelected = true; // Re-selecionar
        vm.AddToQueueCommand.Execute(null); // 2ª vez (duplicado)

        // Assert
        Assert.Single(vm.FilaTerapias); // Apenas 1 item

        _output.WriteLine($"✅ Duplicados bloqueados: {vm.FilaTerapias.Count} item na fila");

        // Cleanup
        context.Dispose();
    }

    [Fact]
    public void Test04_RemoveFromQueue_DeveReordenar()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 04: RemoveFromQueue deve reordenar (1-based)");
        var (vm, context) = CreateViewModelWithMocks();

        vm.FilaTerapias.Add(new TerapiaFilaItem(1, "Protocolo A", 70.0, 1));
        vm.FilaTerapias.Add(new TerapiaFilaItem(2, "Protocolo B", 70.0, 2));
        vm.FilaTerapias.Add(new TerapiaFilaItem(3, "Protocolo C", 70.0, 3));

        // Act
        var itemRemover = vm.FilaTerapias[1]; // Protocolo B (ordem 2)
        vm.RemoveFromQueueCommand.Execute(itemRemover);

        // Assert
        Assert.Equal(2, vm.FilaTerapias.Count);
        Assert.Equal(1, vm.FilaTerapias[0].Ordem); // A mantém ordem 1
        Assert.Equal(2, vm.FilaTerapias[1].Ordem); // C passa para ordem 2 (era 3)

        _output.WriteLine($"✅ Reordenação correta: {string.Join(", ", vm.FilaTerapias.Select(t => $"{t.Nome} (Ordem {t.Ordem})"))}");

        // Cleanup
        context.Dispose();
    }

    [Fact]
    public void Test05_CanIniciarSessao_DeveDependerDeFila()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 05: CanIniciarSessao deve requerer fila não vazia");
        var (vm, context) = CreateViewModelWithMocks();

        // Act & Assert
        Assert.False(vm.IniciarSessaoCommand.CanExecute(null)); // Fila vazia

        vm.FilaTerapias.Add(new TerapiaFilaItem(1, "Protocolo Test", 70.0, 1));

        Assert.True(vm.IniciarSessaoCommand.CanExecute(null)); // Agora pode

        _output.WriteLine("✅ CanIniciarSessao funciona corretamente");

        // Cleanup
        context.Dispose();
    }

    [Fact]
    public async Task Test06_ImprovementPercent_DeveCrescerProgressivamente()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 06: DummyMedicaoService deve simular crescimento linear");
        var medicaoService = new DummyMedicaoService(new XUnitLogger<DummyMedicaoService>(_output));

        var baseline = await medicaoService.CapturarBaselineAsync(1);
        var leituras = new System.Collections.Generic.List<double>();

        // Act: Capturar 10 leituras
        for (int i = 0; i < 10; i++)
        {
            await Task.Delay(100); // Simular tempo
            var leitura = await medicaoService.CapturarLeituraAsync();
            var improvement = medicaoService.CalcularImprovementPercent(baseline, leitura);
            leituras.Add(improvement);
            _output.WriteLine($"   Leitura {i + 1}: {improvement:N2}%");
        }

        // Assert: Crescimento monotónico
        for (int i = 1; i < leituras.Count; i++)
        {
            Assert.True(leituras[i] >= leituras[i - 1],
                $"Salto detectado: {leituras[i - 1]:N2}% → {leituras[i]:N2}%");
        }

        _output.WriteLine($"✅ Crescimento linear validado (10 leituras monotónicas)");
    }

    [Fact]
    public void Test07_TerapiaFilaItem_AlvoMelhoriaObservavel()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 07: TerapiaFilaItem.AlvoMelhoria deve ser observável");
        var item = new TerapiaFilaItem(1, "Protocolo Test", 70.0, 1);

        bool propertyChanged = false;
        item.PropertyChanged += (s, e) =>
        {
            if (e.PropertyName == nameof(item.AlvoMelhoria))
                propertyChanged = true;
        };

        // Act
        item.AlvoMelhoria = 90.0;

        // Assert
        Assert.True(propertyChanged);
        Assert.Equal(90.0, item.AlvoMelhoria);

        _output.WriteLine("✅ AlvoMelhoria notifica mudanças corretamente");
    }

    [Fact]
    public void Test08_TerapiaFilaItem_AtingiuAlvoCalculado()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 08: TerapiaFilaItem.AtingiuAlvo deve recalcular");
        var item = new TerapiaFilaItem(1, "Protocolo Test", 70.0, 1)
        {
            AlvoMelhoria = 95.0,
            ImprovementPercent = 90.0
        };

        // Assert
        Assert.False(item.AtingiuAlvo); // 90% < 95%

        // Act
        item.ImprovementPercent = 96.0;

        // Assert
        Assert.True(item.AtingiuAlvo); // 96% >= 95%

        _output.WriteLine("✅ AtingiuAlvo calculado corretamente");
    }

    #endregion

    #region TESTES DE SELEÇÃO RÁPIDA

    [Fact]
    public void Test09_SelecionarTop_DeveSelecionarNMaiores()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 09: SelecionarTop deve selecionar N maiores Value%");
        var (vm, context) = CreateViewModelWithMocks();

        // Adicionar protocolos com values conhecidos
        var protocolos = new[]
        {
            new ProtocoloTerapeutico { Id = 1, ExternalId = "A", Nome = "A", FrequenciasJson = "[1]", AmplitudeV = 5.0 },
            new ProtocoloTerapeutico { Id = 2, ExternalId = "B", Nome = "B", FrequenciasJson = "[2]", AmplitudeV = 5.0 },
            new ProtocoloTerapeutico { Id = 3, ExternalId = "C", Nome = "C", FrequenciasJson = "[3]", AmplitudeV = 5.0 },
            new ProtocoloTerapeutico { Id = 4, ExternalId = "D", Nome = "D", FrequenciasJson = "[4]", AmplitudeV = 5.0 }
        };

        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[0], 90.0));
        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[1], 80.0));
        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[2], 70.0));
        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[3], 60.0));

        // Act
        vm.SelecionarTopCommand.Execute(2); // Top 2

        // Assert
        var selecionados = vm.ProtocolosScanned.Where(p => p.IsSelected).ToList();
        Assert.Equal(2, selecionados.Count);

        _output.WriteLine($"✅ Top 2 selecionados: {string.Join(", ", selecionados.Select(p => $"{p.Nome} ({p.ValuePercent}%)"))}");

        // Cleanup
        context.Dispose();
    }

    [Fact]
    public void Test10_SelecionarPorValue_DeveSelecionarAcimaFiltro()
    {
        // Arrange
        _output.WriteLine("🧪 TEST 10: SelecionarPorValue deve selecionar >= FiltroValueMinimo");
        var (vm, context) = CreateViewModelWithMocks();

        var protocolos = new[]
        {
            new ProtocoloTerapeutico { Id = 1, ExternalId = "A", Nome = "A", FrequenciasJson = "[1]", AmplitudeV = 5.0 },
            new ProtocoloTerapeutico { Id = 2, ExternalId = "B", Nome = "B", FrequenciasJson = "[2]", AmplitudeV = 5.0 },
            new ProtocoloTerapeutico { Id = 3, ExternalId = "C", Nome = "C", FrequenciasJson = "[3]", AmplitudeV = 5.0 },
            new ProtocoloTerapeutico { Id = 4, ExternalId = "D", Nome = "D", FrequenciasJson = "[4]", AmplitudeV = 5.0 }
        };

        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[0], 90.0));
        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[1], 75.0));
        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[2], 50.0));
        vm.ProtocolosScanned.Add(new ProtocoloComValue(protocolos[3], 30.0));

        vm.FiltroValueMinimo = 70.0;

        // Act
        vm.SelecionarPorValueCommand.Execute(null);

        // Assert
        var selecionados = vm.ProtocolosScanned.Where(p => p.IsSelected).ToList();
        Assert.Equal(2, selecionados.Count);
        Assert.All(selecionados, p => Assert.True(p.ValuePercent >= 70.0));

        _output.WriteLine($"✅ {selecionados.Count} protocolos selecionados (Value >= 70%)");

        // Cleanup
        context.Dispose();
    }

    #endregion

    #region DISPOSE

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _output.WriteLine("🧹 Cleanup E2E completo");
    }

    #endregion
}
