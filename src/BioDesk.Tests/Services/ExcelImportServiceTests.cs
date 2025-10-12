using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data;
using BioDesk.Data.Repositories;
using BioDesk.Services.Excel;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Xunit;
using Xunit.Abstractions;

namespace BioDesk.Tests.Services;

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
    }
}

/// <summary>
/// Testes para ExcelImportService - Importação de FrequencyList.xls
/// </summary>
public sealed class ExcelImportServiceTests : IDisposable
{
    private readonly BioDeskDbContext _context;
    private readonly IProtocoloRepository _repository;
    private readonly IExcelImportService _service;
    private readonly ITestOutputHelper _output;

    public ExcelImportServiceTests(ITestOutputHelper output)
    {
        _output = output;

        // Criar BD in-memory para testes
        var options = new DbContextOptionsBuilder<BioDeskDbContext>()
            .UseInMemoryDatabase(databaseName: $"TestDb_{Guid.NewGuid()}")
            .Options;

        _context = new BioDeskDbContext(options);
        _repository = new ProtocoloRepository(_context);

        // Logger simples com output para xUnit
        var logger = new XUnitLogger<ExcelImportService>(_output);

        _service = new ExcelImportService(_repository, logger);
    }

    [Fact] // ⚡ EXECUTAR AGORA
    public async Task PreviewAsync_DevolveFirstTwentyRows()
    {
        // Arrange
        var excelPath = @"C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Templates\Terapias\FrequencyList.xls";

        // Verificar se ficheiro existe antes de executar teste
        if (!File.Exists(excelPath))
        {
            _output.WriteLine($"⚠️ SKIP: Ficheiro não encontrado: {excelPath}");
            return;
        }

        // Act
        var result = await _service.PreviewAsync(excelPath, maxLinhasPreview: 20);

        // Assert
        _output.WriteLine($"✅ Total linhas: {result.TotalLinhas}");
        _output.WriteLine($"✅ Linhas válidas: {result.LinhasValidas}");
        _output.WriteLine($"✅ Warnings: {result.LinhasWarnings}");
        _output.WriteLine($"✅ Erros: {result.LinhasErros}");
        _output.WriteLine("");
        _output.WriteLine("PRIMEIRAS 20 LINHAS:");
        _output.WriteLine(new string('-', 80));

        foreach (var linha in result.Previews)
        {
            _output.WriteLine($"{linha.NumeroLinha,3}. {linha.NomeTraduzido}");
            _output.WriteLine($"     Original: {linha.NomeOriginal}");
            _output.WriteLine($"     Categoria: {linha.Categoria}");
            _output.WriteLine($"     Frequências: {linha.NumeroFrequencias}");
            if (!string.IsNullOrWhiteSpace(linha.Aviso))
                _output.WriteLine($"     ⚠️  {linha.Aviso}");
            _output.WriteLine("");
        }

        Assert.True(result.TotalLinhas > 1000, "Deve ter mais de 1000 linhas");
        Assert.True(result.Previews.Count <= 20, "Preview deve ter no máximo 20 linhas");
        Assert.True(result.Previews.All(p => !string.IsNullOrWhiteSpace(p.NomeTraduzido)), "Todos devem ter nome traduzido");
        Assert.True(result.Previews.All(p => p.NumeroFrequencias > 0), "Todos devem ter pelo menos 1 frequência");
    }

    [Fact] // ⚡ EXECUTAR IMPORTAÇÃO COMPLETA
    public async Task ImportAsync_ImportaTodosProtocolos()
    {
        // Arrange
        var excelPath = @"C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Templates\Terapias\FrequencyList.xls";

        // Verificar se ficheiro existe antes de executar teste
        if (!File.Exists(excelPath))
        {
            _output.WriteLine($"⚠️ SKIP: Ficheiro não encontrado: {excelPath}");
            return;
        }

        // Act
        var startTime = DateTime.Now;
        var result = await _service.ImportAsync(excelPath);
        var elapsed = DateTime.Now - startTime;

        // Assert
        _output.WriteLine("");
        _output.WriteLine(new string('=', 80));
        _output.WriteLine("✅ IMPORTAÇÃO COMPLETA!");
        _output.WriteLine(new string('=', 80));
        _output.WriteLine($"Total Linhas:  {result.TotalLinhas}");
        _output.WriteLine($"Linhas OK:     {result.LinhasOk}");
        _output.WriteLine($"Warnings:      {result.LinhasWarnings}");
        _output.WriteLine($"Erros:         {result.LinhasErros}");
        _output.WriteLine($"Duração:       {elapsed.TotalSeconds:F2}s");
        _output.WriteLine($"Taxa:          {result.LinhasOk / elapsed.TotalSeconds:F1} linhas/seg");
        _output.WriteLine(new string('=', 80));

        if (result.Warnings.Count > 0)
        {
            _output.WriteLine("");
            _output.WriteLine("⚠️ WARNINGS:");
            foreach (var w in result.Warnings.Take(10)) // Mostrar apenas primeiros 10
                _output.WriteLine($"  - {w}");
            if (result.Warnings.Count > 10)
                _output.WriteLine($"  ... e mais {result.Warnings.Count - 10} warnings");
        }

        if (result.Erros.Count > 0)
        {
            _output.WriteLine("");
            _output.WriteLine("❌ ERROS:");
            foreach (var e in result.Erros)
                _output.WriteLine($"  - {e}");
        }

        // Verificações
        Assert.True(result.TotalLinhas > 1000, "Deve ter processado mais de 1000 linhas");
        Assert.True(result.LinhasOk > 1000, "Deve ter pelo menos 1000 linhas OK (esperado ~1094 após filtrar placeholders)");
        Assert.Equal(0, result.LinhasErros); // Não deve ter erros críticos
        Assert.True(result.DuracaoSegundos > 0);
        Assert.True(result.DuracaoSegundos < 300, "Não deve demorar mais de 5 minutos");

        // Verificar na BD in-memory
        var count = await _context.ProtocolosTerapeuticos.CountAsync();
        _output.WriteLine("");
        _output.WriteLine($"✅ Registos na BD: {count}");
        Assert.Equal(result.LinhasOk, count);

        // Spot-check: verificar alguns protocolos específicos
        var abdomen = await _context.ProtocolosTerapeuticos
            .FirstOrDefaultAsync(p => p.Nome.Contains("Abdominal") || p.Nome.Contains("abdominal"));
        Assert.NotNull(abdomen);
        var freqs = abdomen!.GetFrequencias();
        Assert.True(freqs.Length > 0, "Deve ter frequências");
        _output.WriteLine($"✅ Spot-check 'Abdominal' → '{abdomen.Nome}' ({freqs.Length} freq)");
    }

    [Fact]
    public async Task ValidateFileAsync_FicheiroNaoExiste_RetornaFalse()
    {
        // Arrange
        var fakePath = @"C:\ficheiro_inexistente.xls";

        // Act
        var result = await _service.ValidateFileAsync(fakePath);

        // Assert
        Assert.False(result.IsValid);
        Assert.Contains("não encontrado", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task ValidateFileAsync_ExtensaoInvalida_RetornaFalse()
    {
        // Arrange
        var tempFile = Path.GetTempFileName(); // Cria ficheiro .tmp
        File.WriteAllText(tempFile, "dummy content");

        try
        {
            // Act
            var result = await _service.ValidateFileAsync(tempFile);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains("extensão", result.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            File.Delete(tempFile);
        }
    }

    public void Dispose()
    {
        _context.Dispose();
    }
}
