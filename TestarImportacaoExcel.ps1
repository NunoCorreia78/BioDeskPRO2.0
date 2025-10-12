# ===================================================================
# Script PowerShell: Testar Importação Excel FrequencyList.xls
# ===================================================================
# Cria um teste temporário em C# para executar PreviewAsync() e ImportAsync()
# do ExcelImportService com logging detalhado.
# ===================================================================

$ErrorActionPreference = "Stop"

# Caminho do ficheiro Excel
$excelPath = "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Templates\Terapias\FrequencyList.xls"

# Caminho da BD
$dbPath = "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "   TESTE IMPORTAÇÃO FREQUENCYLIST.XLS" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "📂 Excel Path: $excelPath" -ForegroundColor Yellow
Write-Host "📂 Database:   $dbPath" -ForegroundColor Yellow
Write-Host ""

# Verificar se Excel existe
if (-not (Test-Path $excelPath)) {
    Write-Host "❌ ERRO: FrequencyList.xls não encontrado!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Ficheiro Excel encontrado ($(([System.IO.FileInfo]$excelPath).Length / 1MB).ToString('F2')) MB)" -ForegroundColor Green
Write-Host ""

# Criar código C# de teste temporário
$testCode = @"
using System;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;
using BioDesk.Data.Repositories;
using BioDesk.Services.Excel;
using BioDesk.Services;

namespace BioDeskTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            // Configurar DI
            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Information));
            services.AddDbContext<BioDeskDbContext>(options =>
                options.UseSqlite("Data Source=$dbPath"));
            services.AddScoped<IProtocoloRepository, ProtocoloRepository>();
            services.AddScoped<IExcelImportService, ExcelImportService>();

            var serviceProvider = services.BuildServiceProvider();

            using var scope = serviceProvider.CreateScope();
            var excelService = scope.ServiceProvider.GetRequiredService<IExcelImportService>();
            var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

            string excelPath = @"$excelPath";

            logger.LogInformation("========================================");
            logger.LogInformation("INICIANDO TESTE PREVIEW");
            logger.LogInformation("========================================");

            try
            {
                var previewResult = await excelService.PreviewAsync(excelPath, maxLinhas: 20);

                logger.LogInformation("✅ PREVIEW COMPLETO");
                logger.LogInformation($"Total linhas no ficheiro: {previewResult.TotalLinhasNoFicheiro}");
                logger.LogInformation($"Linhas retornadas: {previewResult.ProtocolosPreview.Count}");
                logger.LogInformation("");
                logger.LogInformation("PRIMEIRAS 20 LINHAS:");
                logger.LogInformation("-------------------------------------------");

                int i = 1;
                foreach (var proto in previewResult.ProtocolosPreview)
                {
                    logger.LogInformation($"{i}. {proto.Nome} | {proto.NomeOriginalEn}");
                    logger.LogInformation($"   Categoria: {proto.Categoria} | Frequências: {proto.GetFrequencias().Count}");
                    i++;
                }

                logger.LogInformation("");
                logger.LogInformation("========================================");
                logger.LogInformation("Deseja executar importação COMPLETA? (S/N)");
                logger.LogInformation("========================================");

                var resposta = Console.ReadLine();
                if (resposta?.ToUpper() == "S")
                {
                    logger.LogInformation("");
                    logger.LogInformation("🚀 INICIANDO IMPORTAÇÃO COMPLETA...");
                    logger.LogInformation("");

                    var importResult = await excelService.ImportAsync(excelPath);

                    logger.LogInformation("");
                    logger.LogInformation("========================================");
                    logger.LogInformation("✅ IMPORTAÇÃO COMPLETA!");
                    logger.LogInformation("========================================");
                    logger.LogInformation($"Total Linhas: {importResult.TotalLinhas}");
                    logger.LogInformation($"Linhas OK: {importResult.LinhasOk}");
                    logger.LogInformation($"Warnings: {importResult.LinhasWarnings}");
                    logger.LogInformation($"Erros: {importResult.LinhasErros}");
                    logger.LogInformation($"Duração: {importResult.DuracaoSegundos:F2}s");

                    if (importResult.Warnings.Count > 0)
                    {
                        logger.LogInformation("");
                        logger.LogInformation("⚠️ Warnings:");
                        foreach (var w in importResult.Warnings)
                            logger.LogWarning(w);
                    }

                    if (importResult.Erros.Count > 0)
                    {
                        logger.LogInformation("");
                        logger.LogInformation("❌ Erros:");
                        foreach (var e in importResult.Erros)
                            logger.LogError(e);
                    }
                }
                else
                {
                    logger.LogInformation("❌ Importação cancelada pelo utilizador");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "💥 ERRO durante teste");
            }
        }
    }
}
"@

# Guardar código temporário
$tempCsPath = Join-Path $PSScriptRoot "TestarImportacaoTemp.cs"
$testCode | Out-File -FilePath $tempCsPath -Encoding UTF8

Write-Host "📝 Código de teste criado: $tempCsPath" -ForegroundColor Cyan
Write-Host ""

# Compilar e executar com dotnet script (requer script runner)
Write-Host "🔨 Para executar o teste, use um dos seguintes métodos:" -ForegroundColor Yellow
Write-Host ""
Write-Host "MÉTODO 1 (dotnet-script):" -ForegroundColor White
Write-Host "  dotnet tool install -g dotnet-script" -ForegroundColor Gray
Write-Host "  dotnet script $tempCsPath" -ForegroundColor Gray
Write-Host ""
Write-Host "MÉTODO 2 (criar projeto console temporário):" -ForegroundColor White
Write-Host "  cd src/BioDesk.Tests" -ForegroundColor Gray
Write-Host "  dotnet test --filter ""ClassName=ExcelImportServiceTests""" -ForegroundColor Gray
Write-Host ""
Write-Host "MÉTODO 3 (executar diretamente via App):" -ForegroundColor White
Write-Host "  Adicionar botão de teste na UI do BioDeskPro2" -ForegroundColor Gray
Write-Host ""

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "💡 RECOMENDAÇÃO: Criar teste unitário xUnit" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
