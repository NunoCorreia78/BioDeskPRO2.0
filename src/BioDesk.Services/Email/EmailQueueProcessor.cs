using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Email;

/// <summary>
/// Serviço em background que processa fila de emails automaticamente
/// Executa a cada 2 minutos verificando se há mensagens pendentes
/// </summary>
public class EmailQueueProcessor : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly IConfiguration _configuration;
    private readonly ILogger<EmailQueueProcessor> _logger;

    public EmailQueueProcessor(IServiceProvider serviceProvider, IConfiguration configuration, ILogger<EmailQueueProcessor> logger)
    {
        _serviceProvider = serviceProvider;
        _configuration = configuration;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("🚀 EmailQueueProcessor iniciado. Aguardando 10s para DB inicializar...");

        // ⚡ CRITICAL: Aguardar app inicializar completamente antes de aceder DB
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        _logger.LogWarning("✅ ========== EMAIL QUEUE PROCESSOR ATIVO ==========");
        _logger.LogWarning("✅ Verificando fila a cada 30 segundos...");
        _logger.LogWarning("✅ ==================================================");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _logger.LogWarning("🔄 [EmailQueueProcessor] ========== CICLO INICIADO ==========");
                _logger.LogWarning("🔄 [EmailQueueProcessor] EXECUTANDO AGORA - {Time}", DateTime.Now.ToString("HH:mm:ss"));
                _logger.LogWarning("🔄 [EmailQueueProcessor] Thread ID: {ThreadId}", System.Threading.Thread.CurrentThread.ManagedThreadId);

                // Criar scope para resolver IEmailService
                using var scope = _serviceProvider.CreateScope();
                var emailService = scope.ServiceProvider.GetRequiredService<IEmailService>();

                // Processar fila
                await emailService.ProcessarFilaAsync();

                _logger.LogWarning("✅ [EmailQueueProcessor] Ciclo completo - Próximo em 30s");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao processar fila de emails");
            }

            // Aguardar 30 segundos antes da próxima verificação (mais responsivo!)
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }

        _logger.LogInformation("🛑 EmailQueueProcessor encerrado");
    }
}
