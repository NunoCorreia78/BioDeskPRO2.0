using System;
using System.Threading;
using System.Threading.Tasks;
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
    private readonly ILogger<EmailQueueProcessor> _logger;

    public EmailQueueProcessor(IServiceProvider serviceProvider, ILogger<EmailQueueProcessor> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("🚀 EmailQueueProcessor iniciado. Aguardando 10s para DB inicializar...");

        // ⚡ CRITICAL: Aguardar app inicializar completamente antes de aceder DB
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);

        _logger.LogInformation("✅ EmailQueueProcessor ativo. Verificando fila a cada 2 minutos...");

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                // Criar scope para resolver IEmailService
                using var scope = _serviceProvider.CreateScope();
                var emailService = scope.ServiceProvider.GetRequiredService<IEmailService>();

                // Processar fila
                await emailService.ProcessarFilaAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao processar fila de emails");
            }

            // Aguardar 2 minutos antes da próxima verificação
            await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);
        }

        _logger.LogInformation("🛑 EmailQueueProcessor encerrado");
    }
}
