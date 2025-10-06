using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Debug;

/// <summary>
/// Implementação do serviço de debug de arrasto.
/// Apenas ativo em builds DEBUG - em Release, todos os métodos são no-op.
/// </summary>
public class DragDebugService : IDragDebugService
{
    private readonly ILogger<DragDebugService> _logger;

    public DragDebugService(ILogger<DragDebugService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Regista evento de debug. Em builds Release, este método não faz nada.
    /// </summary>
    public void RecordEvent(
        DragDebugEventType type,
        string message,
        IReadOnlyDictionary<string, double>? metrics = null,
        IReadOnlyDictionary<string, string>? context = null)
    {
#if DEBUG
        // Apenas em DEBUG: log detalhado para análise
        var contextStr = context != null ? string.Join(", ", context) : "N/A";
        var metricsStr = metrics != null ? string.Join(", ", metrics) : "N/A";
        
        _logger.LogDebug(
            "[DRAG DEBUG] {Type} | {Message} | Context: {Context} | Metrics: {Metrics}",
            type,
            message,
            contextStr,
            metricsStr);
#endif
        // Em Release: não faz nada (zero overhead)
    }
}
