using System.Collections.Generic;

namespace BioDesk.Services.Debug;

/// <summary>
/// Tipos de eventos de debug para arrasto do mapa iridológico
/// </summary>
public enum DragDebugEventType
{
    DragStart,
    DragMove,
    DragEnd,
    DragMovePreTransform,
    DragMovePostTransform,
    HandlerTranslation,
    ViewModelUpdate
}

/// <summary>
/// Interface para serviço de debug de arrasto do mapa iridológico.
/// Em builds de produção (Release), este serviço não faz nada (no-op).
/// Em builds de debug, grava eventos para análise de performance.
/// </summary>
public interface IDragDebugService
{
    /// <summary>
    /// Regista um evento de debug (apenas em builds DEBUG)
    /// </summary>
    /// <param name="type">Tipo do evento</param>
    /// <param name="message">Mensagem descritiva</param>
    /// <param name="metrics">Métricas opcionais (coordenadas, deltas, etc)</param>
    /// <param name="context">Contexto adicional (modo, estado, etc)</param>
    void RecordEvent(
        DragDebugEventType type,
        string message,
        IReadOnlyDictionary<string, double>? metrics = null,
        IReadOnlyDictionary<string, string>? context = null);
}
