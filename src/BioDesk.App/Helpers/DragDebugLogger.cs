using System;
using System.IO;
using System.Text;

namespace BioDesk.App.Helpers;

/// <summary>
/// Logger simples para gravar debug de drag do mapa iridológico
/// Grava logs em: BioDeskPro2/drag_debug.log
/// </summary>
public static class DragDebugLogger
{
    private static readonly string _logPath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "..", "..", "..", "..",
        "drag_debug.log"
    );

    private static readonly object _lock = new();

    static DragDebugLogger()
    {
        // Limpar log anterior ao iniciar
        try
        {
            var fullPath = Path.GetFullPath(_logPath);
            if (File.Exists(fullPath))
            {
                File.Delete(fullPath);
            }

            // Escrever cabeçalho
            File.WriteAllText(fullPath, $"=== DRAG DEBUG LOG - {DateTime.Now:yyyy-MM-dd HH:mm:ss} ===\n\n", Encoding.UTF8);
        }
        catch
        {
            // Ignorar erros de inicialização
        }
    }

    public static void Log(string message)
    {
        try
        {
            lock (_lock)
            {
                var fullPath = Path.GetFullPath(_logPath);
                var timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                var line = $"[{timestamp}] {message}\n";
                File.AppendAllText(fullPath, line, Encoding.UTF8);
            }
        }
        catch
        {
            // Ignorar erros silenciosamente
        }
    }

    public static void LogDragStart(double x, double y, string modo, double centroPupilaX, double centroPupilaY, double centroIrisX, double centroIrisY)
    {
        Log($"🟢 [DRAG START] Posição inicial: ({x:F2}, {y:F2})");
        Log($"   Modo: {modo}");
        Log($"   Centro Pupila: ({centroPupilaX:F2}, {centroPupilaY:F2})");
        Log($"   Centro Íris: ({centroIrisX:F2}, {centroIrisY:F2})");
    }

    public static void LogDragMove(double currentX, double currentY, double deltaX, double deltaY, double scaleY, string tipo, double centroPupilaPreX, double centroPupilaPreY, double centroIrisPreX, double centroIrisPreY)
    {
        Log($"🔵 [DRAG MOVE] Pos atual: ({currentX:F2}, {currentY:F2})");
        Log($"   Delta RAW: ({deltaX:F2}, {deltaY:F2})");
        Log($"   ScaleY: {scaleY:F3}");
        Log($"   Invertendo Y? {(Math.Abs(scaleY + 1.0) < 0.001 ? "SIM" : "NÃO")}");
        Log($"   Delta FINAL: ({deltaX:F2}, {deltaY:F2})");
        Log($"   Tipo: {tipo}");
        Log($"   Centro PRÉ-translação - Pupila: ({centroPupilaPreX:F2}, {centroPupilaPreY:F2}), Íris: ({centroIrisPreX:F2}, {centroIrisPreY:F2})");
    }

    public static void LogDragMovePost(double centroPupilaPostX, double centroPupilaPostY, double centroIrisPostX, double centroIrisPostY)
    {
        Log($"   Centro PÓS-translação - Pupila: ({centroPupilaPostX:F2}, {centroPupilaPostY:F2}), Íris: ({centroIrisPostX:F2}, {centroIrisPostY:F2})");
    }

    public static void LogDragEnd()
    {
        Log($"🔴 [DRAG END] Arrasto finalizado");
        Log("");
    }

    public static void LogTransform(double canvasX, double canvasY, double handlerX, double handlerY)
    {
        Log($"🔄 [TRANSFORM] TransformToVisual: MapaOverlayCanvas → HandlersCanvas");
        Log($"   Canvas: ({canvasX:F2}, {canvasY:F2}) → Handlers: ({handlerX:F2}, {handlerY:F2})");
    }
}
