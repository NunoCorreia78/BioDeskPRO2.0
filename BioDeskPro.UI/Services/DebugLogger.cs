using System;
using System.IO;

namespace BioDeskPro.UI.Services;

public static class DebugLogger
{
    private static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "BioDesk", "debug.log");

    static DebugLogger()
    {
        var logDir = Path.GetDirectoryName(LogPath);
        if (!Directory.Exists(logDir))
        {
            Directory.CreateDirectory(logDir!);
        }
    }

    public static void Log(string message)
    {
        var timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.fff");
        var logMessage = $"[{timestamp}] {message}";
        
        // Escrever no console
        Console.WriteLine(logMessage);
        
        // Escrever no arquivo
        try
        {
            File.AppendAllText(LogPath, logMessage + Environment.NewLine);
        }
        catch
        {
            // Ignorar erros de escrita no arquivo para não quebrar a aplicação
        }
    }

    public static void LogError(string message, Exception? ex = null)
    {
        Log($"❌ ERROR: {message}");
        if (ex != null)
        {
            Log($"❌ EXCEPTION: {ex.Message}");
            Log($"❌ STACK TRACE: {ex.StackTrace}");
        }
    }

    public static void LogInfo(string message)
    {
        Log($"✅ INFO: {message}");
    }

    public static void LogDebug(string message)
    {
        Log($"🔍 DEBUG: {message}");
    }
}