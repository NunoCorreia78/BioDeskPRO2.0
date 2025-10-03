using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace BioDesk.Services;

/// <summary>
/// Interface para serviço de captura de câmara USB
/// Suporta WebCam (índice 0) e Iridoscópio (índice 1)
/// </summary>
public interface ICameraService
{
    /// <summary>
    /// Lista todas as câmaras disponíveis no sistema
    /// </summary>
    Task<List<CameraInfo>> ListAvailableCamerasAsync();

    /// <summary>
    /// Inicia preview da câmara especificada
    /// </summary>
    /// <param name="cameraIndex">0 = WebCam, 1 = Iridoscópio</param>
    Task StartPreviewAsync(int cameraIndex);

    /// <summary>
    /// Para o preview atual
    /// </summary>
    Task StopPreviewAsync();

    /// <summary>
    /// Captura frame atual como imagem
    /// </summary>
    Task<byte[]?> CaptureFrameAsync();

    /// <summary>
    /// Guarda frame capturado como ficheiro
    /// </summary>
    Task<string> SaveCapturedFrameAsync(string destinationPath, string filename);

    /// <summary>
    /// Event disparado quando há novo frame disponível (para preview)
    /// </summary>
    event EventHandler<byte[]>? FrameAvailable;

    /// <summary>
    /// Câmara atualmente ativa
    /// </summary>
    CameraInfo? ActiveCamera { get; }

    /// <summary>
    /// Estado do preview
    /// </summary>
    bool IsPreviewRunning { get; }
}

/// <summary>
/// Informação sobre câmara disponível
/// </summary>
public class CameraInfo
{
    public int Index { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool IsAvailable { get; set; }
}

/// <summary>
/// Implementação do serviço de câmara usando DirectShow (Windows)
/// NOTA: Esta é uma implementação simplificada. Para produção, usar AForge.NET ou Emgu.CV
/// </summary>
public class CameraService : ICameraService, IDisposable
{
    private bool _isPreviewRunning;
    private CameraInfo? _activeCamera;
    private Bitmap? _lastCapturedFrame;
    private readonly System.Timers.Timer _previewTimer;
    private bool _disposed;

    public event EventHandler<byte[]>? FrameAvailable;
    public CameraInfo? ActiveCamera => _activeCamera;
    public bool IsPreviewRunning => _isPreviewRunning;

    public CameraService()
    {
        _previewTimer = new System.Timers.Timer(33); // ~30 FPS
        _previewTimer.Elapsed += async (s, e) => await EmitPreviewFrameAsync();
    }

    public Task<List<CameraInfo>> ListAvailableCamerasAsync()
    {
        // STUB: Detecção real requer DirectShow FilterGraph
        // Por agora, retornar câmaras simuladas
        var cameras = new List<CameraInfo>
        {
            new CameraInfo
            {
                Index = 0,
                Name = "WebCam Integrada",
                Description = "Câmara padrão do sistema (índice 0)",
                IsAvailable = true
            },
            new CameraInfo
            {
                Index = 1,
                Name = "Iridoscópio USB",
                Description = "Câmara especializada para íris (índice 1)",
                IsAvailable = false // Será true quando ligada
            }
        };

        return Task.FromResult(cameras);
    }

    public Task StartPreviewAsync(int cameraIndex)
    {
        if (_isPreviewRunning)
            StopPreviewAsync().Wait();

        _activeCamera = new CameraInfo
        {
            Index = cameraIndex,
            Name = cameraIndex == 0 ? "WebCam" : "Iridoscópio",
            IsAvailable = true
        };

        _isPreviewRunning = true;
        _previewTimer.Start();

        return Task.CompletedTask;
    }

    public Task StopPreviewAsync()
    {
        _isPreviewRunning = false;
        _previewTimer.Stop();
        _activeCamera = null;

        return Task.CompletedTask;
    }

    public Task<byte[]?> CaptureFrameAsync()
    {
        if (!_isPreviewRunning || _activeCamera == null)
            return Task.FromResult<byte[]?>(null);

        // STUB: Captura real requer DirectShow
        // Por agora, gerar frame placeholder
        var bitmap = GeneratePlaceholderFrame(_activeCamera.Index);
        _lastCapturedFrame = bitmap;

        // Converter para bytes (PNG)
        using var memoryStream = new MemoryStream();
        bitmap.Save(memoryStream, ImageFormat.Png);
        return Task.FromResult<byte[]?>(memoryStream.ToArray());
    }

    public async Task<string> SaveCapturedFrameAsync(string destinationPath, string filename)
    {
        if (_lastCapturedFrame == null)
            throw new InvalidOperationException("Nenhum frame capturado. Chame CaptureFrameAsync() primeiro.");

        Directory.CreateDirectory(destinationPath);
        var fullPath = Path.Combine(destinationPath, filename);

        await Task.Run(() => _lastCapturedFrame.Save(fullPath, ImageFormat.Jpeg));

        return fullPath;
    }

    private async Task EmitPreviewFrameAsync()
    {
        if (!_isPreviewRunning || _activeCamera == null)
            return;

        try
        {
            var frameBytes = await CaptureFrameAsync();
            if (frameBytes != null)
                FrameAvailable?.Invoke(this, frameBytes);
        }
        catch
        {
            // Silenciar erros de preview
        }
    }

    private Bitmap GeneratePlaceholderFrame(int cameraIndex)
    {
        // Gerar imagem placeholder simples
        var bitmap = new Bitmap(800, 600);
        using var g = Graphics.FromImage(bitmap);

        // Fundo preto
        g.Clear(Color.Black);

        // Texto principal centrado
        var font = new Font("Segoe UI", 28, FontStyle.Bold);
        var brush = new SolidBrush(Color.White);
        var text = cameraIndex == 0 ? "📹 WebCam Preview" : "👁️ Iridoscópio Preview";
        var textSize = g.MeasureString(text, font);
        g.DrawString(text, font, brush, (800 - textSize.Width) / 2, 260);

        // Subtexto
        var subFont = new Font("Segoe UI", 14);
        var subBrush = new SolidBrush(Color.FromArgb(150, 150, 150));
        var subText = "Aguardando sinal da câmara...";
        var subSize = g.MeasureString(subText, subFont);
        g.DrawString(subText, subFont, subBrush, (800 - subSize.Width) / 2, 320);

        return bitmap;
    }

    public void Dispose()
    {
        if (_disposed) return;

        _previewTimer?.Dispose();
        _lastCapturedFrame?.Dispose();
        _disposed = true;
    }
}
