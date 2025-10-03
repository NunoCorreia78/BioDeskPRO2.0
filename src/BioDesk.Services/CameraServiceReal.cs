using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AForge.Video;
using AForge.Video.DirectShow;

namespace BioDesk.Services;

/// <summary>
/// Serviço de câmara com captura REAL usando AForge.NET DirectShow
/// </summary>
public class RealCameraService : ICameraService, IDisposable
{
    private bool _isPreviewRunning;
    private CameraInfo? _activeCamera;
    private Bitmap? _lastCapturedFrame;
    private VideoCaptureDevice? _videoSource;
    private bool _disposed;

    public event EventHandler<byte[]>? FrameAvailable;
    public CameraInfo? ActiveCamera => _activeCamera;
    public bool IsPreviewRunning => _isPreviewRunning;

    public Task<List<CameraInfo>> ListAvailableCamerasAsync()
    {
        var cameras = new List<CameraInfo>();

        try
        {
            // Enumerar dispositivos DirectShow reais
            var videoDevices = new FilterInfoCollection(FilterCategory.VideoInputDevice);

            for (int i = 0; i < videoDevices.Count; i++)
            {
                cameras.Add(new CameraInfo
                {
                    Index = i,
                    Name = videoDevices[i].Name,
                    Description = $"Dispositivo DirectShow (índice {i})",
                    IsAvailable = true
                });
            }

            // Se não houver câmaras, adicionar placeholders
            if (cameras.Count == 0)
            {
                cameras.Add(new CameraInfo
                {
                    Index = 0,
                    Name = "Nenhuma câmara detectada",
                    Description = "Conecte uma webcam ou iridoscópio USB",
                    IsAvailable = false
                });
            }
        }
        catch
        {
            // Fallback se AForge falhar
            cameras.Add(new CameraInfo
            {
                Index = 0,
                Name = "Erro ao detectar câmaras",
                Description = "Verifique drivers e permissões",
                IsAvailable = false
            });
        }

        return Task.FromResult(cameras);
    }

    public async Task StartPreviewAsync(int cameraIndex)
    {
        // 🔴 CRÍTICO: NUNCA usar .Wait() em WPF!
        if (_isPreviewRunning)
            await StopPreviewAsync();

        try
        {
            var videoDevices = new FilterInfoCollection(FilterCategory.VideoInputDevice);

            if (cameraIndex >= videoDevices.Count)
            {
                throw new ArgumentException($"Câmara {cameraIndex} não encontrada. Disponíveis: {videoDevices.Count}");
            }

            // Criar source de vídeo
            _videoSource = new VideoCaptureDevice(videoDevices[cameraIndex].MonikerString);

            // Configurar resolução (priorizar 640x480 ou 800x600)
            if (_videoSource.VideoCapabilities.Length > 0)
            {
                var preferred = _videoSource.VideoCapabilities
                    .FirstOrDefault(c => c.FrameSize.Width == 640 && c.FrameSize.Height == 480)
                    ?? _videoSource.VideoCapabilities[0];

                _videoSource.VideoResolution = preferred;
            }

            // Subscrever eventos de novo frame
            _videoSource.NewFrame += OnNewFrameReceived;

            // Iniciar captura
            _videoSource.Start();

            _activeCamera = new CameraInfo
            {
                Index = cameraIndex,
                Name = videoDevices[cameraIndex].Name,
                IsAvailable = true
            };

            _isPreviewRunning = true;
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Falha ao iniciar câmara {cameraIndex}: {ex.Message}", ex);
        }
    }

    private void OnNewFrameReceived(object sender, NewFrameEventArgs eventArgs)
    {
        try
        {
            // Clonar frame (AForge reutiliza o bitmap)
            var frame = (Bitmap)eventArgs.Frame.Clone();

            // Guardar última captura
            _lastCapturedFrame?.Dispose();
            _lastCapturedFrame = (Bitmap)frame.Clone();

            // Converter para byte[] e emitir evento
            byte[] frameBytes = BitmapToByteArray(frame);
            FrameAvailable?.Invoke(this, frameBytes);

            frame.Dispose();
        }
        catch
        {
            // Silenciar erros de conversão
        }
    }

    public async Task StopPreviewAsync()
    {
        _isPreviewRunning = false;

        if (_videoSource != null && _videoSource.IsRunning)
        {
            // 🔴 CRÍTICO: WaitForStop() bloqueia thread!
            // Executar em Task.Run + polling com timeout
            await Task.Run(async () =>
            {
                try
                {
                    _videoSource.SignalToStop();

                    // Polling com timeout de 2 segundos
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                    while (_videoSource.IsRunning && stopwatch.ElapsedMilliseconds < 2000)
                    {
                        await Task.Delay(50);
                    }

                    // Forçar paragem se ainda a correr
                    if (_videoSource.IsRunning)
                    {
                        _videoSource.Stop();
                    }
                }
                catch { /* Ignora erros de paragem forçada */ }
            });

            _videoSource.NewFrame -= OnNewFrameReceived;
            _videoSource = null;
        }

        _activeCamera = null;
    }

    public Task<byte[]?> CaptureFrameAsync()
    {
        if (!_isPreviewRunning || _lastCapturedFrame == null)
            return Task.FromResult<byte[]?>(null);

        // Retornar último frame capturado
        byte[] frameBytes = BitmapToByteArray(_lastCapturedFrame);
        return Task.FromResult<byte[]?>(frameBytes);
    }

    public Task<string> SaveCapturedFrameAsync(string folderPath, string fileName)
    {
        if (_lastCapturedFrame == null)
            throw new InvalidOperationException("Nenhum frame capturado disponível.");

        // Criar pasta se não existir
        Directory.CreateDirectory(folderPath);

        // Caminho completo
        var fullPath = Path.Combine(folderPath, fileName);

        // Guardar como JPEG
        _lastCapturedFrame.Save(fullPath, ImageFormat.Jpeg);

        return Task.FromResult(fullPath);
    }

    private byte[] BitmapToByteArray(Bitmap bitmap)
    {
        using var ms = new MemoryStream();
        bitmap.Save(ms, ImageFormat.Png);
        return ms.ToArray();
    }

    public void Dispose()
    {
        if (_disposed) return;

        StopPreviewAsync().Wait();
        _lastCapturedFrame?.Dispose();
        _disposed = true;
    }
}
