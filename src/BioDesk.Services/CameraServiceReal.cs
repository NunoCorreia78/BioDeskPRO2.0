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
public sealed class RealCameraService : ICameraService, IDisposable
{
    private bool _isPreviewRunning;
    private CameraInfo? _activeCamera;
    private Bitmap? _lastCapturedFrame;
    private VideoCaptureDevice? _videoSource;
    private readonly object _frameLock = new();
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

            // 🎯 CROP QUADRADO CENTRAL (para íris)
            var croppedFrame = CropToSquare(frame);
            frame.Dispose();

            // Guardar última captura (já em formato quadrado) de forma thread-safe
            Bitmap? eventBitmap = null;
            lock (_frameLock)
            {
                _lastCapturedFrame?.Dispose();
                // Clonar para garantir que o bitmap que guardamos não seja alterado externamente
                _lastCapturedFrame = (Bitmap)croppedFrame.Clone();

                // Criar uma cópia dedicada para o evento para evitar races com _lastCapturedFrame
                eventBitmap = (Bitmap)_lastCapturedFrame.Clone();
            }

            try
            {
                // Converter para byte[] a partir da cópia dedicada (sem risco de race)
                byte[] frameBytes = BitmapToByteArray(eventBitmap);
                FrameAvailable?.Invoke(this, frameBytes);
            }
            finally
            {
                // Dispor do croppedFrame original e da cópia do evento
                eventBitmap?.Dispose();
                croppedFrame.Dispose();
            }
        }
        catch
        {
            // Silenciar erros de conversão
        }
    }

    /// <summary>
    /// Faz crop quadrado central da imagem (para captura de íris)
    /// </summary>
    private Bitmap CropToSquare(Bitmap source)
    {
        int width = source.Width;
        int height = source.Height;

        // Calcular dimensão quadrada (menor lado)
        int size = Math.Min(width, height);

        // Calcular offset para centralizar
        int offsetX = (width - size) / 2;
        int offsetY = (height - size) / 2;

        // Criar bitmap quadrado
        var squareBitmap = new Bitmap(size, size);
        using (var g = Graphics.FromImage(squareBitmap))
        {
            g.DrawImage(source,
                new Rectangle(0, 0, size, size),           // Destino: quadrado completo
                new Rectangle(offsetX, offsetY, size, size), // Origem: centro da imagem
                GraphicsUnit.Pixel);
        }

        return squareBitmap;
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

        // Clonar o bitmap enquanto protegido por lock para evitar
        // que o frame seja alterado/descartado por outro thread
        Bitmap? clone = null;
        lock (_frameLock)
        {
            if (_lastCapturedFrame == null)
                return Task.FromResult<byte[]?>(null);

            clone = (Bitmap)_lastCapturedFrame.Clone();
        }

        try
        {
            // Converter a cópia para bytes (sem risco de race)
            byte[] frameBytes = BitmapToByteArray(clone);
            return Task.FromResult<byte[]?>(frameBytes);
        }
        finally
        {
            clone?.Dispose();
        }
    }

    public Task<string> SaveCapturedFrameAsync(string folderPath, string fileName)
    {
        Bitmap? clone;
        lock (_frameLock)
        {
            if (_lastCapturedFrame == null)
                throw new InvalidOperationException("Nenhum frame capturado disponível.");

            // Clonar sob lock para garantir que o bitmap não é alterado enquanto gravamos
            clone = (Bitmap)_lastCapturedFrame.Clone();
        }

        try
        {
            // Criar pasta se não existir
            Directory.CreateDirectory(folderPath);

            // Caminho completo
            var fullPath = Path.Combine(folderPath, fileName);

            // Guardar como JPEG usando a cópia
            clone.Save(fullPath, ImageFormat.Jpeg);

            return Task.FromResult(fullPath);
        }
        finally
        {
            clone?.Dispose();
        }
    }

    private byte[] BitmapToByteArray(Bitmap bitmap)
    {
        using var ms = new MemoryStream();
        bitmap.Save(ms, ImageFormat.Png);
        return ms.ToArray();
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            _isPreviewRunning = false;

            if (_videoSource != null)
            {
                try
                {
                    if (_videoSource.IsRunning)
                    {
                        _videoSource.SignalToStop();

                        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
                        while (_videoSource.IsRunning && stopwatch.ElapsedMilliseconds < 2000)
                        {
                            System.Threading.Thread.Sleep(50);
                        }

                        if (_videoSource.IsRunning)
                        {
                            _videoSource.Stop();
                        }
                    }
                }
                catch
                {
                    // Ignorar erros de paragem durante dispose
                }
                finally
                {
                    _videoSource.NewFrame -= OnNewFrameReceived;
                    _videoSource = null;
                }
            }

            _lastCapturedFrame?.Dispose();
            _lastCapturedFrame = null;
            _activeCamera = null;
        }

        _disposed = true;
    }
}
