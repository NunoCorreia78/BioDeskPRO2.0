using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media.Imaging;
using BioDesk.Services;

namespace BioDesk.App.Dialogs;

public partial class CameraCaptureWindow : Window
{
    private readonly ICameraService _cameraService;
    private byte[]? _capturedFrameBytes;
    private int _selectedCameraIndex = 0;
    private bool _isPreviewRunning = false;

    public string? CapturedImagePath { get; private set; }

    public CameraCaptureWindow(ICameraService cameraService)
    {
        InitializeComponent();
        _cameraService = cameraService;
        _cameraService.FrameAvailable += OnFrameAvailable;
    }

    private void OnFrameAvailable(object? sender, byte[] frameBytes)
    {
        // Atualizar preview no thread UI
        Dispatcher.Invoke(() =>
        {
            try
            {
                // Converter bytes para BitmapImage WPF
                using var ms = new MemoryStream(frameBytes);
                var bitmapImage = new BitmapImage();
                bitmapImage.BeginInit();
                bitmapImage.CacheOption = BitmapCacheOption.OnLoad;
                bitmapImage.StreamSource = ms;
                bitmapImage.EndInit();
                bitmapImage.Freeze();

                PreviewImage.Source = bitmapImage;
            }
            catch
            {
                // Silenciar erros de conversão
            }
        });
    }

    private async void StartPreviewButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            StartPreviewButton.IsEnabled = false;
            CaptureButton.IsEnabled = false;

            await _cameraService.StartPreviewAsync(_selectedCameraIndex);
            _isPreviewRunning = true;

            StartPreviewButton.Content = "⏹️ Parar Preview";
            StartPreviewButton.Background = System.Windows.Media.Brushes.OrangeRed;
            CaptureButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao iniciar preview: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            StartPreviewButton.IsEnabled = true;
        }
    }

    private async void CaptureButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            CaptureButton.IsEnabled = false;

            // Capturar frame atual
            _capturedFrameBytes = await _cameraService.CaptureFrameAsync();

            if (_capturedFrameBytes == null)
            {
                MessageBox.Show("Falha ao capturar frame.", "Erro", MessageBoxButton.OK, MessageBoxImage.Warning);
                CaptureButton.IsEnabled = true;
                return;
            }

            // 🔴 CRÍTICO: Parar preview ANTES de qualquer MessageBox!
            if (_isPreviewRunning)
            {
                await _cameraService.StopPreviewAsync();
                _isPreviewRunning = false;
            }

            // Confirmar captura
            var result = MessageBox.Show(
                "Imagem capturada! Deseja guardar esta imagem?",
                "Captura Concluída",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {

                // Gerar nome de ficheiro
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var filename = $"iris_captura_{timestamp}.jpg";
                var tempPath = Path.Combine(Path.GetTempPath(), "BioDeskIris");

                // Guardar imagem
                CapturedImagePath = await _cameraService.SaveCapturedFrameAsync(tempPath, filename);

                DialogResult = true;
                Close();
            }
            else
            {
                CaptureButton.IsEnabled = true;
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao capturar imagem: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            CaptureButton.IsEnabled = true;
        }
    }

    private async void CancelButton_Click(object sender, RoutedEventArgs e)
    {
        if (_isPreviewRunning)
        {
            await _cameraService.StopPreviewAsync();
            _isPreviewRunning = false;
        }
        DialogResult = false;
        Close();
    }

    private async void CameraSelector_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Guardar contra evento disparado durante inicialização XAML
        if (CameraSelector == null || !IsLoaded)
            return;

        _selectedCameraIndex = CameraSelector.SelectedIndex;

        // Se preview já estava ativo, reiniciar com nova câmara
        if (_isPreviewRunning)
        {
            await _cameraService.StopPreviewAsync();
            await _cameraService.StartPreviewAsync(_selectedCameraIndex);
        }
    }

    protected override void OnClosed(EventArgs e)
    {
        _cameraService.FrameAvailable -= OnFrameAvailable;

        // ⚠️ NÃO usar .Wait() - causa deadlock! Disposição síncrona
        if (_isPreviewRunning)
        {
            try
            {
                // StopPreview deve ser chamado ANTES do Close nos botões
                // Aqui é apenas fallback de segurança
                _cameraService.StopPreviewAsync().GetAwaiter().GetResult();
            }
            catch { /* Ignora erros em cleanup final */ }
            finally
            {
                _isPreviewRunning = false;
            }
        }
        base.OnClosed(e);
    }
}
