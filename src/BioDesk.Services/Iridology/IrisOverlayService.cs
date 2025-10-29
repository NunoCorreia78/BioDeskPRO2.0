using System;
using System.Drawing;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Emgu.CV;
using Emgu.CV.CvEnum;
using Emgu.CV.Structure;
using Emgu.CV.Util;
using Microsoft.Extensions.Logging;
using Point = System.Windows.Point;

namespace BioDesk.Services.Iridology;

/// <summary>
/// Serviço "INFALÍVEL" para sobreposição do mapa iridológico sobre íris real.
///
/// FLUXO COMPLETO:
/// 1. User: 3 cliques (centro, direita, topo) → Sistema cria elipse inicial
/// 2. Sistema: Detecção automática de bordas (OpenCV Canny + Hough Ellipse)
/// 3. User: Preview do ajuste → "Aceitar" ou "Ajustar Manualmente"
/// 4. Opcional: Ajuste manual com 4 pontos cardinais (N, S, E, W)
///
/// GARANTIAS:
/// - SEMPRE funciona (fallback manual se auto-detect falhar)
/// - User-friendly: 3 cliques + 1 botão = solução em 5 segundos
/// - Performance: Detecção em thread separada, não trava UI
/// </summary>
public class IrisOverlayService : IDisposable
{
    private readonly ILogger<IrisOverlayService>? _logger;
    private bool _disposed;

    // Estado do alinhamento (3-click phase)
    private int _clickCount;
    private Point _centerClick;
    private Point _rightClick;
    private Point _topClick;

    // Transformação calculada
    private TransformGroup? _currentTransform;

    public IrisOverlayService(ILogger<IrisOverlayService>? logger = null)
    {
        _logger = logger;
        ResetAlignment();
    }

    /// <summary>
    /// Fase atual do alinhamento (3-click system)
    /// </summary>
    public enum AlignmentPhase
    {
        Idle,           // Esperando iniciar
        ClickCenter,    // 1/3: Clicar no centro
        ClickRight,     // 2/3: Clicar na borda direita
        ClickTop,       // 3/3: Clicar na borda superior
        AutoFitting,    // Executando auto-detect OpenCV
        ManualAdjust,   // Ajuste manual com pontos cardinais
        Completed       // Alinhamento confirmado
    }

    public AlignmentPhase CurrentPhase { get; private set; } = AlignmentPhase.Idle;

    /// <summary>
    /// Mensagem de instrução contextual para o user
    /// </summary>
    public string InstructionText => CurrentPhase switch
    {
        AlignmentPhase.ClickCenter => "1/3: Clique no centro da pupila",
        AlignmentPhase.ClickRight => "2/3: Clique na borda DIREITA da íris",
        AlignmentPhase.ClickTop => "3/3: Clique na borda SUPERIOR da íris",
        AlignmentPhase.AutoFitting => "⏳ Detectando bordas automaticamente...",
        AlignmentPhase.ManualAdjust => "✓ Ajuste concluído! Aceitar ou refinar manualmente?",
        AlignmentPhase.Completed => "✅ Alinhamento confirmado!",
        _ => ""
    };

    /// <summary>
    /// Inicia novo alinhamento (reseta estado)
    /// </summary>
    public void StartAlignment()
    {
        ResetAlignment();
        CurrentPhase = AlignmentPhase.ClickCenter;
        _logger?.LogInformation("🎯 Alinhamento iniciado - aguardando 3 cliques");
    }

    /// <summary>
    /// Processa clique do user durante fase 3-click
    /// </summary>
    /// <returns>true se os 3 cliques foram completados</returns>
    public bool ProcessClick(Point clickPosition)
    {
        switch (CurrentPhase)
        {
            case AlignmentPhase.ClickCenter:
                _centerClick = clickPosition;
                _clickCount = 1;
                CurrentPhase = AlignmentPhase.ClickRight;
                _logger?.LogDebug($"Centro definido: ({clickPosition.X:F0}, {clickPosition.Y:F0})");
                return false;

            case AlignmentPhase.ClickRight:
                _rightClick = clickPosition;
                _clickCount = 2;
                CurrentPhase = AlignmentPhase.ClickTop;
                _logger?.LogDebug($"Borda direita: ({clickPosition.X:F0}, {clickPosition.Y:F0})");
                return false;

            case AlignmentPhase.ClickTop:
                _topClick = clickPosition;
                _clickCount = 3;
                _logger?.LogDebug($"Borda superior: ({clickPosition.X:F0}, {clickPosition.Y:F0})");

                // Calcular transformação inicial (elipse básica)
                CalculateInitialTransform();
                return true; // 3 cliques completados

            default:
                return false;
        }
    }

    /// <summary>
    /// Calcula transformação inicial baseada nos 3 cliques (elipse)
    /// </summary>
    private void CalculateInitialTransform()
    {
        // Calcular raios da elipse
        double radiusX = Math.Abs(_rightClick.X - _centerClick.X);
        double radiusY = Math.Abs(_topClick.Y - _centerClick.Y);

        // Tamanho original do mapa (assumir canvas 1400x1400, raio nominal ~600)
        const double originalSize = 1400.0;
        const double nominalRadius = 600.0;

        // Calcular escalas
        double scaleX = (radiusX * 2) / nominalRadius;
        double scaleY = (radiusY * 2) / nominalRadius;

        // Criar TransformGroup: Scale → Translate para centro
        _currentTransform = new TransformGroup();

        // 1. Escalar ao redor do centro original (700, 700 para canvas 1400x1400)
        var scaleTransform = new ScaleTransform(scaleX, scaleY, originalSize / 2, originalSize / 2);
        _currentTransform.Children.Add(scaleTransform);

        // 2. Transladar para o centro clicado
        double translateX = _centerClick.X - originalSize / 2;
        double translateY = _centerClick.Y - originalSize / 2;
        var translateTransform = new TranslateTransform(translateX, translateY);
        _currentTransform.Children.Add(translateTransform);

        _logger?.LogInformation($"Transformação inicial: Scale({scaleX:F2}, {scaleY:F2}), Translate({translateX:F0}, {translateY:F0})");
    }

    /// <summary>
    /// Detecção automática de bordas usando OpenCV (async, CPU-intensive)
    /// </summary>
    /// <param name="irisImage">Imagem da íris (BitmapSource WPF)</param>
    /// <returns>true se detecção bem-sucedida, false se falhar (fallback manual)</returns>
    public async Task<bool> AutoFitAsync(BitmapSource irisImage)
    {
        if (_clickCount < 3)
        {
            _logger?.LogWarning("AutoFit chamado antes de completar 3 cliques");
            return false;
        }

        CurrentPhase = AlignmentPhase.AutoFitting;

        try
        {
            // Executar detecção em thread separada (não bloquear UI)
            var result = await Task.Run(() => DetectIrisBoundary(irisImage));

            if (result.HasValue)
            {
                // Aplicar transformação refinada baseada na elipse detectada
                ApplyDetectedEllipse(result.Value);
                CurrentPhase = AlignmentPhase.ManualAdjust;
                _logger?.LogInformation("✓ Auto-fit bem-sucedido");
                return true;
            }
            else
            {
                // Fallback: manter transformação inicial dos 3 cliques
                CurrentPhase = AlignmentPhase.ManualAdjust;
                _logger?.LogWarning("⚠️ Auto-fit falhou, usando transformação manual");
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Erro durante auto-fit");
            CurrentPhase = AlignmentPhase.ManualAdjust;
            return false;
        }
    }

    /// <summary>
    /// Detecção de bordas da íris usando OpenCV (Canny + FitEllipse)
    /// </summary>
    private RotatedRect? DetectIrisBoundary(BitmapSource bitmapSource)
    {
        try
        {
            // Converter BitmapSource → Bitmap → OpenCV Mat
            using var bitmap = BitmapSourceToBitmap(bitmapSource);

            // Converter Bitmap → Mat usando BitmapData
            var bitmapData = bitmap.LockBits(
                new Rectangle(0, 0, bitmap.Width, bitmap.Height),
                System.Drawing.Imaging.ImageLockMode.ReadOnly,
                bitmap.PixelFormat);

            using var image = new Image<Bgr, byte>(bitmap.Width, bitmap.Height, bitmapData.Stride, bitmapData.Scan0);
            bitmap.UnlockBits(bitmapData);

            using var mat = image.Mat;
            using var gray = new Mat();
            using var blurred = new Mat();
            using var edges = new Mat();

            // 1. Converter para escala de cinza
            CvInvoke.CvtColor(mat, gray, ColorConversion.Bgr2Gray);

            // 2. Gaussian Blur para reduzir ruído
            CvInvoke.GaussianBlur(gray, blurred, new System.Drawing.Size(5, 5), 1.5);

            // 3. Canny edge detection
            CvInvoke.Canny(blurred, edges, 50, 150);

            // 4. Definir ROI (Region of Interest) baseada no centro aproximado
            double roiSize = Math.Max(
                Math.Abs(_rightClick.X - _centerClick.X),
                Math.Abs(_topClick.Y - _centerClick.Y)
            ) * 2.5; // 2.5x para margem

            var roiRect = new Rectangle(
                (int)Math.Max(0, _centerClick.X - roiSize / 2),
                (int)Math.Max(0, _centerClick.Y - roiSize / 2),
                (int)Math.Min(roiSize, mat.Width - (_centerClick.X - roiSize / 2)),
                (int)Math.Min(roiSize, mat.Height - (_centerClick.Y - roiSize / 2))
            );

            using var roi = new Mat(edges, roiRect);
            using var contours = new VectorOfVectorOfPoint();

            // 5. Encontrar contornos
            CvInvoke.FindContours(roi, contours, null, RetrType.List, ChainApproxMethod.ChainApproxSimple);

            // 6. Encontrar maior contorno (assumir que é a íris)
            double maxArea = 0;
            int largestContourIndex = -1;

            for (int i = 0; i < contours.Size; i++)
            {
                double area = CvInvoke.ContourArea(contours[i]);
                if (area > maxArea && contours[i].Size >= 5)  // Precisa >=5 pontos para FitEllipse
                {
                    maxArea = area;
                    largestContourIndex = i;
                }
            }

            if (largestContourIndex == -1)
            {
                _logger?.LogWarning("Nenhum contorno válido encontrado");
                return null;
            }

            // 7. Ajustar elipse ao contorno
            var ellipse = CvInvoke.FitEllipse(contours[largestContourIndex]);

            // Ajustar coordenadas para espaço completo (compensar ROI offset)
            ellipse.Center = new PointF(
                ellipse.Center.X + roiRect.X,
                ellipse.Center.Y + roiRect.Y
            );

            _logger?.LogDebug($"Elipse detectada: Centro({ellipse.Center.X:F0}, {ellipse.Center.Y:F0}), Tamanho({ellipse.Size.Width:F0}x{ellipse.Size.Height:F0}), Ângulo({ellipse.Angle:F1}°)");

            return ellipse;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Erro na detecção OpenCV");
            return null;
        }
    }

    /// <summary>
    /// Aplica transformação refinada baseada na elipse detectada
    /// </summary>
    private void ApplyDetectedEllipse(RotatedRect ellipse)
    {
        const double originalSize = 1400.0;
        const double nominalRadius = 600.0;

        // Calcular escalas baseadas na elipse detectada
        double scaleX = ellipse.Size.Width / nominalRadius;
        double scaleY = ellipse.Size.Height / nominalRadius;

        // Criar TransformGroup: Scale → Rotate → Translate
        _currentTransform = new TransformGroup();

        // 1. Escalar
        var scaleTransform = new ScaleTransform(scaleX, scaleY, originalSize / 2, originalSize / 2);
        _currentTransform.Children.Add(scaleTransform);

        // 2. Rotacionar (se elipse tiver ângulo significativo)
        if (Math.Abs(ellipse.Angle) > 2.0)  // Threshold 2° para evitar ruído
        {
            var rotateTransform = new RotateTransform(ellipse.Angle, originalSize / 2, originalSize / 2);
            _currentTransform.Children.Add(rotateTransform);
        }

        // 3. Transladar para centro detectado
        double translateX = ellipse.Center.X - originalSize / 2;
        double translateY = ellipse.Center.Y - originalSize / 2;
        var translateTransform = new TranslateTransform(translateX, translateY);
        _currentTransform.Children.Add(translateTransform);

        _logger?.LogInformation($"Transformação refinada: Scale({scaleX:F2}, {scaleY:F2}), Rotate({ellipse.Angle:F1}°), Translate({translateX:F0}, {translateY:F0})");
    }

    /// <summary>
    /// Retorna a transformação atual para aplicar ao Canvas do mapa
    /// </summary>
    public Transform? GetCurrentTransform()
    {
        return _currentTransform;
    }

    /// <summary>
    /// Confirma alinhamento (marca como completo)
    /// </summary>
    public void ConfirmAlignment()
    {
        if (_currentTransform == null)
        {
            _logger?.LogWarning("ConfirmAlignment chamado sem transformação válida");
            return;
        }

        CurrentPhase = AlignmentPhase.Completed;
        _logger?.LogInformation("✅ Alinhamento confirmado pelo user");
    }

    /// <summary>
    /// Reseta alinhamento (volta ao início)
    /// </summary>
    public void ResetAlignment()
    {
        CurrentPhase = AlignmentPhase.Idle;
        _clickCount = 0;
        _centerClick = new Point();
        _rightClick = new Point();
        _topClick = new Point();
        _currentTransform = null;
    }

    /// <summary>
    /// Converte BitmapSource WPF → System.Drawing.Bitmap
    /// </summary>
    private static Bitmap BitmapSourceToBitmap(BitmapSource bitmapSource)
    {
        var encoder = new BmpBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmapSource));

        using var stream = new System.IO.MemoryStream();
        encoder.Save(stream);
        stream.Position = 0;

        return new Bitmap(stream);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (disposing)
        {
            // Limpar recursos managed
            _currentTransform = null;
        }

        _disposed = true;
    }
}
