using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace BioDesk.App.Controls
{
    /// <summary>
    /// UserControl reutilizável para captura de assinatura digital
    /// Converte assinatura para imagem PNG em Base64
    /// </summary>
    public partial class SignatureCanvasControl : UserControl
    {
        private bool _isDrawing = false;
        private bool _hasSignature = false;
        private Polyline? _currentStroke = null;

        // Evento que dispara quando a assinatura é confirmada
        public event EventHandler<SignatureConfirmedEventArgs>? SignatureConfirmed;

        public SignatureCanvasControl()
        {
            InitializeComponent();
        }

        #region === MOUSE EVENTS (DESENHO) ===

        private void AssinaturaCanvas_MouseDown(object sender, MouseButtonEventArgs e)
        {
            if (e.LeftButton == MouseButtonState.Pressed)
            {
                _isDrawing = true;
                AssinaturaInstrucoes.Visibility = Visibility.Collapsed;
                AssinaturaCanvas.CaptureMouse();

                // Iniciar novo traço
                _currentStroke = new Polyline
                {
                    Stroke = new SolidColorBrush(Color.FromRgb(63, 74, 61)), // #3F4A3D (cor terroso)
                    StrokeThickness = 2.5,
                    StrokeLineJoin = PenLineJoin.Round,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round
                };

                Point startPoint = e.GetPosition(AssinaturaCanvas);
                _currentStroke.Points.Add(startPoint);
                AssinaturaCanvas.Children.Add(_currentStroke);
            }
        }

        private void AssinaturaCanvas_MouseMove(object sender, MouseEventArgs e)
        {
            if (_isDrawing && e.LeftButton == MouseButtonState.Pressed && _currentStroke != null)
            {
                Point currentPoint = e.GetPosition(AssinaturaCanvas);
                _currentStroke.Points.Add(currentPoint);

                if (!_hasSignature)
                {
                    _hasSignature = true;
                    BtnConfirmar.IsEnabled = true;
                }
            }
        }

        private void AssinaturaCanvas_MouseUp(object sender, MouseButtonEventArgs e)
        {
            _isDrawing = false;
            AssinaturaCanvas.ReleaseMouseCapture();
            _currentStroke = null;
        }

        #endregion

        #region === BOTÕES ===

        private void BtnLimpar_Click(object sender, RoutedEventArgs e)
        {
            LimparAssinatura();
        }

        private void BtnConfirmar_Click(object sender, RoutedEventArgs e)
        {
            if (_hasSignature)
            {
                // Capturar assinatura como imagem Base64
                string assinaturaBase64 = CapturarAssinaturaComoImagem();

                if (!string.IsNullOrEmpty(assinaturaBase64))
                {
                    // Disparar evento com a assinatura capturada
                    SignatureConfirmed?.Invoke(this, new SignatureConfirmedEventArgs(assinaturaBase64));

                    // Mostrar mensagem de sucesso
                    MessageBox.Show(
                        "✅ Assinatura capturada com sucesso!\n\nA assinatura será incluída no documento PDF.",
                        "✅ Assinatura Confirmada",
                        MessageBoxButton.OK,
                        MessageBoxImage.Information);

                    // Limpar canvas após confirmação
                    LimparAssinatura();
                }
                else
                {
                    MessageBox.Show(
                        "❌ Erro ao capturar assinatura.\n\nPor favor, tente novamente.",
                        "Erro de Captura",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
            }
            else
            {
                MessageBox.Show(
                    "⚠️ Por favor, assine no campo acima antes de confirmar.",
                    "Assinatura Necessária",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        #endregion

        #region === MÉTODOS PÚBLICOS ===

        /// <summary>
        /// Limpa o canvas de assinatura
        /// </summary>
        public void LimparAssinatura()
        {
            AssinaturaCanvas.Children.Clear();
            AssinaturaInstrucoes.Visibility = Visibility.Visible;
            _hasSignature = false;
            BtnConfirmar.IsEnabled = false;
            _currentStroke = null;
        }

        /// <summary>
        /// Verifica se há assinatura no canvas
        /// </summary>
        public bool TemAssinatura()
        {
            return _hasSignature;
        }

        #endregion

        #region === CAPTURA DE IMAGEM ===

        /// <summary>
        /// Captura a assinatura do canvas e converte para Base64 (PNG)
        /// </summary>
        private string CapturarAssinaturaComoImagem()
        {
            try
            {
                // Verificar se canvas tem tamanho válido
                if (AssinaturaCanvas.ActualWidth <= 0 || AssinaturaCanvas.ActualHeight <= 0)
                {
                    return string.Empty;
                }

                // Criar bitmap com resolução do canvas
                var renderBitmap = new RenderTargetBitmap(
                    (int)AssinaturaCanvas.ActualWidth,
                    (int)AssinaturaCanvas.ActualHeight,
                    96, // DPI horizontal
                    96, // DPI vertical
                    PixelFormats.Pbgra32);

                // Renderizar canvas no bitmap
                renderBitmap.Render(AssinaturaCanvas);

                // Codificar como PNG
                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(renderBitmap));

                // Converter para Base64
                using (var memoryStream = new MemoryStream())
                {
                    encoder.Save(memoryStream);
                    byte[] imageBytes = memoryStream.ToArray();
                    string base64String = Convert.ToBase64String(imageBytes);
                    return base64String;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    $"❌ Erro ao capturar assinatura como imagem:\n\n{ex.Message}",
                    "Erro de Captura",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                return string.Empty;
            }
        }

        #endregion
    }

    /// <summary>
    /// Argumentos do evento SignatureConfirmed
    /// </summary>
    public class SignatureConfirmedEventArgs : EventArgs
    {
        public string SignatureBase64 { get; }

        public SignatureConfirmedEventArgs(string signatureBase64)
        {
            SignatureBase64 = signatureBase64;
        }
    }
}
