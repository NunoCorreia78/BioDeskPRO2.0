using System;
using System.IO;
using System.Linq;  // ✅ ADICIONADO para LINQ (Select, etc.)
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using BioDesk.ViewModels.Abas;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// UserControl para Aba 2: Declaração de Saúde
/// Contém formulário completo de histórico médico e estilo de vida
/// </summary>
public partial class DeclaracaoSaudeUserControl : UserControl
{
    private bool _isDrawing = false;
    private bool _hasSignature = false;
    private Polyline? _currentStroke = null;

    public DeclaracaoSaudeUserControl()
    {
        InitializeComponent();
        Loaded += OnLoaded;

        // Configura o DataContext através do DI container
        if (Application.Current is App app && app.ServiceProvider != null)
        {
            DataContext = app.ServiceProvider.GetRequiredService<DeclaracaoSaudeViewModel>();
        }

        // Configura data atual no TextBox
        TxtDataDeclaracao.Text = DateTime.Now.ToString("dd/MM/yyyy");
    }

    private void OnLoaded(object sender, RoutedEventArgs e)
    {
        // Subscrever eventos de mudança em todos os controles
        SubscribeToControlChanges(this);
    }

    /// <summary>
    /// Subscrever recursivamente a mudanças em TextBox, ComboBox e CheckBox
    /// para marcar formulário como "dirty" (IsDirty = true)
    /// </summary>
    private void SubscribeToControlChanges(DependencyObject parent)
    {
        int childCount = System.Windows.Media.VisualTreeHelper.GetChildrenCount(parent);
        for (int i = 0; i < childCount; i++)
        {
            var child = System.Windows.Media.VisualTreeHelper.GetChild(parent, i);

            if (child is TextBox textBox)
            {
                textBox.TextChanged -= OnControlValueChanged;
                textBox.TextChanged += OnControlValueChanged;
            }
            else if (child is ComboBox comboBox)
            {
                comboBox.SelectionChanged -= OnControlValueChanged;
                comboBox.SelectionChanged += OnControlValueChanged;
            }
            else if (child is CheckBox checkBox)
            {
                checkBox.Checked -= OnControlValueChanged;
                checkBox.Unchecked -= OnControlValueChanged;
                checkBox.Checked += OnControlValueChanged;
                checkBox.Unchecked += OnControlValueChanged;
            }

            // Recursivo para filhos
            SubscribeToControlChanges(child);
        }
    }

    /// <summary>
    /// Marcar formulário como alterado (IsDirty = true)
    /// </summary>
    private void OnControlValueChanged(object sender, RoutedEventArgs e)
    {
        // Obter o ViewModel principal da FichaPaciente
        var window = Window.GetWindow(this);
        if (window?.DataContext is BioDesk.ViewModels.FichaPacienteViewModel viewModel)
        {
            viewModel.MarcarComoAlterado();
        }
    }

    // ===== ASSINATURA DIGITAL =====

    // ===== MOUSE EVENTS (Mouse tradicional) =====
    private void AssinaturaCanvas_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed && e.StylusDevice == null)
        {
            System.Diagnostics.Debug.WriteLine("🖱️ MOUSE DOWN detectado!"); // DEBUG
            IniciarDesenho(e.GetPosition(AssinaturaCanvasDeclaracao));
        }
        else if (e.StylusDevice != null)
        {
            System.Diagnostics.Debug.WriteLine("🖱️ MOUSE DOWN ignorado (é stylus)"); // DEBUG
        }
    }

    private void AssinaturaCanvas_MouseMove(object sender, MouseEventArgs e)
    {
        if (_isDrawing && _currentStroke != null && e.LeftButton == MouseButtonState.Pressed && e.StylusDevice == null)
        {
            Point currentPoint = e.GetPosition(AssinaturaCanvasDeclaracao);
            _currentStroke.Points.Add(currentPoint);
        }
    }

    private void AssinaturaCanvas_MouseUp(object sender, MouseButtonEventArgs e)
    {
        if (e.StylusDevice == null)
        {
            FinalizarDesenho();
        }
    }

    private void AssinaturaCanvas_MouseLeave(object sender, MouseEventArgs e)
    {
        if (_isDrawing && e.StylusDevice == null)
        {
            FinalizarDesenho();
        }
    }

    // ===== STYLUS EVENTS (Wacom / Canetas digitais) =====
    private void AssinaturaCanvas_StylusDown(object sender, StylusDownEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🖊️ STYLUS DOWN detectado!"); // DEBUG
        IniciarDesenho(e.GetPosition(AssinaturaCanvasDeclaracao));
        e.Handled = true; // Prevenir que dispare MouseDown também
    }

    private void AssinaturaCanvas_StylusMove(object sender, StylusEventArgs e)
    {
        if (_isDrawing && _currentStroke != null)
        {
            StylusPointCollection points = e.GetStylusPoints(AssinaturaCanvasDeclaracao);
            System.Diagnostics.Debug.WriteLine($"🖊️ STYLUS MOVE - {points.Count} pontos"); // DEBUG
            foreach (StylusPoint sp in points)
            {
                _currentStroke.Points.Add(new Point(sp.X, sp.Y));
            }
            e.Handled = true;
        }
    }

    private void AssinaturaCanvas_StylusUp(object sender, StylusEventArgs e)
    {
        System.Diagnostics.Debug.WriteLine("🖊️ STYLUS UP detectado!"); // DEBUG
        FinalizarDesenho();
        e.Handled = true;
    }

    // ===== MÉTODOS AUXILIARES =====
    private void IniciarDesenho(Point startPoint)
    {
        _isDrawing = true;
        _hasSignature = true;

        // Oculta as instruções
        AssinaturaInstrucoesDeclaracao.Visibility = Visibility.Collapsed;

        // ✅ CAPTURAR MOUSE/STYLUS ANTES de criar stroke
        AssinaturaCanvasDeclaracao.CaptureStylus();
        AssinaturaCanvasDeclaracao.CaptureMouse();

        // Cria nova linha
        _currentStroke = new Polyline
        {
            Stroke = Brushes.Black,
            StrokeThickness = 2,
            StrokeLineJoin = PenLineJoin.Round,
            StrokeStartLineCap = PenLineCap.Round,
            StrokeEndLineCap = PenLineCap.Round
        };

        _currentStroke.Points.Add(startPoint);
        AssinaturaCanvasDeclaracao.Children.Add(_currentStroke);
    }

    private void FinalizarDesenho()
    {
        if (_isDrawing)
        {
            _isDrawing = false;
            _currentStroke = null;
            AssinaturaCanvasDeclaracao.ReleaseStylusCapture();
            AssinaturaCanvasDeclaracao.ReleaseMouseCapture();
        }
    }

    private void BtnLimparAssinatura_Click(object sender, RoutedEventArgs e)
    {
        AssinaturaCanvasDeclaracao.Children.Clear();
        AssinaturaInstrucoesDeclaracao.Visibility = Visibility.Visible;
        _hasSignature = false;
        TxtMensagemAssinatura.Visibility = Visibility.Collapsed;
    }

    private void BtnConfirmarDeclaracao_Click(object sender, RoutedEventArgs e)
    {
        // Validações
        if (string.IsNullOrWhiteSpace(TxtNomePacienteDeclaracao.Text))
        {
            MessageBox.Show("Por favor, insira o nome completo do paciente.",
                "Campo Obrigatório", MessageBoxButton.OK, MessageBoxImage.Warning);
            TxtNomePacienteDeclaracao.Focus();
            return;
        }

        if (!_hasSignature)
        {
            MessageBox.Show("Por favor, assine a declaração para confirmar.",
                "Assinatura Obrigatória", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(TxtDataDeclaracao.Text))
        {
            MessageBox.Show("Por favor, preencha a data da declaração.",
                "Campo Obrigatório", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Confirma a declaração
        TxtMensagemAssinatura.Text = $"✅ Declaração confirmada em {TxtDataDeclaracao.Text} por {TxtNomePacienteDeclaracao.Text}";
        TxtMensagemAssinatura.Visibility = Visibility.Visible;

        MessageBox.Show("Declaração de Saúde confirmada com sucesso!\n\nA assinatura digital foi registada.",
            "Declaração Confirmada", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void BtnGerarPdfDeclaracao_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // 🛡️ VALIDAÇÕES OBRIGATÓRIAS
            if (string.IsNullOrWhiteSpace(TxtNomePacienteDeclaracao.Text))
            {
                MessageBox.Show("Por favor, insira o nome completo do paciente.",
                    "Campo Obrigatório", MessageBoxButton.OK, MessageBoxImage.Warning);
                TxtNomePacienteDeclaracao.Focus();
                return;
            }

            if (!_hasSignature)
            {
                MessageBox.Show("Por favor, assine a declaração antes de gerar o PDF.",
                    "Assinatura Obrigatória", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // 📸 Capturar assinatura do canvas como PNG Base64
            string assinaturaPacienteBase64 = CapturarAssinaturaCanvas();
            if (string.IsNullOrEmpty(assinaturaPacienteBase64))
            {
                MessageBox.Show("Erro ao capturar a assinatura do canvas.",
                    "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // 🏥 Obter DeclaracaoSaudePdfService do DI
            if (Application.Current is not App app || app.ServiceProvider == null)
            {
                MessageBox.Show("Erro ao acessar serviços da aplicação.",
                    "Erro Interno", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var pdfService = app.ServiceProvider.GetRequiredService<BioDesk.Services.Pdf.DeclaracaoSaudePdfService>();

            // ✅ CORRIGIDO: Pegar dados REAIS do ViewModel
            var viewModel = DataContext as DeclaracaoSaudeViewModel;

            // 📋 Preparar dados da declaração
            var dadosDeclaracao = new BioDesk.Services.Pdf.DadosDeclaracaoSaude
            {
                NomePaciente = viewModel?.NomePaciente ?? "Paciente",
                NomeTerapeuta = "Nuno Correia", // ✅ ADICIONADO: Nome do terapeuta
                DataDeclaracao = DateTime.Now,
                AssinaturaPacienteBase64 = assinaturaPacienteBase64,
                AssinaturaTerapeutaPath = System.IO.Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Resources", "assinatura_terapeuta.png"),

                // ✅ CORRIGIDO: Secções com dados REAIS do questionário
                MotivoConsulta = viewModel != null
                    ? $"Consulta de saúde integrativa. Paciente: {viewModel.NomePaciente}"
                    : string.Empty,

                HistoriaClinica = viewModel != null
                    ? $"Doenças Crónicas:\n" +
                      $"• Diabetes: {(viewModel.TemDiabetes ? "Sim" : "Não")}\n" +
                      $"• Hipertensão: {(viewModel.TemHipertensao ? "Sim" : "Não")}\n" +
                      $"• Cardiopatias: {(viewModel.TemCardiopatias ? "Sim" : "Não")}" +
                      (viewModel.TemOutrasDoencas ? $"\n• Outras: {viewModel.EspecificacaoOutrasDoencas}" : "")
                    : string.Empty,

                MedicacaoAtual = viewModel != null && viewModel.MedicamentosAtuais.Any()
                    ? "• " + string.Join("\n• ", viewModel.MedicamentosAtuais.Select(m => $"{m.Nome} ({m.Dosagem}) - {m.Frequencia}"))
                    : string.Empty,

                Alergias = viewModel != null && viewModel.AlergiasMedicamentosas.Any()
                    ? "• " + string.Join("\n• ", viewModel.AlergiasMedicamentosas.Select(a => $"{a.Medicamento} (Severidade: {a.Severidade})"))
                    : string.Empty,

                EstiloVida = viewModel != null
                    ? $"• Tabagismo: {viewModel.Tabagismo}\n" +
                      $"• Consumo de Álcool: {viewModel.ConsumoAlcool}\n" +
                      $"• Exercício Físico: {viewModel.ExercicioFisico}\n" +
                      $"• Horas de Sono: {viewModel.HorasSono}h/noite ({viewModel.QualidadeSono})\n" +
                      $"• Tipo de Dieta: {viewModel.TipoDieta}"
                    : string.Empty,

                HistoriaFamiliar = viewModel != null && viewModel.HistoriaFamiliar.Any()
                    ? "• " + string.Join("\n• ", viewModel.HistoriaFamiliar.Select(h =>
                        $"{h.GrauParentesco}: {h.CondicaoDoenca}" +
                        (h.IdadeDiagnostico.HasValue ? $" (Idade diagnóstico: {h.IdadeDiagnostico})" : "")))
                    : string.Empty,

                // ✅ DADOS ADICIONAIS - FILTRAR registos vazios E usar formato flexível de data
                DadosCirurgias = viewModel != null && viewModel.Cirurgias.Any(c => c.Data.Year > 1)
                    ? string.Join("\n", viewModel.Cirurgias
                        .Where(c => c.Data.Year > 1)
                        .Select(c =>
                        {
                            // Formatar data de forma flexível
                            string dataFormatada;
                            if (c.Data.Day == 1 && c.Data.Month == 1)
                                dataFormatada = c.Data.ToString("yyyy");
                            else if (c.Data.Day == 1)
                                dataFormatada = c.Data.ToString("MM/yyyy");
                            else
                                dataFormatada = c.Data.ToString("dd/MM/yyyy");

                            return $"• {c.TipoCirurgia} ({dataFormatada})" +
                                   (!string.IsNullOrEmpty(c.Observacoes) ? $" - {c.Observacoes}" : "");
                        }))
                    : string.Empty,

                DadosHospitalizacoes = viewModel != null && viewModel.Hospitalizacoes.Any(h => h.Data.Year > 1)
                    ? string.Join("\n", viewModel.Hospitalizacoes
                        .Where(h => h.Data.Year > 1)
                        .Select(h =>
                        {
                            // Formatar data de forma flexível
                            string dataFormatada;
                            if (h.Data.Day == 1 && h.Data.Month == 1)
                                dataFormatada = h.Data.ToString("yyyy");
                            else if (h.Data.Day == 1)
                                dataFormatada = h.Data.ToString("MM/yyyy");
                            else
                                dataFormatada = h.Data.ToString("dd/MM/yyyy");

                            return $"• {h.Motivo} ({dataFormatada})" +
                                   (h.DuracaoDias > 0 ? $" - {h.DuracaoDias} dias" : "");
                        }))
                    : string.Empty,

                DadosMedicamentosAtuais = viewModel != null && viewModel.MedicamentosAtuais.Any(m => m.DesdeQuando.Year > 1)
                    ? "• " + string.Join("\n• ", viewModel.MedicamentosAtuais
                        .Where(m => m.DesdeQuando.Year > 1) // ✅ Filtrar registos com data padrão
                        .Select(m =>
                            $"{m.Nome} ({m.Dosagem}) - {m.Frequencia} (desde {m.DesdeQuando:dd/MM/yyyy})"))
                    : string.Empty,

                DadosAlergiasDetalhadas = viewModel != null && viewModel.AlergiasMedicamentosas.Any()
                    ? "• " + string.Join("\n• ", viewModel.AlergiasMedicamentosas.Select(a =>
                        $"{a.Medicamento}: {a.Severidade}" +
                        (!string.IsNullOrEmpty(a.Reacao) ? $" - Reação: {a.Reacao}" : "")))
                    : string.Empty,

                DadosIntoleranciaAlimentar = viewModel != null && viewModel.IntoleranciasAlimentares.Any()
                    ? "• " + string.Join("\n• ", viewModel.IntoleranciasAlimentares.Select(i =>
                        $"{i.Alimento}" +
                        (!string.IsNullOrEmpty(i.Sintomas) ? $" - {i.Sintomas}" : "")))
                    : string.Empty,

                DadosDoencasCronicas = viewModel != null
                    ? $"• Diabetes: {(viewModel.TemDiabetes ? "Sim" : "Não")}\n" +
                      $"• Hipertensão: {(viewModel.TemHipertensao ? "Sim" : "Não")}\n" +
                      $"• Cardiopatias: {(viewModel.TemCardiopatias ? "Sim" : "Não")}" +
                      (viewModel.TemOutrasDoencas ? $"\n• Outras: {viewModel.EspecificacaoOutrasDoencas}" : "")
                    : string.Empty,

                ObservacoesAdicionais = viewModel?.ObservacoesAdicionais ?? string.Empty
            };

            // 📄 Gerar PDF
            string caminhoCompletoPdf = pdfService.GerarPdfDeclaracaoSaude(dadosDeclaracao);

            // ✅ Sucesso
            MessageBox.Show($"✅ PDF da Declaração de Saúde gerado com sucesso!\n\n📁 Localização:\n{caminhoCompletoPdf}",
                "PDF Gerado", MessageBoxButton.OK, MessageBoxImage.Information);

            // Perguntar se quer abrir o PDF
            var resultado = MessageBox.Show("Deseja abrir o PDF agora?",
                "Abrir PDF", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (resultado == MessageBoxResult.Yes && File.Exists(caminhoCompletoPdf))
            {
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = caminhoCompletoPdf,
                    UseShellExecute = true
                });
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"❌ ERRO ao gerar PDF da Declaração de Saúde:\n\n{ex.Message}\n\nDetalhes: {ex.StackTrace}",
                "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// Captura o conteúdo do canvas de assinatura como PNG Base64
    /// </summary>
    private string CapturarAssinaturaCanvas()
    {
        try
        {
            if (AssinaturaCanvasDeclaracao.Children.Count == 0)
            {
                return string.Empty;
            }

            // Criar bitmap com resolução do canvas
            var renderBitmap = new RenderTargetBitmap(
                (int)AssinaturaCanvasDeclaracao.ActualWidth,
                (int)AssinaturaCanvasDeclaracao.ActualHeight,
                96, // DPI horizontal
                96, // DPI vertical
                PixelFormats.Pbgra32);

            // Renderizar canvas no bitmap
            renderBitmap.Render(AssinaturaCanvasDeclaracao);

            // Codificar como PNG
            var encoder = new PngBitmapEncoder();
            encoder.Frames.Add(BitmapFrame.Create(renderBitmap));

            // Converter para Base64
            using (var memoryStream = new MemoryStream())
            {
                encoder.Save(memoryStream);
                byte[] imageBytes = memoryStream.ToArray();
                return Convert.ToBase64String(imageBytes);
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro ao capturar assinatura: {ex.Message}",
                "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
            return string.Empty;
        }
    }
}
