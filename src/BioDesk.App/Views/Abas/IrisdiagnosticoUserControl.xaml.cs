using System;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using BioDesk.ViewModels.Abas;
using BioDesk.App.Views.Dialogs;
using BioDesk.Domain;
using BioDesk.Domain.Entities;
using BioDesk.App.Dialogs;
using BioDesk.Services;
using BioDesk.Services.Debug;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// Lógica de interação para IrisdiagnosticoUserControl.xaml
/// FASE 3: Inclui dialog de observações + menu contextual para edição de marcas
/// </summary>
public partial class IrisdiagnosticoUserControl : UserControl
{
    private readonly IDragDebugService? _dragDebugService;

    public IrisdiagnosticoUserControl()
    {
        InitializeComponent();

        if (Application.Current is App app && app.ServiceProvider != null)
        {
            _dragDebugService = app.ServiceProvider.GetService<IDragDebugService>();
        }
    }

    /// <summary>
    /// Handler para click no Canvas - mostra dialog e adiciona marca com observações
    /// FASE 4: Integra hit-testing para detectar zona iridológica
    /// </summary>
    private async void MarkingsCanvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
        if (viewModel.IrisImagemSelecionada == null) return;

        // Obter posição do click relativa ao Canvas
        var canvas = sender as Canvas;
        if (canvas == null) return;

        var position = e.GetPosition(canvas);

        // FASE 4: Detectar zona iridológica no clique (se mapa estiver visível)
        if (viewModel.MostrarMapaIridologico)
        {
            viewModel.DetectarZonaNoClique(position.X, position.Y);
        }

        // 1️⃣ Mostrar dialog para capturar observações
        var dialog = new ObservacaoMarcaDialog
        {
            Owner = Window.GetWindow(this) // Centralizar no MainWindow
        };

        if (dialog.ShowDialog() != true)
        {
            // Utilizador cancelou - não adicionar marca
            return;
        }

        // 2️⃣ Chamar comando do ViewModel com observações fornecidas
        await viewModel.AdicionarMarcaCommand.ExecuteAsync((position.X, position.Y, dialog.Observacoes));
    }

    /// <summary>
    /// Handler para mudar cor da marca via menu contextual (FASE 3)
    /// </summary>
    private async void MudarCor_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;

        var menuItem = sender as MenuItem;
        if (menuItem == null) return;

        // Obter marca do DataContext do MenuItem (binding da Grid)
        var marca = menuItem.DataContext as IrisMarca;
        if (marca == null) return;

        // Obter cor do Tag do MenuItem
        var novaCor = menuItem.Tag as string;
        if (string.IsNullOrEmpty(novaCor)) return;

        // Chamar comando do ViewModel
        await viewModel.MudarCorMarcaCommand.ExecuteAsync((marca, novaCor));
    }

    /// <summary>
    /// Handler para editar observações da marca via menu contextual (FASE 3)
    /// </summary>
    private async void EditarObservacoes_Click(object sender, RoutedEventArgs e)
    {
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;

        var menuItem = sender as MenuItem;
        if (menuItem == null) return;

        // Obter marca do DataContext do MenuItem
        var marca = menuItem.DataContext as IrisMarca;
        if (marca == null) return;

        // Mostrar dialog com observações atuais
        var dialog = new EditarObservacaoDialog(marca.Observacoes ?? string.Empty)
        {
            Owner = Window.GetWindow(this)
        };

        if (dialog.ShowDialog() != true)
        {
            // Utilizador cancelou
            return;
        }

        // Atualizar observações
        marca.Observacoes = dialog.Observacoes;
        await viewModel.EditarObservacoesMarcaCommand.ExecuteAsync(marca);
    }

    /// <summary>
    /// Handler para capturar imagem da câmara USB (iridoscópio)
    /// </summary>
    private async void CapturarDaCameraButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            // Obter serviço de câmara do DI
            var app = (App)Application.Current;
            if (app.ServiceProvider == null)
            {
                MessageBox.Show("Serviço de câmara não disponível.", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            var cameraService = app.ServiceProvider.GetRequiredService<ICameraService>();

            // Abrir janela de captura
            var captureWindow = new CameraCaptureWindow(cameraService)
            {
                Owner = Window.GetWindow(this)
            };

            if (captureWindow.ShowDialog() == true && !string.IsNullOrEmpty(captureWindow.CapturedImagePath))
            {
                // Imagem capturada com sucesso! Adicionar à galeria
                if (DataContext is IrisdiagnosticoViewModel viewModel)
                {
                    await viewModel.CarregarImagemCapturadaAsync(captureWindow.CapturedImagePath);
                }
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                $"Erro ao capturar imagem: {ex.Message}",
                "Erro de Captura",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
    }

    // === HANDLERS DE CALIBRAÇÃO ===

    private bool _isDraggingHandler = false;
    private object? _currentHandler = null;

    /// <summary>
    /// Inicia arrasto do handler
    /// </summary>
    private void Handler_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (sender is not FrameworkElement element) return;

        Console.WriteLine($"🎯 DEBUG Handler_MouseDown: Tag={element.Tag?.GetType().Name}, Capture={element.CaptureMouse()}");
        Console.WriteLine($"🧪 Tag FullName: {element.Tag?.GetType().FullName}");
        Console.WriteLine($"🧪 Tag is CalibrationHandler: {element.Tag is IrisdiagnosticoViewModel.CalibrationHandler}");

        _isDraggingHandler = true;
        _currentHandler = element.Tag; // CalibrationHandler do DataContext

        e.Handled = true;
    }

    /// <summary>
    /// Arrasta handler (atualiza posição)
    /// </summary>
    private void Handler_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_isDraggingHandler || _currentHandler == null) return;
        if (sender is not FrameworkElement element) return;
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;

        Console.WriteLine($"🔧 DEBUG Handler_MouseMove: Dragging={_isDraggingHandler}, Handler={_currentHandler?.GetType().Name}");

        // 🔧 FIX: Usar HandlersCanvas diretamente (nomeado no XAML) em vez de element.Parent
        // ItemsControl não define Parent corretamente, causava canvas = null
        var position = e.GetPosition(HandlersCanvas);
        Console.WriteLine($"� DEBUG MousePosition: ({position.X:F2}, {position.Y:F2})");

        // Atualizar posição do handler
        if (_currentHandler is IrisdiagnosticoViewModel.CalibrationHandler handler)
        {
            handler.X = position.X - 8; // -8 para centralizar ellipse 16x16
            handler.Y = position.Y - 8;

            Console.WriteLine($"📍 POSITION UPDATE: X={handler.X:F2}, Y={handler.Y:F2}, MousePos=({position.X:F2}, {position.Y:F2})");

            // Recalcular raio baseado na nova posição
            double centroX = handler.Tipo == "Pupila" ? viewModel.CentroPupilaX : viewModel.CentroIrisX;
            double centroY = handler.Tipo == "Pupila" ? viewModel.CentroPupilaY : viewModel.CentroIrisY;

            double novoRaio = Math.Sqrt(Math.Pow(position.X - centroX, 2) + Math.Pow(position.Y - centroY, 2));

            if (handler.Tipo == "Pupila")
            {
                viewModel.RaioPupila = novoRaio;
            }
            else
            {
                viewModel.RaioIris = novoRaio;
            }

            // TODO: Implementar deformação local (apenas na área de influência do handler)
            // Por agora, atualiza todos os handlers do mesmo círculo uniformemente

            // Recalcular polígonos
            viewModel.RecalcularPoligonosComDeformacao();
        }

        e.Handled = true;
    }

    /// <summary>
    /// Finaliza arrasto do handler
    /// </summary>
    private void Handler_MouseUp(object sender, MouseButtonEventArgs e)
    {
        if (!_isDraggingHandler) return;
        if (sender is not FrameworkElement element) return;

        _isDraggingHandler = false;
        _currentHandler = null;
        element.ReleaseMouseCapture();

        // 🔧 FIX: NÃO reinicializar handlers - mantém posição manual do arrasto
        // (InicializarHandlers() resetava para círculo perfeito, perdendo ajuste manual)

        e.Handled = true;
    }

    // === HANDLERS DE CENTRO (STUB - não usados) ===

    private void CentroHandler_MouseDown(object sender, MouseButtonEventArgs e) { }
    private void CentroHandler_MouseMove(object sender, MouseEventArgs e) { }
    private void CentroHandler_MouseUp(object sender, MouseButtonEventArgs e) { }

    private void TrackDragEvent(
        DragDebugEventType type,
        string message,
        Dictionary<string, double>? metrics = null,
        Dictionary<string, string>? context = null)
    {
        if (_dragDebugService == null)
        {
            return;
        }

        try
        {
            _dragDebugService.RecordEvent(type, message, metrics, context);
        }
        catch
        {
            // Ignorar exceptions de logging para não afetar o fluxo do UI.
        }
    }

    private static Dictionary<string, double> BuildCentroMetrics(IrisdiagnosticoViewModel viewModel)
    {
        return new Dictionary<string, double>
        {
            ["centroPupilaX"] = viewModel.CentroPupilaX,
            ["centroPupilaY"] = viewModel.CentroPupilaY,
            ["raioPupila"] = viewModel.RaioPupila,
            ["centroIrisX"] = viewModel.CentroIrisX,
            ["centroIrisY"] = viewModel.CentroIrisY,
            ["raioIris"] = viewModel.RaioIris
        };
    }

    private static Dictionary<string, string> BuildContext(IrisdiagnosticoViewModel viewModel, string? modo = null)
    {
        var context = new Dictionary<string, string>
        {
            ["modoCalibracaoAtivo"] = viewModel.ModoCalibracaoAtivo.ToString(),
            ["modoMoverMapa"] = viewModel.ModoMoverMapa.ToString(),
            ["tipoCalibracaoPupila"] = viewModel.TipoCalibracaoPupila.ToString(),
            ["tipoCalibracaoIris"] = viewModel.TipoCalibracaoIris.ToString(),
            ["tipoCalibracaoAmbos"] = viewModel.TipoCalibracaoAmbos.ToString(),
            ["mostrarMapaIridologico"] = viewModel.MostrarMapaIridologico.ToString()
        };

        if (!string.IsNullOrWhiteSpace(modo))
        {
            context["modo"] = modo;
        }

        if (viewModel.IrisImagemSelecionada != null)
        {
            context["imagemId"] = viewModel.IrisImagemSelecionada.Id.ToString();
            context["olho"] = viewModel.IrisImagemSelecionada.Olho ?? string.Empty;
        }

        return context;
    }

    // === HANDLERS DE DRAG DO MAPA ===

    private bool _isDraggingMapa = false;
    private Point _ultimaPosicaoMapa;

    /// <summary>
    /// Inicia arrasto do mapa overlay
    /// </summary>
    private void MapaOverlayCanvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (HandlersCanvas == null) return;
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
        if (!viewModel.ModoCalibracaoAtivo && !viewModel.ModoMoverMapa) return;

        // ⭐ Iniciar sessão de drag (previne renderizações intermédias)
        viewModel.BeginDrag();

        _isDraggingMapa = true;
        _ultimaPosicaoMapa = GetMapaPositionRelativeToHandlers(e);
        var modo = viewModel.ModoMoverMapa ? "MoverMapa" : "Calibracao";

        var metrics = BuildCentroMetrics(viewModel);
        metrics["mouseX"] = _ultimaPosicaoMapa.X;
        metrics["mouseY"] = _ultimaPosicaoMapa.Y;

        TrackDragEvent(
            DragDebugEventType.DragStart,
            "MouseDown mapa overlay",
            metrics,
            BuildContext(viewModel, modo));

        MapaOverlayCanvas.CaptureMouse();
        e.Handled = true;
    }

    /// <summary>
    /// Arrasta mapa overlay (translada handlers)
    /// </summary>
    private void MapaOverlayCanvas_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_isDraggingMapa) return;
        if (HandlersCanvas == null) return;
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;

        var current = GetMapaPositionRelativeToHandlers(e);

        double deltaX = current.X - _ultimaPosicaoMapa.X;
        double deltaY = current.Y - _ultimaPosicaoMapa.Y;

        // Detectar inversão Y (ScaleY=-1 no RenderTransform)
        double scaleY = 1.0;
        if (MapaOverlayCanvas?.RenderTransform is Transform renderTransform)
        {
            var matrix = renderTransform.Value;
            scaleY = matrix.M22; // ScaleY component

            // Se ScaleY negativo, inverter deltaY para movimento intuitivo
            if (scaleY < 0)
            {
                deltaY = -deltaY;
            }
        }

        // Determinar tipo de calibração ativa
        var tipo = viewModel.ModoMoverMapa
            ? "Ambos"
            : viewModel.TipoCalibracaoAmbos
                ? "Ambos"
                : viewModel.TipoCalibracaoIris ? "Iris" : "Pupila";

        var metricsPre = BuildCentroMetrics(viewModel);
        metricsPre["mouseX"] = current.X;
        metricsPre["mouseY"] = current.Y;
        metricsPre["deltaX"] = deltaX;
        metricsPre["deltaY"] = deltaY;
        metricsPre["scaleY"] = scaleY;

        TrackDragEvent(
            DragDebugEventType.DragMovePreTransform,
            "MouseMove (pré-translação)",
            metricsPre,
            BuildContext(viewModel, tipo));

        // Transladar calibração
        viewModel.TransladarCalibracao(tipo, deltaX, deltaY);

        var metricsPost = BuildCentroMetrics(viewModel);
        metricsPost["mouseX"] = current.X;
        metricsPost["mouseY"] = current.Y;
        metricsPost["deltaX"] = deltaX;
        metricsPost["deltaY"] = deltaY;

        TrackDragEvent(
            DragDebugEventType.DragMovePostTransform,
            "MouseMove (pós-translação)",
            metricsPost,
            BuildContext(viewModel, tipo));

        _ultimaPosicaoMapa = current;
        e.Handled = true;
    }

    /// <summary>
    /// Finaliza arrasto do mapa
    /// </summary>
    private void MapaOverlayCanvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (!_isDraggingMapa) return;

        if (DataContext is IrisdiagnosticoViewModel viewModel)
        {
            TrackDragEvent(
                DragDebugEventType.DragEnd,
                "MouseUp mapa overlay",
                BuildCentroMetrics(viewModel),
                BuildContext(viewModel));

            // ⭐ Finalizar sessão de drag (força renderização final)
            viewModel.EndDrag();
        }

        _isDraggingMapa = false;
        MapaOverlayCanvas.ReleaseMouseCapture();
        e.Handled = true;
    }

    /// <summary>
    /// Converte posição do mouse de MapaOverlayCanvas para HandlersCanvas
    /// </summary>
    private Point GetMapaPositionRelativeToHandlers(MouseEventArgs e)
    {
        if (MapaOverlayCanvas == null || HandlersCanvas == null)
            return new Point(0, 0);

        var canvasPoint = e.GetPosition(MapaOverlayCanvas);
        var transform = MapaOverlayCanvas.TransformToVisual(HandlersCanvas);
        var handlerPoint = transform.Transform(canvasPoint);

        Dictionary<string, string>? context = null;
        if (DataContext is IrisdiagnosticoViewModel viewModel)
        {
            context = BuildContext(viewModel);
        }

        TrackDragEvent(
            DragDebugEventType.CoordinateTransform,
            "TransformToVisual (Mapa → Handlers)",
            new Dictionary<string, double>
            {
                ["canvasX"] = canvasPoint.X,
                ["canvasY"] = canvasPoint.Y,
                ["handlerX"] = handlerPoint.X,
                ["handlerY"] = handlerPoint.Y
            },
            context);

        return handlerPoint;
    }

    /// <summary>
    /// Reset ao soltar mouse fora
    /// </summary>
    private void MapaOverlayCanvas_MouseLeave(object sender, MouseEventArgs e)
    {
        if (_isDraggingMapa)
        {
            _isDraggingMapa = false;
            MapaOverlayCanvas.ReleaseMouseCapture();
        }
    }
}
