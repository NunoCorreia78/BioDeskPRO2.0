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

        // ✅ CRÍTICO: Libertar mouse capture quando UserControl fica invisível
        // Resolve bug onde manipulação da íris bloqueia cliques em outras abas
        this.IsVisibleChanged += IrisdiagnosticoUserControl_IsVisibleChanged;
    }

    /// <summary>
    /// ✅ NOVO: Handler para cliques no MapaOverlayCanvas (Sistema Infalível de 3 cliques)
    /// Processa os 3 cliques necessários para alinhamento do overlay (Centro → Direita → Topo)
    /// </summary>
    private void MapaOverlayCanvas_Click(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is IrisdiagnosticoViewModel vm)
        {
            var clickPosition = e.GetPosition(MapaOverlayCanvas);
            vm.ProcessOverlayClick(clickPosition);
        }
    }

    /// <summary>
    /// ✅ CORREÇÃO CRÍTICA: Reset completo quando UserControl fica invisível
    /// Previne que Canvas capturado bloqueie cliques em outras abas
    /// </summary>
    private void IrisdiagnosticoUserControl_IsVisibleChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        // Quando fica invisível, libertar TODOS os captures
        if (this.Visibility != Visibility.Visible)
        {
            // Reset estado de desenho
            if (_isDrawing)
            {
                _isDrawing = false;
                if (DesenhoCanvas != null)
                {
                    DesenhoCanvas.ReleaseMouseCapture();
                }
            }

            // ✅ Libertar capture de QUALQUER elemento que possa estar capturado
            // Força WPF a limpar o estado global de mouse capture
            if (Mouse.Captured != null)
            {
                Mouse.Capture(null);
            }
        }
    }

    /// <summary>
    /// Handler para click no Canvas - mostra dialog e adiciona marca com observações
    /// FASE 4: Integra hit-testing para detectar zona iridológica
    /// FASE 5: Integra sistema de marcação por 8 pontos cardeais
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

        // Salvar na BD via ViewModel
        await viewModel.AtualizarObservacoesMarcaAsync(marca);
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
                // ✅ CORREÇÃO CRÍTICA 6: Definir olho selecionado ANTES de carregar imagem
                // Previne problema de não conseguir selecionar olho após captura
                if (DataContext is IrisdiagnosticoViewModel viewModel)
                {
                    viewModel.OlhoSelecionado = captureWindow.OlhoSelecionado;
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

    // === EVENT HANDLERS PARA FERRAMENTA DE DESENHO ===

    /// <summary>
    /// Handler para mudança de cor no desenho
    /// </summary>
    private void CorDesenho_Checked(object sender, RoutedEventArgs e)
    {
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
        if (sender is not RadioButton radioButton) return;
        if (radioButton.Tag is not string cor) return;

        viewModel.CorDesenho = cor;
    }

    /// <summary>
    /// Handler para mudança de espessura no desenho
    /// </summary>
    private void EspessuraDesenho_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
        viewModel.EspessuraDesenho = e.NewValue;
    }

    // Estado para captura do stroke atual
    private bool _isDrawing = false;
    private BioDesk.Domain.Models.StrokeModel? _currentStroke;

    /// <summary>
    /// Inicia desenho de um novo stroke
    /// </summary>
    private void DesenhoCanvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
        if (!viewModel.ModoDesenhoAtivo) return;

        var canvas = sender as Canvas;
        if (canvas == null) return;

        _isDrawing = true;
        var position = e.GetPosition(canvas);

        // Criar novo stroke com cor e espessura atuais
        _currentStroke = new BioDesk.Domain.Models.StrokeModel(viewModel.CorDesenho, viewModel.EspessuraDesenho);
        _currentStroke.Points.Add(new BioDesk.Domain.Models.SimplePoint(position.X, position.Y));

        canvas.CaptureMouse();
    }

    /// <summary>
    /// Adiciona pontos ao stroke durante o movimento
    /// </summary>
    private void DesenhoCanvas_MouseMove(object sender, MouseEventArgs e)
    {
        if (!_isDrawing || _currentStroke == null) return;
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
        if (!viewModel.ModoDesenhoAtivo) return;

        var canvas = sender as Canvas;
        if (canvas == null) return;

        var position = e.GetPosition(canvas);
        _currentStroke.Points.Add(new BioDesk.Domain.Models.SimplePoint(position.X, position.Y));
    }

    /// <summary>
    /// Finaliza o stroke e adiciona ao ViewModel
    /// </summary>
    private void DesenhoCanvas_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        if (!_isDrawing || _currentStroke == null) return;
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;

        var canvas = sender as Canvas;
        canvas?.ReleaseMouseCapture();

        // Adicionar stroke final ao ViewModel
        if (_currentStroke.Points.Count > 1)
        {
            viewModel.AdicionarStroke(_currentStroke);
        }

        _isDrawing = false;
        _currentStroke = null;
    }

    /// <summary>
    /// Cancela desenho se mouse sair do canvas
    /// </summary>
    private void DesenhoCanvas_MouseLeave(object sender, MouseEventArgs e)
    {
        if (_isDrawing)
        {
            var canvas = sender as Canvas;
            canvas?.ReleaseMouseCapture();

            _isDrawing = false;
            _currentStroke = null;
        }
    }
}
