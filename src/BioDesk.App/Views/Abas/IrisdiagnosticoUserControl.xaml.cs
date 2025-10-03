using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using BioDesk.ViewModels.Abas;
using BioDesk.App.Views.Dialogs;
using BioDesk.Domain.Entities;
using BioDesk.App.Dialogs;
using BioDesk.Services;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.App.Views.Abas;

/// <summary>
/// Lógica de interação para IrisdiagnosticoUserControl.xaml
/// FASE 3: Inclui dialog de observações + menu contextual para edição de marcas
/// </summary>
public partial class IrisdiagnosticoUserControl : UserControl
{
    public IrisdiagnosticoUserControl()
    {
        InitializeComponent();
    }

    /// <summary>
    /// Handler para click no Canvas - mostra dialog e adiciona marca com observações
    /// </summary>
    private async void MarkingsCanvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
        if (viewModel.IrisImagemSelecionada == null) return;

        // Obter posição do click relativa ao Canvas
        var canvas = sender as Canvas;
        if (canvas == null) return;

        var position = e.GetPosition(canvas);

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
}
