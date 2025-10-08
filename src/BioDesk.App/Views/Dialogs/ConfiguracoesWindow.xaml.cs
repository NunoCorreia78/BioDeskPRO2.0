using System;
using System.Windows;
using Microsoft.Extensions.Logging;
using BioDesk.ViewModels;

namespace BioDesk.App.Views.Dialogs;

/// <summary>
/// ConfiguracoesWindow - Janela modal para configurar dados da clínica
/// Permite editar: Nome, Morada, Telefone, Email, NIPC, Logo
/// </summary>
public partial class ConfiguracoesWindow : Window
{
    private readonly ILogger<ConfiguracoesWindow>? _logger;
    private readonly ConfiguracaoClinicaViewModel _viewModel;

    public ConfiguracoesWindow(ConfiguracaoClinicaViewModel viewModel, ILogger<ConfiguracoesWindow> logger)
    {
        InitializeComponent();
        
        _viewModel = viewModel ?? throw new ArgumentNullException(nameof(viewModel));
        _logger = logger;
        
        DataContext = _viewModel;
        
        // Subscrever evento de sucesso para fechar a janela
        _viewModel.ConfiguracaoSalvaComSucesso += OnConfiguracaoSalvaComSucesso;
        
        _logger?.LogInformation("📋 ConfiguracoesWindow inicializada");
    }

    private void OnConfiguracaoSalvaComSucesso(object? sender, EventArgs e)
    {
        _logger?.LogInformation("✅ Configuração salva com sucesso, fechando janela");
        DialogResult = true;
        Close();
    }

    private void Cancelar_Click(object sender, RoutedEventArgs e)
    {
        _logger?.LogInformation("❌ Configurações canceladas pelo usuário");
        DialogResult = false;
        Close();
    }

    protected override void OnClosed(EventArgs e)
    {
        // Limpar subscrição de evento
        if (_viewModel != null)
        {
            _viewModel.ConfiguracaoSalvaComSucesso -= OnConfiguracaoSalvaComSucesso;
        }
        
        base.OnClosed(e);
    }
}
