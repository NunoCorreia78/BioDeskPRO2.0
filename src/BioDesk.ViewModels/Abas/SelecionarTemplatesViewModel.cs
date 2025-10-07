using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Services.Templates;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel para o pop-up de seleção de templates PDF
/// Suporta pesquisa, multi-seleção e preview
/// </summary>
public partial class SelecionarTemplatesViewModel : ViewModelBase
{
    private readonly ILogger<SelecionarTemplatesViewModel> _logger;
    private readonly ITemplatesPdfService _templatesPdfService;

    /// <summary>
    /// Lista completa de todos os templates (sem filtro)
    /// </summary>
    private List<TemplatePdfViewModel> _todosTemplates = new();

    /// <summary>
    /// Templates filtrados pela pesquisa
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<TemplatePdfViewModel> _templatesFiltrados = new();

    /// <summary>
    /// Texto de pesquisa (filtra templates em tempo real)
    /// </summary>
    [ObservableProperty]
    private string _textoPesquisa = string.Empty;

    /// <summary>
    /// Selecionar/desselecionar todos os templates
    /// </summary>
    [ObservableProperty]
    private bool _selecionarTodos = false;

    /// <summary>
    /// Status da seleção (ex: "3 templates selecionados")
    /// </summary>
    [ObservableProperty]
    private string _statusSelecao = "Nenhum template selecionado";

    /// <summary>
    /// Indica se há templates selecionados (para habilitar botão)
    /// </summary>
    [ObservableProperty]
    private bool _temTemplatesSelecionados = false;

    /// <summary>
    /// Templates que foram selecionados pelo utilizador
    /// Usado pela janela principal após fechar o pop-up
    /// </summary>
    public List<TemplatePdfViewModel> TemplatesSelecionados => _todosTemplates
        .Where(t => t.Selecionado)
        .ToList();

    public SelecionarTemplatesViewModel(
        ILogger<SelecionarTemplatesViewModel> logger,
        ITemplatesPdfService templatesPdfService)
    {
        _logger = logger;
        _templatesPdfService = templatesPdfService;
    }

    /// <summary>
    /// Carrega templates ao inicializar o ViewModel
    /// </summary>
    public async Task InicializarAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;

            var templates = await _templatesPdfService.ListarTemplatesAsync();

            _todosTemplates = templates.Select(t => new TemplatePdfViewModel(
                t.Nome,
                t.CaminhoCompleto,
                t.NomeFicheiro,
                t.TamanhoFormatado))
                .ToList();

            // Subscrever ao PropertyChanged de cada template para atualizar status
            foreach (var template in _todosTemplates)
            {
                template.PropertyChanged += (s, e) =>
                {
                    if (e.PropertyName == nameof(TemplatePdfViewModel.Selecionado))
                    {
                        AtualizarStatus();
                    }
                };
            }

            AplicarFiltro();
            AtualizarStatus();

            _logger.LogInformation("📋 Carregados {Count} templates", _todosTemplates.Count);

            IsLoading = false;

        }, "Erro ao carregar templates", _logger);
    }

    /// <summary>
    /// Filtra templates quando texto de pesquisa muda
    /// </summary>
    partial void OnTextoPesquisaChanged(string value)
    {
        AplicarFiltro();
    }

    /// <summary>
    /// Seleciona/desseleciona todos quando checkbox muda
    /// </summary>
    partial void OnSelecionarTodosChanged(bool value)
    {
        foreach (var template in TemplatesFiltrados)
        {
            template.Selecionado = value;
        }

        AtualizarStatus();
    }

    /// <summary>
    /// Aplica filtro de pesquisa
    /// </summary>
    private void AplicarFiltro()
    {
        var filtrados = string.IsNullOrWhiteSpace(TextoPesquisa)
            ? _todosTemplates
            : _todosTemplates.Where(t => t.Nome.Contains(TextoPesquisa, StringComparison.OrdinalIgnoreCase)).ToList();

        TemplatesFiltrados.Clear();
        foreach (var template in filtrados)
        {
            TemplatesFiltrados.Add(template);
        }

        _logger.LogDebug("🔍 Filtro aplicado: {Count} de {Total}", TemplatesFiltrados.Count, _todosTemplates.Count);
    }

    /// <summary>
    /// Atualiza status de seleção e habilita/desabilita botão
    /// </summary>
    private void AtualizarStatus()
    {
        var selecionados = _todosTemplates.Count(t => t.Selecionado);

        StatusSelecao = selecionados switch
        {
            0 => "Nenhum template selecionado",
            1 => "1 template selecionado",
            _ => $"{selecionados} templates selecionados"
        };

        TemTemplatesSelecionados = selecionados > 0;

        // Atualizar estado do "Selecionar todos" sem triggerar evento
        var todosSelecionados = TemplatesFiltrados.All(t => t.Selecionado);
        if (SelecionarTodos != todosSelecionados)
        {
            // Usar a propriedade gerada pelo MVVM Toolkit ao invés do field
            SelecionarTodos = todosSelecionados;
        }
    }

    /// <summary>
    /// Abre template PDF no visualizador padrão (preview)
    /// </summary>
    [RelayCommand]
    private void PreviewTemplate(string caminhoCompleto)
    {
        try
        {
            _templatesPdfService.AbrirTemplate(caminhoCompleto);
            _logger.LogInformation("👁 Preview: {Caminho}", caminhoCompleto);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao abrir preview");
            ErrorMessage = $"Erro ao abrir preview: {ex.Message}";
        }
    }
}
