using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para visualização e gestão de itens do Banco Core Informacional
/// Permite pesquisa, filtragem por categoria e género
/// </summary>
public partial class ItensCoreViewModel : ViewModelBase
{
    private readonly BioDeskDbContext _context;
    private readonly ILogger<ItensCoreViewModel> _logger;

    [ObservableProperty]
    private ObservableCollection<ItemBancoCore> _itens = new();

    [ObservableProperty]
    private ObservableCollection<ItemBancoCore> _itensFiltrados = new();

    [ObservableProperty]
    private ItemBancoCore? _itemSelecionado;

    [ObservableProperty]
    private string _textoPesquisa = string.Empty;

    [ObservableProperty]
    private CategoriaCore? _categoriaFiltro;

    [ObservableProperty]
    private string? _generoFiltro;

    [ObservableProperty]
    private bool _apenasAtivos = true;

    [ObservableProperty]
    private int _totalItens;

    [ObservableProperty]
    private int _totalFiltrados;

    [ObservableProperty]
    private string _estatisticas = string.Empty;

    // Opções de filtro
    public ObservableCollection<CategoriaCore?> CategoriasDisponiveis { get; } = new()
    {
        null, // "Todas"
        CategoriaCore.FloraisBach,
        CategoriaCore.FloraisCalifornianos,
        CategoriaCore.Homeopatia,
        CategoriaCore.Emocao,
        CategoriaCore.Orgao,
        CategoriaCore.Chakra,
        CategoriaCore.Meridiano,
        CategoriaCore.Vitamina,
        CategoriaCore.Mineral,
        CategoriaCore.Suplemento,
        CategoriaCore.Alimento
    };

    public ObservableCollection<string?> GenerosDisponiveis { get; } = new()
    {
        null,        // "Todos"
        "Ambos",
        "Masculino",
        "Feminino"
    };

    public ItensCoreViewModel(BioDeskDbContext context, ILogger<ItensCoreViewModel> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Carrega todos os itens da base de dados
    /// </summary>
    [RelayCommand]
    private async Task CarregarItensAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Carregando itens do Banco Core...");

            var query = _context.ItensBancoCore.AsQueryable();

            // Filtro básico: apenas ativos
            if (ApenasAtivos)
            {
                query = query.Where(x => x.IsActive);
            }

            var itensDb = await query
                .OrderBy(x => x.Categoria)
                .ThenBy(x => x.Nome)
                .ToListAsync();

            Itens.Clear();
            foreach (var item in itensDb)
            {
                Itens.Add(item);
            }

            TotalItens = Itens.Count;

            // Aplicar filtros automaticamente
            await AplicarFiltrosAsync();

            AtualizarEstatisticas();

            _logger.LogInformation($"✅ {TotalItens} itens carregados com sucesso");
        },
        errorContext: "ao carregar itens do Banco Core",
        logger: _logger);
    }

    /// <summary>
    /// Aplica filtros de pesquisa, categoria e género
    /// </summary>
    [RelayCommand]
    private async Task AplicarFiltrosAsync()
    {
        await Task.Run(() =>
        {
            var query = Itens.AsEnumerable();

            // Filtro 1: Texto de pesquisa (nome ou descrição)
            if (!string.IsNullOrWhiteSpace(TextoPesquisa))
            {
                var termoPesquisa = TextoPesquisa.ToLowerInvariant();
                query = query.Where(x =>
                    x.Nome.ToLowerInvariant().Contains(termoPesquisa) ||
                    (x.DescricaoBreve != null && x.DescricaoBreve.ToLowerInvariant().Contains(termoPesquisa)) ||
                    (x.Subcategoria != null && x.Subcategoria.ToLowerInvariant().Contains(termoPesquisa))
                );
            }

            // Filtro 2: Categoria
            if (CategoriaFiltro.HasValue)
            {
                query = query.Where(x => x.Categoria == CategoriaFiltro.Value);
            }

            // Filtro 3: Género
            if (!string.IsNullOrEmpty(GeneroFiltro))
            {
                query = query.Where(x => x.GeneroAplicavel == GeneroFiltro);
            }

            var resultados = query.ToList();

            // Atualizar UI no thread principal
            Application.Current.Dispatcher.Invoke(() =>
            {
                ItensFiltrados.Clear();
                foreach (var item in resultados)
                {
                    ItensFiltrados.Add(item);
                }

                TotalFiltrados = ItensFiltrados.Count;
                AtualizarEstatisticas();
            });
        });
    }

    /// <summary>
    /// Limpa todos os filtros
    /// </summary>
    [RelayCommand]
    private async Task LimparFiltrosAsync()
    {
        TextoPesquisa = string.Empty;
        CategoriaFiltro = null;
        GeneroFiltro = null;

        await AplicarFiltrosAsync();
    }

    /// <summary>
    /// Atualiza estatísticas exibidas
    /// </summary>
    private void AtualizarEstatisticas()
    {
        if (TotalItens == 0)
        {
            Estatisticas = "Nenhum item carregado";
            return;
        }

        var porCategoria = Itens
            .GroupBy(x => x.Categoria)
            .Select(g => $"{g.Key}: {g.Count()}")
            .ToList();

        var stats = $"Total: {TotalItens} itens | Filtrados: {TotalFiltrados} itens\n";
        stats += string.Join(" | ", porCategoria);

        Estatisticas = stats;
    }

    /// <summary>
    /// Exporta detalhes do item selecionado
    /// </summary>
    [RelayCommand]
    private void ExportarDetalhes()
    {
        if (ItemSelecionado == null)
        {
            _logger.LogWarning("Nenhum item selecionado para exportar");
            return;
        }

        _logger.LogInformation($"Exportando detalhes do item: {ItemSelecionado.Nome}");

        // TODO: Implementar exportação para PDF ou clipboard
        var detalhes = $"""
            Nome: {ItemSelecionado.Nome}
            Categoria: {ItemSelecionado.Categoria}
            Subcategoria: {ItemSelecionado.Subcategoria ?? "N/A"}
            Género Aplicável: {ItemSelecionado.GeneroAplicavel ?? "N/A"}
            Descrição: {ItemSelecionado.DescricaoBreve ?? "N/A"}
            Fonte: {ItemSelecionado.FonteOrigem ?? "N/A"}
            ExternalId: {ItemSelecionado.ExternalId}
            Metadata: {ItemSelecionado.JsonMetadata ?? "N/A"}
            """;

        System.Windows.Clipboard.SetText(detalhes);
        _logger.LogInformation("✅ Detalhes copiados para clipboard");
    }

    /// <summary>
    /// Carrega itens ao inicializar ViewModel
    /// </summary>
    public async Task InitializeAsync()
    {
        await CarregarItensAsync();
    }
}
