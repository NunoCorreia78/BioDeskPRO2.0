using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;
using BioDesk.Services.Core;
using BioDesk.ViewModels.Base;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.FichaPaciente;

/// <summary>
/// ViewModel para Tab 7 - Terapias Bioenergéticas (Banco Core de 156 itens)
/// </summary>
public partial class TerapiasBioenergeticasViewModel : ViewModelBase
{
    private readonly IItemBancoCoreService _itemBancoCoreService;
    private readonly ILogger<TerapiasBioenergeticasViewModel> _logger;

    [ObservableProperty]
    private ObservableCollection<ItemBancoCore> _itensDisponiveis = new();

    [ObservableProperty]
    private ObservableCollection<ItemBancoCore> _itensSelecionados = new();

    [ObservableProperty]
    private string _pesquisarTexto = string.Empty;

    [ObservableProperty]
    private CategoriaCore? _categoriaFiltro = null;

    [ObservableProperty]
    private ItemBancoCore? _itemSelecionado;

    [ObservableProperty]
    private string _mensagemStatus = string.Empty;

    public TerapiasBioenergeticasViewModel(
        IItemBancoCoreService itemBancoCoreService,
        ILogger<TerapiasBioenergeticasViewModel> logger)
    {
        _itemBancoCoreService = itemBancoCoreService ?? throw new ArgumentNullException(nameof(itemBancoCoreService));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Carrega todos os 156 itens do Banco Core
    /// </summary>
    [RelayCommand]
    private async Task CarregarItensAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Carregando itens do Banco Core...");

            var itens = await _itemBancoCoreService.GetItensDisponiveisAsync();
            ItensDisponiveis = new ObservableCollection<ItemBancoCore>(itens);

            MensagemStatus = $"{itens.Count} itens disponíveis";
            _logger.LogInformation("✅ {Count} itens carregados", itens.Count);

        }, "ao carregar itens do Banco Core", _logger);
    }

    /// <summary>
    /// Pesquisa itens por nome ou notas
    /// </summary>
    [RelayCommand]
    private async Task PesquisarAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (string.IsNullOrWhiteSpace(PesquisarTexto))
            {
                await CarregarItensAsync();
                return;
            }

            _logger.LogDebug("Pesquisando: {Termo}", PesquisarTexto);

            var resultados = await _itemBancoCoreService.PesquisarAsync(PesquisarTexto);
            ItensDisponiveis = new ObservableCollection<ItemBancoCore>(resultados);

            MensagemStatus = $"{resultados.Count} resultados para '{PesquisarTexto}'";

        }, "ao pesquisar itens", _logger);
    }

    /// <summary>
    /// Filtra itens por categoria (Bach Florais, Chakras, etc.)
    /// </summary>
    [RelayCommand]
    private async Task FiltrarPorCategoriaAsync(CategoriaCore? categoria)
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            CategoriaFiltro = categoria;

            if (categoria == null)
            {
                _logger.LogDebug("Removendo filtro de categoria");
                await CarregarItensAsync();
                return;
            }

            _logger.LogDebug("Filtrando por categoria: {Categoria}", categoria);

            var itens = await _itemBancoCoreService.GetItensPorCategoriaAsync(categoria.Value);
            ItensDisponiveis = new ObservableCollection<ItemBancoCore>(itens);

            MensagemStatus = $"{itens.Count} itens - {categoria}";

        }, "ao filtrar por categoria", _logger);
    }

    /// <summary>
    /// Adiciona item à seleção da sessão atual
    /// </summary>
    [RelayCommand]
    private void AdicionarItem(ItemBancoCore? item)
    {
        if (item == null)
        {
            _logger.LogWarning("Tentativa de adicionar item nulo");
            return;
        }

        if (ItensSelecionados.Contains(item))
        {
            MensagemStatus = $"'{item.Nome}' já está selecionado";
            return;
        }

        ItensSelecionados.Add(item);
        MensagemStatus = $"'{item.Nome}' adicionado ({ItensSelecionados.Count} selecionados)";

        _logger.LogDebug("Item adicionado: {Nome} ({Categoria})", item.Nome, item.Categoria);
    }

    /// <summary>
    /// Remove item da seleção
    /// </summary>
    [RelayCommand]
    private void RemoverItem(ItemBancoCore? item)
    {
        if (item != null && ItensSelecionados.Remove(item))
        {
            MensagemStatus = $"'{item.Nome}' removido ({ItensSelecionados.Count} selecionados)";
            _logger.LogDebug("Item removido: {Nome}", item.Nome);
        }
    }

    /// <summary>
    /// Limpa toda a seleção
    /// </summary>
    [RelayCommand]
    private void LimparSelecao()
    {
        var count = ItensSelecionados.Count;
        ItensSelecionados.Clear();
        MensagemStatus = $"{count} itens removidos da seleção";

        _logger.LogInformation("Seleção limpa ({Count} itens removidos)", count);
    }

    /// <summary>
    /// Valida integridade do seed (156 itens)
    /// </summary>
    [RelayCommand]
    private async Task ValidarIntegridadeAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Validando integridade do Banco Core...");

            var resultado = await _itemBancoCoreService.ValidarIntegridadeAsync();

            if (resultado.IsValido)
            {
                MensagemStatus = $"✅ Validação OK - {resultado.TotalItens} itens";
                _logger.LogInformation("✅ Validação bem-sucedida");
            }
            else
            {
                MensagemStatus = $"❌ Validação falhou - ver logs";
                _logger.LogWarning("❌ Validação falhou: {Erros}", string.Join(", ", resultado.Erros));
            }

        }, "ao validar integridade", _logger);
    }
}
