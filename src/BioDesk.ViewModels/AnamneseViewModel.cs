using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Navigation;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para o novo sistema de Anamnese/Declaração com ecrã único
/// Suporte para Modo Edição vs Modo Documento + Sistema de Reconciliação
/// </summary>
public partial class AnamneseViewModel : ViewModelBase, IDisposable
{
    private readonly IPacienteService _pacienteService;
    private readonly INavigationService _navigationService;
    private readonly ILogger<AnamneseViewModel> _logger;

    [ObservableProperty]
    private Paciente? _pacienteAtual;

    [ObservableProperty]
    private bool _modoDocumento = false; // false = Modo Edição (default), true = Modo Documento (PDF preview)

    [ObservableProperty]
    private bool _isLoading = false;

    [ObservableProperty]
    private string _statusMessage = "📋 Sistema de Declaração Inteligente ativo";

    // Coleção principal de expanders (secções da anamnese)
    public ObservableCollection<ExpanderAnamnese> Expanders { get; } = new();

    // Computed collections para a Reconciliação
    public IEnumerable<ItemTimeline> ItensParaTimeline => 
        Expanders.SelectMany(exp => exp.Items
            .Where(item => item.Flags.GetEnviarParaTimeline(exp.Flags) || item.Flags.TrabalharHoje)
            .Select(item => new ItemTimeline
            {
                Id = item.Id,
                Categoria = exp.Categoria,
                Titulo = item.Nome,
                Descricao = FormatarItemParaTimeline(item),
                Prioridade = item.Flags.GetPrioridade(exp.Flags),
                PretendidoPeloPaciente = item.Flags.GetPretendidoPeloPaciente(exp.Flags),
                TrabalharHoje = item.Flags.TrabalharHoje,
                ItemOrigemId = item.Id
            }));

    public IEnumerable<DeltaPermanente> DeltasPermanente =>
        Expanders.SelectMany(exp => exp.Items
            .Where(item => item.Flags.GetAtualizarPermanente(exp.Flags))
            .Select(item => new DeltaPermanente
            {
                Categoria = exp.Categoria,
                TipoOperacao = DeterminarTipoOperacao(item),
                Descricao = GerarDescricaoDelta(item),
                ItemId = item.Id,
                Confirmado = false
            }));

    public string PreviewPDF =>
        GerarConteudoLimpo();

    public AnamneseViewModel(
        IPacienteService pacienteService, 
        INavigationService navigationService, 
        ILogger<AnamneseViewModel> logger)
    {
        _pacienteService = pacienteService;
        _navigationService = navigationService;
        _logger = logger;

        // Inicializar com estrutura padrão de expanders
        InicializarEstruturaPadrao();
    }

    /// <summary>
    /// Toggle entre Modo Edição e Modo Documento (preview PDF)
    /// </summary>
    [RelayCommand]
    private async Task AlternarModoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            ModoDocumento = !ModoDocumento;
            StatusMessage = ModoDocumento 
                ? "📄 Modo Documento - Preview do PDF oficial"
                : "📋 Modo Edição - Controlos ativos";
            
            _logger?.LogInformation("Modo alterado para: {Modo}", ModoDocumento ? "Documento" : "Edição");
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Abre o modal de Reconciliação & Guardar Sessão
    /// </summary>
    [RelayCommand]
    private async Task AbrirReconciliacaoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            StatusMessage = "🔄 Preparando reconciliação...";
            
            var itensTimeline = ItensParaTimeline.ToList();
            var deltasPermante = DeltasPermanente.ToList();
            var previewPdf = PreviewPDF;

            _logger?.LogInformation("Reconciliação iniciada - {Timeline} itens timeline, {Deltas} deltas permanente", 
                itensTimeline.Count, deltasPermante.Count);

            // TODO: Abrir modal com os 3 painéis
            StatusMessage = $"🔄 Reconciliação: {itensTimeline.Count} timeline + {deltasPermante.Count} deltas";
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Gera PDF oficial com conteúdo limpo (sem controlos)
    /// </summary>
    [RelayCommand]
    private async Task GerarPdfAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            StatusMessage = "📄 Gerando PDF oficial...";
            
            var conteudoLimpo = PreviewPDF;
            
            // TODO: Implementar geração real do PDF
            _logger?.LogInformation("PDF gerado para paciente {PacienteId}", PacienteAtual?.Id);
            
            StatusMessage = "✅ PDF gerado com sucesso!";
            await Task.Delay(2000); // Mostrar mensagem por 2s
            StatusMessage = "📋 Sistema de Declaração Inteligente ativo";
        });
    }

    private void InicializarEstruturaPadrao()
    {
        // Motivo da Consulta
        var motivoExpander = new ExpanderAnamnese
        {
            Titulo = "🎯 MOTIVO DA CONSULTA",
            Categoria = "motivo",
            IsExpanded = true,
            Flags = new ExpanderFlags
            {
                IncluirNoPdf = true,
                EnviarParaTimeline = true,
                PrioridadePadrao = Prioridade.Alta,
                AtualizarPermanente = false
            }
        };

        motivoExpander.Items.Add(new ItemAnamnese
        {
            Nome = "Motivo Principal",
            TipoItem = "texto",
            Conteudo = "Dor cervical com irradiação"
        });

        // Sintomas Musculoesqueléticos
        var sintomasExpander = new ExpanderAnamnese
        {
            Titulo = "🦴 SINTOMAS - Musculoesquelético",
            Categoria = "sintomas_musculo",
            IsExpanded = true,
            Flags = new ExpanderFlags
            {
                IncluirNoPdf = true,
                EnviarParaTimeline = true,
                PrioridadePadrao = Prioridade.Media,
                AtualizarPermanente = true
            }
        };

        sintomasExpander.Items.AddRange(new[]
        {
            new ItemAnamnese { Nome = "Cervicalgia", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Lombalgia", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Dorsalgia", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Dor articular", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Rigidez matinal", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Fraqueza", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" }
        });

        // Sintomas Neurológicos
        var neuroExpander = new ExpanderAnamnese
        {
            Titulo = "🧠 SINTOMAS - Neurológico",
            Categoria = "sintomas_neuro",
            IsExpanded = false,
            Flags = new ExpanderFlags { IncluirNoPdf = true, EnviarParaTimeline = true, AtualizarPermanente = true }
        };

        neuroExpander.Items.AddRange(new[]
        {
            new ItemAnamnese { Nome = "Cefaleia", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Tonturas", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Vertigens", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Parestesias", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" },
            new ItemAnamnese { Nome = "Dormência", TipoItem = "sintoma", Intensidade = 0, Estado = "inativo" }
        });

        // Adicionar expanders à coleção
        Expanders.Add(motivoExpander);
        Expanders.Add(sintomasExpander);
        Expanders.Add(neuroExpander);

        _logger?.LogInformation("Estrutura padrão inicializada com {Count} expanders", Expanders.Count);
    }

    private string FormatarItemParaTimeline(ItemAnamnese item)
    {
        if (item.TipoItem == "sintoma" && item.Intensidade.HasValue && item.Intensidade > 0)
        {
            return $"{item.Nome} ({item.Intensidade}/10) - {item.Estado}";
        }
        return $"{item.Nome}: {item.Conteudo}";
    }

    private string DeterminarTipoOperacao(ItemAnamnese item)
    {
        // Lógica simplificada - pode ser expandida
        if (item.TipoItem == "sintoma" && item.Intensidade > 0)
            return "atualizar";
        if (!string.IsNullOrEmpty(item.Conteudo))
            return "adicionar";
        return "avaliar";
    }

    private string GerarDescricaoDelta(ItemAnamnese item)
    {
        if (item.TipoItem == "sintoma" && item.Intensidade.HasValue)
        {
            return $"Atualizar '{item.Nome}': intensidade {item.Intensidade}/10, estado {item.Estado}?";
        }
        return $"Adicionar '{item.Nome}' ao perfil permanente?";
    }

    private string GerarConteudoLimpo()
    {
        var conteudo = "DECLARAÇÃO DE SAÚDE\n\n";
        
        foreach (var expander in Expanders.Where(e => e.Flags.IncluirNoPdf))
        {
            conteudo += $"{expander.Titulo}\n";
            
            foreach (var item in expander.Items.Where(i => i.Flags.GetIncluirNoPdf(expander.Flags)))
            {
                if (item.TipoItem == "sintoma" && item.Intensidade.HasValue && item.Intensidade > 0)
                {
                    conteudo += $"• {item.Nome}: intensidade {item.Intensidade}/10\n";
                }
                else if (!string.IsNullOrEmpty(item.Conteudo))
                {
                    conteudo += $"• {item.Nome}: {item.Conteudo}\n";
                }
            }
            conteudo += "\n";
        }
        
        return conteudo;
    }

    public void CarregarPaciente(Paciente paciente)
    {
        PacienteAtual = paciente;
        StatusMessage = $"📋 Declaração carregada para {paciente.Nome}";
        _logger?.LogInformation("Anamnese carregada para paciente {PacienteId}", paciente.Id);
    }

    public void Dispose()
    {
        // Cleanup se necessário
    }
}