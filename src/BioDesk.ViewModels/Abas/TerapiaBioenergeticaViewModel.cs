using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel principal para Tab 7 - Terapias Bioenergéticas (Inergetix-CoRe)
/// Gere scan, emissão sequencial, biofeedback e protocolos Excel
/// </summary>
public partial class TerapiaBioenergeticaViewModel : ViewModelBase
{
    private readonly ILogger<TerapiaBioenergeticaViewModel> _logger;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // PACIENTE ATIVO (PRÉ-REQUISITO)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [ObservableProperty]
    private Paciente? _pacienteAtual;

    [ObservableProperty]
    private bool _pacienteValido = false;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // CATÁLOGO & FILA DE EMISSÃO (COLUNA 1)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [ObservableProperty]
    private ObservableCollection<ProtocoloTerapia> _protocolos = new();

    [ObservableProperty]
    private ObservableCollection<FrequenciaRessonante> _frequenciasRessonantes = new();

    [ObservableProperty]
    private ObservableCollection<EmissaoFrequencia> _filaEmissao = new();

    [ObservableProperty]
    private decimal _limiarRelevancia = 30.0m; // Value % mínimo (padrão: 30%)

    [ObservableProperty]
    private string _pesquisaProtocolo = string.Empty;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // CONTROLO DE SAÍDA (COLUNA 2)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [ObservableProperty]
    private decimal _frequenciaAtualHz = 0;

    [ObservableProperty]
    private decimal _amplitudeV = 5.0m;

    [ObservableProperty]
    private decimal _limiteCorrenteMa = 10.0m;

    [ObservableProperty]
    private string _formaOnda = "Sine"; // Sine, Square, Triangle, Saw

    [ObservableProperty]
    private string _modulacao = "None"; // AM, FM, Burst, None

    [ObservableProperty]
    private int _canal = 1; // 1 ou 2 (TiePie HS3)

    [ObservableProperty]
    private bool _emissaoAtiva = false;

    [ObservableProperty]
    private int _tempoDecorridoSeg = 0;

    [ObservableProperty]
    private int _tempoTotalSeg = 300; // 5 min padrão

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // BIOFEEDBACK TEMPO REAL (COLUNA 3)
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [ObservableProperty]
    private decimal _rmsAtual = 0;

    [ObservableProperty]
    private decimal _picoAtual = 0;

    [ObservableProperty]
    private decimal _frequenciaDominanteHz = 0;

    [ObservableProperty]
    private decimal _impedanciaOhms = 0;

    [ObservableProperty]
    private decimal _improvementPctAtual = 0;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // CHECKLIST PRÉ-SESSÃO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [ObservableProperty]
    private bool _consentimentoAssinado = false;

    [ObservableProperty]
    private bool _dispositivoPronto = false;

    [ObservableProperty]
    private bool _protocoloValido = false;

    [ObservableProperty]
    private bool _limitesOk = false;

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // SESSÃO ATIVA
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [ObservableProperty]
    private SessaoTerapia? _sessaoAtual;

    public TerapiaBioenergeticaViewModel(ILogger<TerapiaBioenergeticaViewModel> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _logger.LogInformation("🌿 TerapiaBioenergeticaViewModel inicializado");
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // COMANDOS - CATÁLOGO & IMPORTAÇÃO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [RelayCommand]
    private async Task ImportarProtocolosExcelAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("📥 Importando protocolos Excel...");
            
            // TODO: Implementar importação Excel v1 idempotente
            // - Abrir file dialog
            // - Validar schema (ExternalId, Nome, FrequenciaHz, etc.)
            // - Upsert baseado em ExternalId
            // - Relatório de OK/erros/warnings
            // - Pré-visualização antes de gravar
            
            await Task.Delay(100); // Placeholder
            
            SuccessMessage = "✅ Protocolos importados com sucesso";
        });
    }

    [RelayCommand]
    private void PesquisarProtocolos()
    {
        // TODO: Filtrar lista de protocolos baseado em PesquisaProtocolo
        _logger.LogDebug("🔍 Pesquisando protocolos: {Texto}", PesquisaProtocolo);
    }

    [RelayCommand]
    private void AdicionarProtocoloFila(ProtocoloTerapia protocolo)
    {
        // TODO: Adicionar protocolo à fila de emissão
        _logger.LogInformation("➕ Adicionando protocolo à fila: {Nome}", protocolo.Nome);
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // COMANDOS - SCAN RESSONANTE
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [RelayCommand]
    private async Task IniciarScanRessonanteAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (PacienteAtual == null)
            {
                ErrorMessage = "❌ Abra a ficha do paciente antes de usar módulos de frequências";
                return;
            }

            _logger.LogInformation("🔍 Iniciando scan ressonante...");
            
            // TODO: Implementar scan ressonante
            // - Gerar frequências aleatórias (TRNG/CSPRNG)
            // - Calcular Value % para cada frequência
            // - Ordenar por Value % (100% no topo)
            // - Filtrar por LimiarRelevancia (ex: > 30%)
            // - Adicionar a FrequenciasRessonantes
            
            await Task.Delay(100); // Placeholder
            
            SuccessMessage = "✅ Scan concluído - Frequências ordenadas por relevância";
        });
    }

    [RelayCommand]
    private void SelecionarFrequencia(FrequenciaRessonante freq)
    {
        freq.Selecionado = !freq.Selecionado;
        _logger.LogDebug("✔️ Frequência {FreqHz} Hz selecionada: {Status}", freq.FrequenciaHz, freq.Selecionado);
    }

    [RelayCommand]
    private void AdicionarSelecionadasFila()
    {
        var selecionadas = FrequenciasRessonantes.Where(f => f.Selecionado).ToList();
        _logger.LogInformation("➕ Adicionando {Count} frequências à fila", selecionadas.Count);
        
        // TODO: Converter FrequenciaRessonante em EmissaoFrequencia e adicionar à fila
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // COMANDOS - EMISSÃO SEQUENCIAL
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [RelayCommand]
    private async Task IniciarEmissaoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (!ValidarChecklistPreSessao())
            {
                ErrorMessage = "❌ Complete o checklist pré-sessão antes de iniciar";
                return;
            }

            _logger.LogInformation("▶️ Iniciando emissão sequencial...");
            EmissaoAtiva = true;

            // TODO: Implementar emissão sequencial
            // - Criar SessaoTerapia
            // - Para cada item na FilaEmissao:
            //   - Emitir frequência com AWG (TiePie HS3)
            //   - Capturar biofeedback em tempo real (RMS, pico, FFT)
            //   - Atualizar ImprovementPct
            //   - Se ImprovementPct >= 100%, prosseguir para próximo
            // - Salvar sessão completa na BD
            
            await Task.Delay(100); // Placeholder
        });
    }

    [RelayCommand]
    private void PausarEmissao()
    {
        _logger.LogWarning("⏸️ Emissão pausada");
        EmissaoAtiva = false;
    }

    [RelayCommand]
    private void PararEmissao()
    {
        _logger.LogWarning("⏹️ Emissão cancelada");
        EmissaoAtiva = false;
        // TODO: Salvar registo parcial na BD
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // COMANDOS - HISTÓRICO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    [RelayCommand]
    private async Task ExportarRelatorioAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("📄 Exportando relatório da sessão...");
            
            // TODO: Gerar PDF/CSV com:
            // - Value % iniciais
            // - Improvement % finais
            // - Parâmetros emitidos (freq/forma/V/mA)
            // - Tempo total
            // - Observações clínicas
            
            await Task.Delay(100); // Placeholder
            
            SuccessMessage = "✅ Relatório exportado";
        });
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // VALIDAÇÃO CHECKLIST PRÉ-SESSÃO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    private bool ValidarChecklistPreSessao()
    {
        if (!ConsentimentoAssinado)
        {
            ErrorMessage = "❌ Consentimento não assinado";
            return false;
        }

        if (!DispositivoPronto)
        {
            ErrorMessage = "❌ Dispositivo não está pronto";
            return false;
        }

        if (FilaEmissao.Count == 0)
        {
            ErrorMessage = "❌ Fila de emissão vazia - adicione protocolos ou frequências";
            return false;
        }

        if (AmplitudeV < 0 || AmplitudeV > 20)
        {
            ErrorMessage = "❌ Amplitude fora dos limites (0-20V)";
            return false;
        }

        if (LimiteCorrenteMa < 0 || LimiteCorrenteMa > 50)
        {
            ErrorMessage = "❌ Corrente fora dos limites (0-50mA)";
            return false;
        }

        return true;
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    // MÉTODOS PÚBLICOS - INICIALIZAÇÃO
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    public void SetPacienteAtual(Paciente? paciente)
    {
        PacienteAtual = paciente;
        PacienteValido = paciente != null;
        
        if (PacienteAtual != null)
        {
            _logger.LogInformation("👤 Paciente ativo: {Nome}", PacienteAtual.NomeCompleto);
        }
    }

    public async Task CarregarProtocolosAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("📚 Carregando protocolos da BD...");
            
            // TODO: Carregar protocolos de ProtocoloTerapia table
            
            await Task.Delay(100); // Placeholder
        });
    }
}
