using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Domain.DTOs;
using BioDesk.Services.Rng;
using BioDesk.Services.Hardware;
using BioDesk.Services.Terapias;
using BioDesk.Services.Medicao;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using FluentValidation;

namespace BioDesk.ViewModels.UserControls;

/// <summary>
/// ViewModel para interface de Terapias Bioenergéticas com RNG e TiePie HS5
/// </summary>
public partial class TerapiasBioenergeticasUserControlViewModel : ViewModelBase, IDisposable
{
    private bool _disposed = false;
    private readonly IProtocoloRepository _protocoloRepository;
    private readonly IRngService _rngService;
    private readonly ITiePieHardwareService _tiePieService;
    private readonly IValueScanningService _valueScanningService;
    private readonly IMedicaoService _medicaoService;
    private readonly ILogger<TerapiasBioenergeticasUserControlViewModel> _logger;
    private readonly IValidator<ProtocoloTerapeutico> _protocoloValidator;
    private readonly IValidator<TerapiaFilaItem> _filaItemValidator;

    private CancellationTokenSource? _sessaoCts;

    [ObservableProperty] private ObservableCollection<ProtocoloTerapeutico> _protocolosDisponiveis = new();
    [ObservableProperty] private ProtocoloTerapeutico? _protocoloSelecionado;
    [ObservableProperty] private string _pesquisaProtocolo = string.Empty;
    [ObservableProperty] private string _infoProtocolo = "Nenhum protocolo selecionado";
    [ObservableProperty] private int _numeroFrequencias = 5;
    [ObservableProperty] private ObservableCollection<string> _fontesEntropiaDisponiveis = new() { "Hardware Crypto", "Atmospheric Noise", "Pseudo Random" };
    [ObservableProperty] private string _fonteEntropiaSelecionada = "Hardware Crypto";
    [ObservableProperty] private ObservableCollection<string> _frequenciasSelecionadas = new();
    [ObservableProperty] private bool _temFrequenciasSelecionadas;
    [ObservableProperty] private ObservableCollection<string> _canaisDisponiveis = new() { "Ch1", "Ch2" };
    [ObservableProperty] private string _canalSelecionado = "Ch1";
    [ObservableProperty] private double _voltagem = 2.0;
    [ObservableProperty] private ObservableCollection<string> _formasOndaDisponiveis = new() { "Sine", "Square", "Triangle", "Sawtooth" };
    [ObservableProperty] private string _formaOndaSelecionada = "Sine";
    [ObservableProperty] private int _duracaoPorFrequencia = 30;
    [ObservableProperty] private string _statusHardware = "Desconhecido";
    [ObservableProperty] private Brush _statusHardwareCor = Brushes.Gray;
    [ObservableProperty] private Brush _statusHardwareBackground = new SolidColorBrush(Color.FromRgb(240, 240, 240));
    [ObservableProperty] private Brush _statusHardwareBorda = new SolidColorBrush(Color.FromRgb(200, 200, 200));
    [ObservableProperty] private Brush _statusHardwareTexto = Brushes.Black;
    [ObservableProperty] private bool _isExecutandoTerapia;
    [ObservableProperty] private int _frequenciaAtualIndex;
    [ObservableProperty] private int _totalFrequencias;
    [ObservableProperty] private string _progressoTexto = string.Empty;
    [ObservableProperty] private bool _podeSelecionarFrequencias;
    [ObservableProperty] private bool _podeIniciarTerapia;
    [ObservableProperty] private ObservableCollection<string> _historicoSessoes = new();

    private double[] _frequenciasRaw = Array.Empty<double>();

    public TerapiasBioenergeticasUserControlViewModel(
        IProtocoloRepository protocoloRepository,
        IRngService rngService,
        ITiePieHardwareService tiePieService,
        IValueScanningService valueScanningService,
        IMedicaoService medicaoService,
        ILogger<TerapiasBioenergeticasUserControlViewModel> logger,
        IValidator<ProtocoloTerapeutico> protocoloValidator,
        IValidator<TerapiaFilaItem> filaItemValidator)
    {
        _protocoloRepository = protocoloRepository;
        _rngService = rngService;
        _tiePieService = tiePieService;
        _valueScanningService = valueScanningService;
        _medicaoService = medicaoService;
        _logger = logger;
        _protocoloValidator = protocoloValidator;
        _filaItemValidator = filaItemValidator;

        // ✅ Carregar dados de forma síncrona no construtor
        Task.Run(async () => await CarregarDadosAsync()).Wait();
    }

    private async Task CarregarDadosAsync()
    {
        try
        {
            _logger.LogInformation("📂 Carregando dados do módulo Terapias...");

            // Carregar protocolos da BD
            var protocolos = await _protocoloRepository.GetAllActiveAsync();
            ProtocolosDisponiveis = new ObservableCollection<ProtocoloTerapeutico>(protocolos);
            _logger.LogInformation("✅ {Count} protocolos carregados", protocolos.Count);

            // Verificar status do hardware (não bloqueia se falhar)
            try
            {
                var status = await _tiePieService.GetStatusAsync();
                AtualizarStatusHardware(status.IsConnected);

                if (status.IsConnected)
                {
                    _logger.LogInformation("✅ TiePie conectado: {DeviceName}", status.DeviceName);
                }
                else
                {
                    _logger.LogWarning("⚠️ TiePie não detectado: {Erro}", status.ErrorMessage ?? "Desconhecido");
                }
            }
            catch (InvalidOperationException ex) when (ex.Message.Contains("LibTiePie SDK"))
            {
                _logger.LogError("❌ LibTiePie SDK não instalado");
                AtualizarStatusHardware(false);
                ErrorMessage = "⚠️ LibTiePie SDK não encontrado. Instale em https://www.tiepie.com/";
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao verificar status do hardware");
                AtualizarStatusHardware(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar dados do módulo Terapias");
            ErrorMessage = $"Erro ao carregar dados: {ex.Message}";
        }
    }

    private void AtualizarStatusHardware(bool conectado)
    {
        StatusHardware = conectado ? "✅ Conectado" : "❌ Desconectado";
        StatusHardwareCor = conectado ? new SolidColorBrush(Color.FromRgb(107, 159, 95)) : new SolidColorBrush(Color.FromRgb(201, 76, 76));
        StatusHardwareBackground = conectado ? new SolidColorBrush(Color.FromRgb(240, 255, 240)) : new SolidColorBrush(Color.FromRgb(255, 240, 240));
        StatusHardwareBorda = conectado ? new SolidColorBrush(Color.FromRgb(107, 159, 95)) : new SolidColorBrush(Color.FromRgb(201, 76, 76));
        StatusHardwareTexto = conectado ? new SolidColorBrush(Color.FromRgb(60, 100, 50)) : new SolidColorBrush(Color.FromRgb(150, 50, 50));
    }

    partial void OnProtocoloSelecionadoChanged(ProtocoloTerapeutico? value)
    {
        if (value != null)
        {
            var freqs = value.GetFrequencias();
            InfoProtocolo = $"{freqs.Length} frequências disponíveis";
            PodeSelecionarFrequencias = freqs.Length > 0;
        }
        else
        {
            InfoProtocolo = "Nenhum protocolo selecionado";
            PodeSelecionarFrequencias = false;
        }
        AtualizarPodeIniciar();
    }

    partial void OnFrequenciasSelecionadasChanged(ObservableCollection<string> value)
    {
        TemFrequenciasSelecionadas = value?.Count > 0;
        TotalFrequencias = value?.Count ?? 0;
        AtualizarPodeIniciar();
    }

    partial void OnIsExecutandoTerapiaChanged(bool value) => AtualizarPodeIniciar();

    private void AtualizarPodeIniciar()
    {
        PodeIniciarTerapia = ProtocoloSelecionado != null && FrequenciasSelecionadas.Count > 0 && !IsExecutandoTerapia && StatusHardware.Contains("Conectado");
    }

    [RelayCommand]
    private async Task SelecionarFrequenciasAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (ProtocoloSelecionado == null || NumeroFrequencias < 2 || NumeroFrequencias > 10) return;
            var fonte = FonteEntropiaSelecionada switch { "Hardware Crypto" => EntropySource.HardwareCrypto, "Atmospheric Noise" => EntropySource.AtmosphericNoise, _ => EntropySource.PseudoRandom };
            _rngService.CurrentSource = fonte;
            _frequenciasRaw = await _rngService.SelectRandomFrequenciesAsync(ProtocoloSelecionado, NumeroFrequencias);
            FrequenciasSelecionadas = new ObservableCollection<string>(_frequenciasRaw.Select(f => $"{f:N2} Hz"));
        }, "ao selecionar frequências", _logger);
    }

    [RelayCommand]
    private async Task TestarHardwareAsync()
    {
        IsLoading = true;
        ErrorMessage = string.Empty;

        try
        {
            _logger.LogInformation("🔍 Iniciando teste de hardware TiePie...");

            // Testar conexão
            var status = await _tiePieService.GetStatusAsync();

            if (!status.IsConnected)
            {
                var erro = status.ErrorMessage ?? "Dispositivo não detectado";
                ErrorMessage = $"❌ TiePie não conectado: {erro}\n\n" +
                    "Verificações:\n" +
                    "1. TiePie HS5 está ligado via USB?\n" +
                    "2. LibTiePie SDK instalado? (https://www.tiepie.com/)\n" +
                    "3. Drivers do Windows atualizados?\n" +
                    "4. Aplicação executada como Administrador?";

                AtualizarStatusHardware(false);
                _logger.LogWarning("⚠️ Teste falhou: {Erro}", erro);
                return;
            }

            // Testar funcionalidade (1 kHz, 1V, 2 segundos)
            var testeOk = await _tiePieService.TestHardwareAsync();

            if (testeOk)
            {
                ErrorMessage = $"✅ Hardware funcionando!\n\n" +
                    $"Dispositivo: {status.DeviceName}\n" +
                    $"S/N: {status.SerialNumber}\n" +
                    $"Canais: {status.ChannelCount}\n" +
                    $"Freq. Máx: {status.MaxFrequencyHz / 1_000_000.0:N1} MHz\n" +
                    $"Voltagem Máx: {status.MaxVoltageV:N1} V";

                AtualizarStatusHardware(true);
                _logger.LogInformation("✅ Teste de hardware bem-sucedido");
            }
            else
            {
                ErrorMessage = "⚠️ Hardware conectado mas teste de sinal falhou.\n" +
                    "Verifique se o dispositivo não está em uso por outra aplicação.";

                AtualizarStatusHardware(true); // Conectado mas com problemas
                _logger.LogWarning("⚠️ Hardware conectado mas teste falhou");
            }
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("LibTiePie SDK"))
        {
            ErrorMessage = $"❌ LibTiePie SDK NÃO INSTALADO!\n\n" +
                $"Erro: {ex.Message}\n\n" +
                $"Solução:\n" +
                $"1. Descarregar SDK em: https://www.tiepie.com/en/libtiepie-sdk\n" +
                $"2. Instalar versão {(Environment.Is64BitProcess ? "64-bit" : "32-bit")}\n" +
                $"3. Reiniciar aplicação";

            AtualizarStatusHardware(false);
            _logger.LogError(ex, "❌ LibTiePie SDK não encontrado");
        }
        catch (Exception ex)
        {
            ErrorMessage = $"❌ Erro ao testar hardware:\n{ex.Message}";
            AtualizarStatusHardware(false);
            _logger.LogError(ex, "❌ Erro inesperado ao testar hardware");
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private async Task IniciarTerapiaAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (!PodeIniciarTerapia || _frequenciasRaw.Length == 0) return;
            IsExecutandoTerapia = true;
            using var cts = new CancellationTokenSource();
            try
            {
                var canal = CanalSelecionado == "Ch1" ? SignalChannel.Channel1 : SignalChannel.Channel2;
                var waveform = FormaOndaSelecionada switch { "Sine" => SignalWaveform.Sine, "Square" => SignalWaveform.Square, "Triangle" => SignalWaveform.Triangle, "Sawtooth" => SignalWaveform.Sawtooth, _ => SignalWaveform.Sine };
                for (int i = 0; i < _frequenciasRaw.Length && !cts.Token.IsCancellationRequested; i++)
                {
                    FrequenciaAtualIndex = i + 1;
                    ProgressoTexto = $"Frequência {FrequenciaAtualIndex}/{TotalFrequencias}: {_frequenciasRaw[i]:N2} Hz";
                    var config = new SignalConfiguration { FrequencyHz = _frequenciasRaw[i], Channel = canal, VoltageV = Voltagem, Waveform = waveform, DurationSeconds = DuracaoPorFrequencia };
                    await _tiePieService.SendSignalAsync(config);
                    await Task.Delay(TimeSpan.FromSeconds(DuracaoPorFrequencia), cts.Token);
                }
                ProgressoTexto = "✅ Terapia concluída";
                HistoricoSessoes.Insert(0, $"{DateTime.Now:dd/MM HH:mm} - {ProtocoloSelecionado!.Nome} - {TotalFrequencias} freqs");
                if (HistoricoSessoes.Count > 10) HistoricoSessoes.RemoveAt(10);
            }
            catch (OperationCanceledException) { ProgressoTexto = "⚠️ Terapia interrompida"; }
            finally { IsExecutandoTerapia = false; }
        }, "ao executar terapia", _logger);
    }

    [RelayCommand]
    private async Task PararTerapiaAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            await _tiePieService.StopAllChannelsAsync();
            IsExecutandoTerapia = false;
            ProgressoTexto = "🛑 Terapia parada";
        }, "ao parar terapia", _logger);
    }

    // ============================================================================
    // === NOVO: VALUE % SCANNING + FILA DE EXECUÇÃO (Sprint 2) ===
    // ============================================================================

    #region Value % Scanning

    /// <summary>
    /// Protocolos scaneados com Value % (CoRe 5.0)
    /// Populado pelo comando ScanValuesCommand
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<ProtocoloComValue> _protocolosScanned = new();

    /// <summary>
    /// Indica se está a fazer scanning de valores
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ScanValuesCommand))]
    private bool _isScanning;

    /// <summary>
    /// Comando para scanear Value % de todos os protocolos
    /// Algoritmo CoRe 5.0: 10 amostras RNG por protocolo
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanScanValues))]
    private async Task ScanValuesAsync()
    {
        try
        {
            _logger.LogCritical("🔥 INICIO ScanValuesAsync");
            IsScanning = true;

            _logger.LogCritical("🔥 ANTES ExecuteWithErrorHandlingAsync");

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                _logger.LogCritical("🔥 DENTRO ExecuteWithErrorHandlingAsync");
                ProtocolosScanned.Clear();
                _logger.LogCritical("� ProtocolosScanned.Clear() OK");

                // Obter todos os protocolos ativos
                _logger.LogCritical("🔥 ANTES GetAllActiveAsync");
                var protocolos = await _protocoloRepository.GetAllActiveAsync();
                _logger.LogCritical($"🔥 GetAllActiveAsync retornou {protocolos.Count} protocolos");

                if (protocolos.Count == 0)
                {
                    ErrorMessage = "⚠️ Nenhum protocolo disponível para scanning";
                    System.Windows.MessageBox.Show("Nenhum protocolo na BD!", "AVISO");
                    return;
                }

                // Scanear com ValueScanningService (CoRe 5.0)
                _logger.LogCritical("🔥 ANTES ScanearEOrdenarAsync");
                var resultados = await _valueScanningService.ScanearEOrdenarAsync(protocolos, topN: protocolos.Count);
                _logger.LogCritical($"🔥 ScanearEOrdenarAsync retornou {resultados.Count} resultados");

                // Converter para DTO e popular ObservableCollection
                _logger.LogCritical("🔥 ANTES foreach (adicionar ao ObservableCollection)");
                foreach (var (protocolo, valuePercent) in resultados)
                {
                    var dto = new ProtocoloComValue(protocolo, valuePercent);
                    // CRITICAL: Subscrever PropertyChanged para atualizar CanExecute do botão
                    dto.PropertyChanged += (s, e) =>
                    {
                        if (e.PropertyName == nameof(ProtocoloComValue.IsSelected))
                        {
                            AddToQueueCommand.NotifyCanExecuteChanged();
                        }
                    };
                    ProtocolosScanned.Add(dto);
                }
                _logger.LogInformation("✅ Scan completo: {Count} protocolos", ProtocolosScanned.Count);

            }, "ao scanear valores", _logger);

            _logger.LogCritical("🔥 DEPOIS ExecuteWithErrorHandlingAsync");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ ERRO em ScanValuesAsync");
            System.Windows.MessageBox.Show($"ERRO: {ex.Message}", "ERRO");
        }
        finally
        {
            IsScanning = false;
            _logger.LogCritical("🔥 FIM ScanValuesAsync");
        }
    }

    private bool CanScanValues() => !IsScanning && !IsSessionRunning;

    #endregion

    #region Fila de Execução

    /// <summary>
    /// Fila de terapias para execução sequencial
    /// Drag-drop reordering suportado
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(IniciarSessaoCommand))]
    private ObservableCollection<TerapiaFilaItem> _filaTerapias = new();

    /// <summary>
    /// Indica se há sessão de terapias em execução
    /// </summary>
    [ObservableProperty]
    [NotifyCanExecuteChangedFor(nameof(ScanValuesCommand), nameof(IniciarSessaoCommand), nameof(PararSessaoCommand))]
    private bool _isSessionRunning;

    /// <summary>
    /// Nome do protocolo atualmente em execução
    /// </summary>
    [ObservableProperty]
    private string _currentProtocolName = string.Empty;

    /// <summary>
    /// Improvement % atual (baseline vs leitura atual)
    /// Atualizado em tempo real (1 Hz)
    /// </summary>
    [ObservableProperty]
    private double _currentImprovementPercent;

    /// <summary>
    /// Progresso da terapia atual (0-100)
    /// </summary>
    [ObservableProperty]
    private double _currentProgress;

    /// <summary>
    /// Comando para adicionar protocolos selecionados à fila
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanAddToQueue))]
    private void AddToQueue()
    {
        var selecionados = ProtocolosScanned.Where(p => p.IsSelected).ToList();

        if (selecionados.Count == 0)
        {
            ErrorMessage = "⚠️ Selecione pelo menos 1 protocolo";
            return;
        }

        foreach (var protocolo in selecionados)
        {
            // Verificar se já está na fila
            if (FilaTerapias.Any(f => f.ProtocoloId == protocolo.ProtocoloId))
            {
                continue;
            }

            var ordem = FilaTerapias.Count + 1;
            var item = new TerapiaFilaItem(
                protocolo.ProtocoloId,
                protocolo.Nome,
                protocolo.ValuePercent,
                ordem)
            {
                AlvoMelhoria = AlvoMelhoriaGlobal // Aplicar alvo configurado
            };

            // ✅ VALIDAÇÃO FluentValidation antes de adicionar à fila
            var validationResult = _filaItemValidator.Validate(item);
            if (!validationResult.IsValid)
            {
                var errors = string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage));
                ErrorMessage = $"❌ Validação falhou: {errors}";
                _logger.LogWarning("⚠️ Item inválido não adicionado: {Nome} - {Errors}", protocolo.Nome, errors);
                continue; // Pular este item e continuar com próximo
            }

            FilaTerapias.Add(item);
        }

        _logger.LogInformation("✅ {Count} protocolos adicionados à fila", selecionados.Count);

        // Notificar comando para reavaliar CanExecute
        IniciarSessaoCommand.NotifyCanExecuteChanged();

        // Limpar seleção
        foreach (var p in selecionados)
        {
            p.IsSelected = false;
        }
    }

    private bool CanAddToQueue()
    {
        var temSelecionados = ProtocolosScanned?.Any(p => p.IsSelected) ?? false;
        _logger.LogInformation($"🔍 CanAddToQueue: {temSelecionados} selecionados, SessionRunning={IsSessionRunning}");
        return temSelecionados && !IsSessionRunning;
    }

    /// <summary>
    /// Comando para remover item da fila
    /// </summary>
    [RelayCommand]
    private void RemoveFromQueue(TerapiaFilaItem item)
    {
        FilaTerapias.Remove(item);

        // Reordenar (1-based)
        for (int i = 0; i < FilaTerapias.Count; i++)
        {
            FilaTerapias[i].Ordem = i + 1;
        }

        // Notificar comando para reavaliar CanExecute
        IniciarSessaoCommand.NotifyCanExecuteChanged();

        _logger.LogInformation("🗑️ Protocolo '{Nome}' removido da fila", item.Nome);
    }

    /// <summary>
    /// Valor mínimo de Value% para seleção rápida
    /// </summary>
    [ObservableProperty]
    private double _filtroValueMinimo = 30.0;

    /// <summary>
    /// Alvo global de melhoria (%) para auto-stop
    /// Valores comuns: 80% (rápido), 95% (standard CoRe), 100% (máximo)
    /// Aplicado a TODOS os protocolos adicionados à fila
    /// </summary>
    [ObservableProperty]
    private double _alvoMelhoriaGlobal = 95.0;

    /// <summary>
    /// Handler quando AlvoMelhoriaGlobal muda
    /// Atualiza TODOS os protocolos já existentes na fila
    /// VALIDAÇÃO: Reverte se valor inválido (1-100%)
    /// </summary>
    partial void OnAlvoMelhoriaGlobalChanged(double value)
    {
        // ✅ VALIDAÇÃO FluentValidation: AlvoMelhoriaGlobal deve estar entre 1-100%
        if (value < 1 || value > 100)
        {
            ErrorMessage = $"❌ AlvoMelhoria deve estar entre 1-100% (valor fornecido: {value:F1}%)";
            _logger.LogWarning("⚠️ AlvoMelhoriaGlobal inválido: {Value}% - Revertido para 95%", value);
            AlvoMelhoriaGlobal = 95.0; // Reverter para valor padrão seguro
            return;
        }

        foreach (var item in FilaTerapias)
        {
            item.AlvoMelhoria = value;

            // ✅ VALIDAÇÃO: Verificar se item continua válido após mudança
            var validationResult = _filaItemValidator.Validate(item);
            if (!validationResult.IsValid)
            {
                var errors = string.Join("; ", validationResult.Errors.Select(e => e.ErrorMessage));
                ErrorMessage = $"❌ Item '{item.Nome}' inválido após mudança: {errors}";
                _logger.LogWarning("⚠️ Item inválido na fila: {Nome} - {Errors}", item.Nome, errors);
                // Não remove o item, apenas notifica - decisão UX de deixar usuário corrigir
            }
        }

        _logger.LogInformation("🎯 Alvo global alterado para {Alvo}% - {Count} protocolos atualizados",
            value, FilaTerapias.Count);
    }

    /// <summary>
    /// Comando para selecionar protocolos com Value% >= X
    /// User-friendly: 1 clique seleciona múltiplos
    /// </summary>
    [RelayCommand]
    private void SelecionarPorValue()
    {
        var selecionados = 0;

        foreach (var protocolo in ProtocolosScanned)
        {
            if (protocolo.ValuePercent >= FiltroValueMinimo)
            {
                protocolo.IsSelected = true;
                selecionados++;
            }
        }

        _logger.LogInformation("✅ {Count} protocolos selecionados (Value% >= {Min})",
            selecionados, FiltroValueMinimo);
    }

    /// <summary>
    /// Comando para selecionar Top N protocolos (maior Value%)
    /// </summary>
    [RelayCommand]
    private void SelecionarTop(int quantidade)
    {
        // Desselecionar todos primeiro
        foreach (var p in ProtocolosScanned)
        {
            p.IsSelected = false;
        }

        // Selecionar top N
        var topN = ProtocolosScanned
            .OrderByDescending(p => p.ValuePercent)
            .Take(quantidade);

        foreach (var protocolo in topN)
        {
            protocolo.IsSelected = true;
        }

        _logger.LogInformation("✅ Top {N} protocolos selecionados", quantidade);
    }

    /// <summary>
    /// Comando para desselecionar todos
    /// </summary>
    [RelayCommand]
    private void DesselecionarTodos()
    {
        foreach (var protocolo in ProtocolosScanned)
        {
            protocolo.IsSelected = false;
        }

        _logger.LogInformation("✅ Todos os protocolos desselecionados");
    }

    /// <summary>
    /// Comando para iniciar sessão de terapias (workflow completo)
    /// 1. Capturar baseline (5s)
    /// 2. Para cada protocolo na fila:
    ///    - Aplicar terapia (TiePie OUTPUT)
    ///    - Monitorizar biofeedback (Oscilloscope INPUT - 1Hz)
    ///    - Calcular Improvement % em tempo real
    ///    - Auto-stop se Improvement >= 95%
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanIniciarSessao))]
    private async Task IniciarSessaoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsSessionRunning = true;
            _sessaoCts = new CancellationTokenSource();
            var token = _sessaoCts.Token;

            _logger.LogInformation("🚀 Iniciando sessão de terapias ({Count} protocolos)", FilaTerapias.Count);

            try
            {
                // === STEP 1: Capturar Baseline (5 segundos) ===
                _logger.LogInformation("📊 Capturando baseline (5s)...");
                CurrentProtocolName = "Capturando baseline...";
                CurrentProgress = 0;

                var baseline = await _medicaoService.CapturarBaselineAsync(duracaoSegundos: 5);
                _logger.LogInformation("✅ Baseline: {Rms:N2} mV, {Freq:N2} Hz", baseline.Rms, baseline.FrequenciaDominante);

                // === STEP 2: Iniciar captura contínua (1 Hz) ===
                await _medicaoService.IniciarCapturaContinuaAsync(intervalMs: 1000);

                // === STEP 3: Aplicar cada terapia na fila ===
                foreach (var terapia in FilaTerapias)
                {
                    if (token.IsCancellationRequested)
                    {
                        _logger.LogWarning("⚠️ Sessão cancelada pelo utilizador");
                        break;
                    }

                    terapia.Estado = "Em Execução";
                    CurrentProtocolName = terapia.Nome;
                    CurrentImprovementPercent = 0;
                    CurrentProgress = 0;

                    _logger.LogInformation("⚡ Aplicando: {Nome} (Value: {Value:N2}%)", terapia.Nome, terapia.ValuePercent);

                    var inicioTerapia = DateTime.Now;
                    terapia.AplicadoEm = inicioTerapia;

                    // Obter protocolo completo (com frequências)
                    var protocolo = await _protocoloRepository.GetByIdAsync(terapia.ProtocoloId);
                    if (protocolo == null)
                    {
                        _logger.LogError("❌ Protocolo {Id} não encontrado", terapia.ProtocoloId);
                        terapia.Estado = "Erro";
                        continue;
                    }

                    // Aplicar terapia com monitorização
                    var atingiuAlvo = await AplicarTerapiaComMonitorizacaoAsync(
                        protocolo,
                        baseline,
                        terapia,
                        token);

                    // Atualizar estado final
                    terapia.DuracaoSegundos = (int)(DateTime.Now - inicioTerapia).TotalSeconds;

                    if (atingiuAlvo)
                    {
                        terapia.Estado = "Auto-Stop";
                        _logger.LogInformation("🎯 Auto-stop: Improvement = {Imp:N2}% (Alvo: {Alvo:N2}%)",
                            terapia.ImprovementPercent, terapia.AlvoMelhoria);
                    }
                    else if (token.IsCancellationRequested)
                    {
                        terapia.Estado = "Parada";
                    }
                    else
                    {
                        terapia.Estado = "Concluída";
                    }
                }

                _logger.LogInformation("✅ Sessão concluída");
                CurrentProtocolName = "Sessão concluída";

            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro durante sessão de terapias");
                ErrorMessage = $"Erro na sessão: {ex.Message}";
            }
            finally
            {
                // Parar captura contínua
                await _medicaoService.PararCapturaContinuaAsync();
                IsSessionRunning = false;
                _sessaoCts?.Dispose();
                _sessaoCts = null;
            }

        }, "ao executar sessão de terapias", _logger);
    }

    private bool CanIniciarSessao() => FilaTerapias.Count > 0 && !IsSessionRunning;

    /// <summary>
    /// Aplicar protocolo com monitorização de biofeedback em tempo real
    /// </summary>
    private async Task<bool> AplicarTerapiaComMonitorizacaoAsync(
        ProtocoloTerapeutico protocolo,
        LeituraBiofeedback baseline,
        TerapiaFilaItem terapia,
        CancellationToken token)
    {
        var frequencias = protocolo.GetFrequencias();
        var duracaoPorFreq = DuracaoPorFrequencia; // segundos

        for (int i = 0; i < frequencias.Length && !token.IsCancellationRequested; i++)
        {
            var freq = frequencias[i];
            CurrentProgress = (double)(i + 1) / frequencias.Length * 100;

            _logger.LogDebug("🎵 Frequência {Index}/{Total}: {Freq:N2} Hz", i + 1, frequencias.Length, freq);

            // Configurar sinal TiePie
            var config = new SignalConfiguration
            {
                FrequencyHz = freq,
                Channel = SignalChannel.Channel1,
                VoltageV = Voltagem,
                Waveform = SignalWaveform.Sine,
                DurationSeconds = duracaoPorFreq
            };

            // Aplicar sinal (OUTPUT)
            await _tiePieService.SendSignalAsync(config);

            // Monitorizar durante aplicação (1 leitura/segundo)
            for (int seg = 0; seg < duracaoPorFreq && !token.IsCancellationRequested; seg++)
            {
                await Task.Delay(1000, token);

                // Capturar leitura atual (INPUT)
                var leituraAtual = await _medicaoService.CapturarLeituraAsync();

                // Calcular Improvement %
                var improvement = _medicaoService.CalcularImprovementPercent(baseline, leituraAtual);
                terapia.ImprovementPercent = improvement;
                CurrentImprovementPercent = improvement;

                _logger.LogDebug("📈 Improvement: {Imp:N2}% (RMS: {Rms:N2} mV)", improvement, leituraAtual.Rms);

                // Auto-stop se atingiu alvo
                if (improvement >= terapia.AlvoMelhoria)
                {
                    _logger.LogInformation("🎯 Alvo atingido! ({Imp:N2}% >= {Alvo:N2}%)", improvement, terapia.AlvoMelhoria);
                    await _tiePieService.StopAllChannelsAsync();
                    return true; // Atingiu alvo
                }
            }
        }

        await _tiePieService.StopAllChannelsAsync();
        return false; // Não atingiu alvo
    }

    /// <summary>
    /// Comando para parar sessão de terapias
    /// CRÍTICO: Cancela CancellationToken E para hardware TiePie
    /// </summary>
    [RelayCommand(CanExecute = nameof(CanPararSessao))]
    private async Task PararSessaoAsync()
    {
        try
        {
            _logger.LogWarning("🛑 Parando sessão...");

            // 1. Cancelar token (para loops async)
            _sessaoCts?.Cancel();

            // 2. Parar hardware TiePie imediatamente
            await _tiePieService.StopAllChannelsAsync();

            // 3. Parar captura contínua
            await _medicaoService.PararCapturaContinuaAsync();

            _logger.LogInformation("✅ Sessão parada pelo utilizador");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao parar sessão");
        }
    }

    private bool CanPararSessao() => IsSessionRunning;

    #endregion

    #region IDisposable Implementation

    /// <summary>
    /// Dispose pattern para limpar recursos (CancellationTokenSource)
    /// CA1001 compliant: ViewModel tem campo disposable (_sessaoCts)
    /// </summary>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    /// <summary>
    /// Dispose protegido para herança (mesmo que não haja subclasses atualmente)
    /// </summary>
    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                // Limpar recursos managed
                _sessaoCts?.Cancel();
                _sessaoCts?.Dispose();
                _sessaoCts = null;
            }

            _disposed = true;
        }
    }

    #endregion
}
