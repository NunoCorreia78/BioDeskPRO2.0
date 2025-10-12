using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Media;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Services.Rng;
using BioDesk.Services.Hardware;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.UserControls;

/// <summary>
/// ViewModel para interface de Terapias Bioenergéticas com RNG e TiePie HS5
/// </summary>
public partial class TerapiasBioenergeticasUserControlViewModel : ViewModelBase
{
    private readonly IProtocoloRepository _protocoloRepository;
    private readonly IRngService _rngService;
    private readonly ITiePieHardwareService _tiePieService;
    private readonly ILogger<TerapiasBioenergeticasUserControlViewModel> _logger;

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
        ILogger<TerapiasBioenergeticasUserControlViewModel> logger)
    {
        _protocoloRepository = protocoloRepository;
        _rngService = rngService;
        _tiePieService = tiePieService;
        _logger = logger;

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
}
