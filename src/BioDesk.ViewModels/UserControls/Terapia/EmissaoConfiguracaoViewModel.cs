using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Services.Audio;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.UserControls.Terapia;

/// <summary>
/// ViewModel para configuração de emissão de frequências.
///
/// FUNCIONALIDADES:
/// - Seleção de dispositivo de áudio (prioriza TiePie HS3)
/// - Ajuste de volume (0-100%)
/// - Seleção de forma de onda
/// - Teste de emissão (440 Hz - Lá musical)
/// </summary>
public partial class EmissaoConfiguracaoViewModel : ViewModelBase
{
    private readonly IFrequencyEmissionService _emissionService;
    private readonly ITerapiaStateService _stateService;
    private readonly ILogger<EmissaoConfiguracaoViewModel> _logger;

    [ObservableProperty] private ObservableCollection<AudioDevice> _dispositivosDisponiveis = new();
    [ObservableProperty] private bool _testando = false;
    [ObservableProperty] private string _mensagemTeste = string.Empty;

    // ✅ PROPRIEDADES LIGADAS AO TerapiaStateService (estado compartilhado)
    public AudioDevice? DispositivoSelecionado
    {
        get => _stateService.DispositivoSelecionado;
        set
        {
            if (_stateService.DispositivoSelecionado != value)
            {
                _stateService.DispositivoSelecionado = value;
                OnPropertyChanged();
                _ = AlterarDispositivoAsync(); // Aplicar mudança ao FrequencyEmissionService
            }
        }
    }

    public int VolumePercent
    {
        get => _stateService.VolumePercent;
        set
        {
            if (_stateService.VolumePercent != value)
            {
                _stateService.VolumePercent = value;
                OnPropertyChanged();
            }
        }
    }

    public WaveForm FormaOndaSelecionada
    {
        get => _stateService.FormaOnda;
        set
        {
            if (_stateService.FormaOnda != value)
            {
                _stateService.FormaOnda = value;
                OnPropertyChanged();
            }
        }
    }

    public ObservableCollection<WaveFormOption> FormasOnda { get; } = new()
    {
        new WaveFormOption("Senoidal (Suave)", WaveForm.Sine, "🌊"),
        new WaveFormOption("Quadrada (Incisiva)", WaveForm.Square, "⬛"),
        new WaveFormOption("Triangular (Híbrida)", WaveForm.Triangle, "🔺"),
        new WaveFormOption("Dente de Serra", WaveForm.Sawtooth, "📐")
    };

    public EmissaoConfiguracaoViewModel(
        IFrequencyEmissionService emissionService,
        ITerapiaStateService stateService,
        ILogger<EmissaoConfiguracaoViewModel> logger)
    {
        _emissionService = emissionService;
        _stateService = stateService;
        _logger = logger;
    }

    /// <summary>
    /// Carrega dispositivos disponíveis (chamado ao abrir controlo).
    /// </summary>
    [RelayCommand]
    private async Task CarregarDispositivosAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var dispositivos = await _emissionService.GetAvailableDevicesAsync();
            DispositivosDisponiveis = new ObservableCollection<AudioDevice>(dispositivos);

            // Selecionar TiePie HS3 se disponível, senão padrão
            DispositivoSelecionado = dispositivos.FirstOrDefault(d =>
                d.Name.Contains("TiePie", StringComparison.OrdinalIgnoreCase) ||
                d.Name.Contains("Handyscope", StringComparison.OrdinalIgnoreCase))
                ?? dispositivos.FirstOrDefault(d => d.IsDefault)
                ?? dispositivos.FirstOrDefault();

            if (DispositivoSelecionado != null)
            {
                await _emissionService.SelectDeviceAsync(DispositivoSelecionado.Id);
                _logger.LogInformation("🔊 Dispositivo selecionado: {Name}", DispositivoSelecionado.Name);
            }
        },
        errorContext: "ao carregar dispositivos de áudio",
        logger: _logger);
    }

    /// <summary>
    /// Altera dispositivo selecionado.
    /// </summary>
    [RelayCommand]
    private async Task AlterarDispositivoAsync()
    {
        if (DispositivoSelecionado != null)
        {
            await ExecuteWithErrorHandlingAsync(async () =>
            {
                await _emissionService.SelectDeviceAsync(DispositivoSelecionado.Id);
                _logger.LogInformation("🔊 Dispositivo alterado: {Name}", DispositivoSelecionado.Name);
            },
            errorContext: "ao alterar dispositivo de áudio",
            logger: _logger);
        }
    }

    /// <summary>
    /// Testa emissão com 440 Hz (Lá musical) por 2 segundos.
    /// </summary>
    [RelayCommand]
    private async Task TestarEmissaoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            Testando = true;
            MensagemTeste = "🎵 Emitindo 440 Hz (Lá musical)...";

            var result = await _emissionService.EmitFrequencyAsync(
                frequencyHz: 440,
                durationSeconds: 2,
                volumePercent: VolumePercent,
                waveForm: FormaOndaSelecionada);

            if (result.Success)
            {
                MensagemTeste = $"✅ Teste concluído! Duração: {result.Duration.TotalSeconds:F1}s";
                _logger.LogInformation("✅ Teste de emissão bem-sucedido");
            }
            else
            {
                MensagemTeste = $"❌ Erro: {result.Message}";
                _logger.LogWarning("❌ Teste de emissão falhou: {Message}", result.Message);
            }

            // Limpar mensagem após 5 segundos
            _ = Task.Run(async () =>
            {
                await Task.Delay(5000);
                MensagemTeste = string.Empty;
            });
        },
        errorContext: "ao testar emissão",
        logger: _logger)
        .ContinueWith(_ => Testando = false);
    }
}

/// <summary>
/// Opção de forma de onda para ComboBox.
/// </summary>
public record WaveFormOption(string Nome, WaveForm Tipo, string Emoji);
