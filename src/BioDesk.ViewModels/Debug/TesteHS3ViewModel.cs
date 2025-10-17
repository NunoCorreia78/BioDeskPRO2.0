using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Hardware.TiePie;

namespace BioDesk.ViewModels.Hardware;

/// <summary>
/// ViewModel para janela de teste do TiePie Handyscope HS3
/// Permite testar emissão de frequências sem integrar no sistema completo
/// </summary>
public partial class TesteHS3ViewModel : ObservableObject
{
    private readonly ITiePieHS3Service _hs3Service;
    private readonly ILogger<TesteHS3ViewModel> _logger;

    [ObservableProperty]
    private string _logs = "📋 Aguardando comandos...\n";

    [ObservableProperty]
    private bool _isConnected = false;

    [ObservableProperty]
    private bool _isEmitting = false;

    [ObservableProperty]
    private double _frequencia = 7.83; // Ressonância Schumann

    [ObservableProperty]
    private double _amplitude = 2.0; // 2V (seguro)

    [ObservableProperty]
    private string _formaOnda = "Sine";

    [ObservableProperty]
    private string _deviceInfo = "Não conectado";

    public string[] FormasOnda { get; } = new[] { "Sine", "Square", "Triangle", "DC", "Noise" };

    public TesteHS3ViewModel(
        ITiePieHS3Service hs3Service,
        ILogger<TesteHS3ViewModel> logger)
    {
        _hs3Service = hs3Service;
        _logger = logger;
    }

    [RelayCommand]
    private async Task ConectarAsync()
    {
        try
        {
            AddLog("🔌 Conectando ao HS3...");

            var success = await _hs3Service.InitializeAsync();

            if (success)
            {
                IsConnected = true;
                AddLog($"✅ HS3 conectado com sucesso!");
                AddLog($"   📟 Número de Série: {_hs3Service.SerialNumber}");

                // Obter informações completas
                var info = await _hs3Service.GetDeviceInfoAsync();
                DeviceInfo = $"Série: {_hs3Service.SerialNumber}";
                AddLog("✅ Pronto para emitir frequências!");
            }
            else
            {
                IsConnected = false;
                DeviceInfo = "Não conectado";
                AddLog("❌ HS3 não encontrado!");
                AddLog("   ℹ️ Verifique:");
                AddLog("   • HS3 está conectado via USB?");
                AddLog("   • Drivers instalados?");
                AddLog("   • hs3.dll está na pasta da aplicação?");
            }
        }
        catch (Exception ex)
        {
            IsConnected = false;
            AddLog($"❌ Erro ao conectar: {ex.Message}");
            _logger.LogError(ex, "Erro ao conectar HS3");
        }
    }

    [RelayCommand(CanExecute = nameof(CanEmitir))]
    private async Task EmitirAsync()
    {
        try
        {
            AddLog($"🎵 Configurando emissão...");
            AddLog($"   Frequência: {Frequencia} Hz");
            AddLog($"   Amplitude: {Amplitude} V");
            AddLog($"   Forma de Onda: {FormaOnda}");

            var success = await _hs3Service.EmitFrequencyAsync(Frequencia, Amplitude, FormaOnda);

            if (success)
            {
                IsEmitting = true;
                AddLog($"✅ Emissão ATIVA!");
                AddLog($"⚡ {Frequencia} Hz @ {Amplitude}V ({FormaOnda})");
                AddLog($"⚠️ CUIDADO: Não tocar nas saídas do HS3!");
            }
            else
            {
                AddLog($"❌ Falha ao iniciar emissão");
            }
        }
        catch (Exception ex)
        {
            AddLog($"❌ Erro ao emitir: {ex.Message}");
            _logger.LogError(ex, "Erro ao emitir frequência");
        }
    }

    private bool CanEmitir() => IsConnected && !IsEmitting;

    [RelayCommand(CanExecute = nameof(CanParar))]
    private async Task PararAsync()
    {
        try
        {
            AddLog("⏹️ Parando emissão...");

            await _hs3Service.StopEmissionAsync();

            IsEmitting = false;
            AddLog("✅ Emissão parada");
            AddLog("🔇 Saída desativada");
        }
        catch (Exception ex)
        {
            AddLog($"❌ Erro ao parar: {ex.Message}");
            _logger.LogError(ex, "Erro ao parar emissão");
        }
    }

    private bool CanParar() => IsConnected && IsEmitting;

    [RelayCommand(CanExecute = nameof(IsConnected))]
    private async Task MostrarInfoAsync()
    {
        try
        {
            AddLog("ℹ️ Obtendo informações do dispositivo...");

            var info = await _hs3Service.GetDeviceInfoAsync();

            AddLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            AddLog(info);
            AddLog("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }
        catch (Exception ex)
        {
            AddLog($"❌ Erro ao obter info: {ex.Message}");
            _logger.LogError(ex, "Erro ao obter informações");
        }
    }

    [RelayCommand]
    private void LimparLogs()
    {
        Logs = "📋 Logs limpos\n";
    }

    [RelayCommand]
    private void PresetSchumann()
    {
        Frequencia = 7.83;
        Amplitude = 2.0;
        FormaOnda = "Sine";
        AddLog("🌍 Preset: Ressonância Schumann (7.83 Hz)");
    }

    [RelayCommand]
    private void PresetSolfeggio()
    {
        Frequencia = 528.0;
        Amplitude = 2.0;
        FormaOnda = "Sine";
        AddLog("🎵 Preset: Solfeggio 528 Hz (Transformação/Milagres)");
    }

    [RelayCommand]
    private void PresetRife()
    {
        Frequencia = 20.0;
        Amplitude = 1.5;
        FormaOnda = "Square";
        AddLog("⚡ Preset: Rife 20 Hz (Detox)");
    }

    private void AddLog(string message)
    {
        var timestamp = DateTime.Now.ToString("HH:mm:ss");
        Logs += $"[{timestamp}] {message}\n";

        // Auto-scroll simulado (últimas 50 linhas)
        var lines = Logs.Split('\n');
        if (lines.Length > 50)
        {
            Logs = string.Join("\n", lines[^50..]);
        }
    }

    partial void OnIsConnectedChanged(bool value)
    {
        // Notificar comandos que dependem de IsConnected
        EmitirCommand.NotifyCanExecuteChanged();
        PararCommand.NotifyCanExecuteChanged();
        MostrarInfoCommand.NotifyCanExecuteChanged();
    }

    partial void OnIsEmittingChanged(bool value)
    {
        // Notificar comandos que dependem de IsEmitting
        EmitirCommand.NotifyCanExecuteChanged();
        PararCommand.NotifyCanExecuteChanged();
    }
}
