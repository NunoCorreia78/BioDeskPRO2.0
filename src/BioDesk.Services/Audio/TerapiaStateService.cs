using System;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Audio;

/// <summary>
/// Implementação de estado compartilhado para configurações de terapia.
/// Singleton: Instância única garante sincronização entre ViewModels.
/// </summary>
public sealed class TerapiaStateService : ITerapiaStateService
{
    private readonly ILogger<TerapiaStateService> _logger;
    private int _volumePercent = 70; // Padrão: 70% (~7V no TiePie HS3)
    private WaveForm _formaOnda = WaveForm.Sine; // Padrão: Senoidal
    private AudioDevice? _dispositivoSelecionado;

    public event EventHandler? ConfiguracoesAlteradas;

    public int VolumePercent
    {
        get => _volumePercent;
        set
        {
            if (_volumePercent != value && value >= 0 && value <= 100)
            {
                _volumePercent = value;
                _logger.LogInformation("🔊 Volume alterado: {Volume}%", value);
                OnConfiguracoesAlteradas();
            }
        }
    }

    public WaveForm FormaOnda
    {
        get => _formaOnda;
        set
        {
            if (_formaOnda != value)
            {
                _formaOnda = value;
                _logger.LogInformation("🌊 Forma de onda alterada: {WaveForm}", value);
                OnConfiguracoesAlteradas();
            }
        }
    }

    public AudioDevice? DispositivoSelecionado
    {
        get => _dispositivoSelecionado;
        set
        {
            if (_dispositivoSelecionado?.Id != value?.Id)
            {
                _dispositivoSelecionado = value;
                _logger.LogInformation("🔊 Dispositivo alterado: {Name}", value?.Name ?? "Padrão do sistema");
                OnConfiguracoesAlteradas();
            }
        }
    }

    public TerapiaStateService(ILogger<TerapiaStateService> logger)
    {
        _logger = logger;
        _logger.LogInformation("✅ TerapiaStateService inicializado (Volume: {Volume}%, Forma: {WaveForm})",
            _volumePercent, _formaOnda);
    }

    private void OnConfiguracoesAlteradas()
    {
        ConfiguracoesAlteradas?.Invoke(this, EventArgs.Empty);
    }
}
