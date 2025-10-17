using System;

namespace BioDesk.Services.Audio;

/// <summary>
/// Serviço de estado compartilhado para configurações de terapia/emissão.
/// Permite sincronizar volume, forma de onda e dispositivo entre ViewModels.
///
/// SINGLETON: Instância única compartilhada por toda a aplicação.
/// </summary>
public interface ITerapiaStateService
{
    /// <summary>
    /// Volume de emissão (0-100%).
    /// </summary>
    int VolumePercent { get; set; }

    /// <summary>
    /// Forma de onda selecionada.
    /// </summary>
    WaveForm FormaOnda { get; set; }

    /// <summary>
    /// Dispositivo de áudio selecionado (null = padrão do sistema).
    /// </summary>
    AudioDevice? DispositivoSelecionado { get; set; }

    /// <summary>
    /// Evento disparado quando qualquer configuração muda.
    /// </summary>
    event EventHandler? ConfiguracoesAlteradas;
}
