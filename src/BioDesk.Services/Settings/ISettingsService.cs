using System;

namespace BioDesk.Services.Settings;

/// <summary>
/// Interface para o serviço de configurações da aplicação
/// </summary>
public interface ISettingsService
{
    /// <summary>
    /// Obtém se o auto-save está ativo
    /// </summary>
    bool AutoSaveEnabled { get; set; }

    /// <summary>
    /// Intervalo de auto-save em segundos
    /// </summary>
    int AutoSaveIntervalSeconds { get; set; }

    /// <summary>
    /// Obtém uma configuração do tipo T
    /// </summary>
    T GetSetting<T>(string key, T defaultValue = default!);

    /// <summary>
    /// Define uma configuração
    /// </summary>
    void SetSetting<T>(string key, T value);

    /// <summary>
    /// Salva as configurações
    /// </summary>
    void SaveSettings();

    /// <summary>
    /// Carrega as configurações
    /// </summary>
    void LoadSettings();
}