using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace BioDesk.Services.Settings;

/// <summary>
/// Implementação do serviço de configurações usando JSON
/// </summary>
public class SettingsService : ISettingsService
{
    private readonly string _settingsPath;
    private readonly Dictionary<string, object> _settings;

    public SettingsService()
    {
        // Caminho para o arquivo de configurações na pasta de dados da aplicação
        var appDataPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), 
            "BioDeskPro2");
        
        if (!Directory.Exists(appDataPath))
        {
            Directory.CreateDirectory(appDataPath);
        }

        _settingsPath = Path.Combine(appDataPath, "settings.json");
        _settings = new Dictionary<string, object>();
        
        LoadSettings();
    }

    /// <summary>
    /// Auto-save ativo por padrão
    /// </summary>
    public bool AutoSaveEnabled
    {
        get => GetSetting("AutoSaveEnabled", true);
        set => SetSetting("AutoSaveEnabled", value);
    }

    /// <summary>
    /// Intervalo de auto-save: 3 segundos por padrão
    /// </summary>
    public int AutoSaveIntervalSeconds
    {
        get => GetSetting("AutoSaveIntervalSeconds", 3);
        set => SetSetting("AutoSaveIntervalSeconds", value);
    }

    public T GetSetting<T>(string key, T defaultValue = default!)
    {
        if (_settings.TryGetValue(key, out var value))
        {
            try
            {
                if (value is JsonElement jsonElement)
                {
                    return JsonSerializer.Deserialize<T>(jsonElement.GetRawText()) ?? defaultValue;
                }
                return (T)value;
            }
            catch
            {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    public void SetSetting<T>(string key, T value)
    {
        _settings[key] = value!;
    }

    public void SaveSettings()
    {
        try
        {
            var json = JsonSerializer.Serialize(_settings, new JsonSerializerOptions 
            { 
                WriteIndented = true 
            });
            File.WriteAllText(_settingsPath, json);
        }
        catch
        {
            // Log error silently - não quebrar a aplicação por problemas de configuração
        }
    }

    public void LoadSettings()
    {
        try
        {
            if (File.Exists(_settingsPath))
            {
                var json = File.ReadAllText(_settingsPath);
                var loadedSettings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);
                
                if (loadedSettings != null)
                {
                    _settings.Clear();
                    foreach (var kvp in loadedSettings)
                    {
                        _settings[kvp.Key] = kvp.Value;
                    }
                }
            }
        }
        catch
        {
            // Se falhar ao carregar, usar valores padrão
            _settings.Clear();
        }
    }
}