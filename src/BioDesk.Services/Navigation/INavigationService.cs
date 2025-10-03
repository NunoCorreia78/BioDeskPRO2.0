using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Navigation;

/// <summary>
/// Interface para navegação entre views no BioDeskPro2
/// Caminho de ouro: Register("Dashboard"|"NovoPaciente"|"FichaPaciente"|"ListaPacientes")
/// SEMPRE SetPacienteAtivo + NavigateTo("FichaPaciente")
/// </summary>
public interface INavigationService
{
    /// <summary>
    /// Navega para uma view específica
    /// </summary>
    void NavigateTo(string viewName);

    /// <summary>
    /// Regista uma view no sistema de navegação
    /// </summary>
    void Register(string viewName, Type viewType);

    /// <summary>
    /// Evento disparado quando a navegação ocorre
    /// </summary>
    event EventHandler<string>? NavigationRequested;
}

/// <summary>
/// Implementação do serviço de navegação
/// Mantém o mapeamento entre nomes de views e tipos
/// </summary>
public class NavigationService : INavigationService
{
    private readonly Dictionary<string, Type> _views = new();
    private readonly ILogger<NavigationService> _logger;

    public event EventHandler<string>? NavigationRequested;

    public NavigationService(ILogger<NavigationService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public void Register(string viewName, Type viewType)
    {
        _views[viewName] = viewType;
        _logger.LogDebug("🔧 View '{ViewName}' registrada como '{ViewType}'", viewName, viewType.Name);
    }

    public void NavigateTo(string viewName)
    {
        _logger.LogInformation("🚀 NavigateTo('{ViewName}') chamado", viewName);
        
        if (!_views.ContainsKey(viewName))
        {
            _logger.LogError("❌ View '{ViewName}' não está registrada. Views disponíveis: {AvailableViews}", 
                viewName, string.Join(", ", _views.Keys));
            throw new ArgumentException($"View '{viewName}' não está registada.");
        }

        _logger.LogInformation("✅ View '{ViewName}' encontrada, disparando NavigationRequested...", viewName);
        
        try
        {
            NavigationRequested?.Invoke(this, viewName);
            _logger.LogInformation("✅ NavigationRequested disparado com sucesso para '{ViewName}'", viewName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "💥 ERRO ao disparar NavigationRequested para '{ViewName}': {Message}", viewName, ex.Message);
            throw;
        }
    }

    /// <summary>
    /// Obtém o tipo da view registada
    /// </summary>
    public Type? GetViewType(string viewName)
    {
        return _views.TryGetValue(viewName, out var viewType) ? viewType : null;
    }
}