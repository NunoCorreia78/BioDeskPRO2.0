using System;
using System.Collections.Generic;

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

    public event EventHandler<string>? NavigationRequested;

    public void Register(string viewName, Type viewType)
    {
        _views[viewName] = viewType;
    }

    public void NavigateTo(string viewName)
    {
        if (!_views.ContainsKey(viewName))
        {
            throw new ArgumentException($"View '{viewName}' não está registada.");
        }

        NavigationRequested?.Invoke(this, viewName);
    }

    /// <summary>
    /// Obtém o tipo da view registada
    /// </summary>
    public Type? GetViewType(string viewName)
    {
        return _views.TryGetValue(viewName, out var viewType) ? viewType : null;
    }
}