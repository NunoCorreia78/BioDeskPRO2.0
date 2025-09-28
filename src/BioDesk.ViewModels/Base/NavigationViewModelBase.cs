using CommunityToolkit.Mvvm.ComponentModel;
using BioDesk.Services.Navigation;

namespace BioDesk.ViewModels.Base;

/// <summary>
/// Base limpa para ViewModels que precisam de navegação
/// Versão simplificada sem dependências de base de dados
/// </summary>
public abstract partial class NavigationViewModelBase : ViewModelBase
{
    protected readonly INavigationService NavigationService;

    protected NavigationViewModelBase(INavigationService navigationService)
    {
        NavigationService = navigationService;
    }
}
