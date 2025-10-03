using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using System.Timers;
using Microsoft.Extensions.Logging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Data.Repositories;
using BioDesk.Services.Navigation;
using BioDesk.Services.Cache;
using BioDesk.Domain.Entities;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// DashboardViewModel - Dashboard com estatísticas em tempo real da BD
/// Usa Repository + UnitOfWork + Cache para performance otimizada
/// </summary>
public partial class DashboardViewModel : NavigationViewModelBase, IDisposable
{
    private readonly ILogger<DashboardViewModel> _logger;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ICacheService _cache;
    private readonly Timer _refreshTimer;
    private bool _disposed = false;

    #region === PROPRIEDADES DE ESTATÍSTICAS ===

    [ObservableProperty]
    private int _totalPacientes;

    [ObservableProperty]
    private int _consultasHoje;

    [ObservableProperty]
    private int _consultasSemana;

    [ObservableProperty]
    private int _consultasMes;

    [ObservableProperty]
    private int _emailsPendentes;

    [ObservableProperty]
    private ObservableCollection<Paciente> _pacientesRecentes = new();

    [ObservableProperty]
    private DateTime _dataAtual = DateTime.Now;

    [ObservableProperty]
    private DateTime _ultimaAtualizacao;

    [ObservableProperty]
    private string _statusMessage = "Sistema BioDeskPro2 ativo";

    [ObservableProperty]
    private bool _isSystemActive = true;

    [ObservableProperty]
    private bool _isLoadingStats = false;

    #endregion

    public DashboardViewModel(
        INavigationService navigationService,
        ILogger<DashboardViewModel> logger,
        IUnitOfWork unitOfWork,
        ICacheService cache) : base(navigationService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));

        _logger.LogInformation("🚀 DashboardViewModel inicializado com estatísticas BD");

        // Carregar estatísticas iniciais
        _ = CarregarEstatisticasAsync();

        // Configurar auto-refresh a cada 30 segundos
        _refreshTimer = new Timer(30000); // 30 segundos
        _refreshTimer.Elapsed += async (s, e) => await RefreshEstatisticasAsync();
        _refreshTimer.AutoReset = true;
        _refreshTimer.Start();

        _logger.LogInformation("⏰ Auto-refresh de estatísticas configurado (30s)");
    }

    #region === COMANDOS ===

    [RelayCommand]
    private void NovoPaciente()
    {
        _logger.LogInformation("📝 Criando novo paciente...");

        // ✅ LIMPAR paciente ativo para criar novo em branco
        PacienteService.Instance.SetPacienteAtivo(null);

        NavigationService.NavigateTo("FichaPaciente");

        _logger.LogInformation("✅ Navegado para FichaPaciente (novo paciente em branco)");
    }

    [RelayCommand]
    private void ListaPacientes()
    {
        _logger.LogInformation("📋 Navegando para Lista de Pacientes...");
        NavigationService.NavigateTo("ListaPacientes");
    }

    [RelayCommand]
    private void AbrirConfiguracoes()
    {
        _logger.LogInformation("⚙️ Abrindo janela de Configurações...");
        // Este comando será tratado no code-behind da view
    }

    [RelayCommand]
    private void NavegarParaFicha()
    {
        NovoPaciente();
    }

    [RelayCommand]
    private async Task RefreshEstatisticas()
    {
        await RefreshEstatisticasAsync();
    }

    #endregion

    #region === MÉTODOS DE CARREGAMENTO ===

    /// <summary>
    /// Carrega todas as estatísticas com cache
    /// Cache TTL: 2 minutos (para estatísticas que mudam pouco)
    /// </summary>
    private async Task CarregarEstatisticasAsync()
    {
        if (IsLoadingStats) return;

        IsLoadingStats = true;
        _logger.LogInformation("📊 Carregando estatísticas do Dashboard...");

        try
        {
            await ExecuteWithErrorHandlingAsync(async () =>
            {
                // Total de pacientes (cache 5 min - muda raramente)
                TotalPacientes = await _cache.GetOrCreateAsync(
                    CacheKeys.TotalPacientes,
                    async () => await _unitOfWork.Pacientes.CountTotalAsync(),
                    TimeSpan.FromMinutes(5)
                );

                // Consultas hoje (cache 2 min - muda frequentemente)
                ConsultasHoje = await _cache.GetOrCreateAsync(
                    CacheKeys.ConsultasHoje,
                    async () => await _unitOfWork.Sessoes.CountHojeAsync(),
                    TimeSpan.FromMinutes(2)
                );

                // Consultas da semana (cache 5 min)
                var inicioSemana = DateTime.Today.AddDays(-(int)DateTime.Today.DayOfWeek);
                ConsultasSemana = await _cache.GetOrCreateAsync(
                    "Dashboard:ConsultasSemana",
                    async () => await _unitOfWork.Sessoes.CountByPeriodoAsync(inicioSemana, DateTime.Now),
                    TimeSpan.FromMinutes(5)
                );

                // Consultas do mês (cache 10 min)
                var inicioMes = new DateTime(DateTime.Today.Year, DateTime.Today.Month, 1);
                ConsultasMes = await _cache.GetOrCreateAsync(
                    "Dashboard:ConsultasMes",
                    async () => await _unitOfWork.Sessoes.CountByPeriodoAsync(inicioMes, DateTime.Now),
                    TimeSpan.FromMinutes(10)
                );

                // Emails pendentes (cache 1 min - crítico)
                EmailsPendentes = await _cache.GetOrCreateAsync(
                    CacheKeys.EmailsPendentes,
                    async () => await _unitOfWork.Comunicacoes.CountAsync(c => !c.IsEnviado),
                    TimeSpan.FromMinutes(1)
                );

                // Pacientes recentes (cache 5 min)
                var pacientesRecentes = await _cache.GetOrCreateAsync(
                    "Dashboard:PacientesRecentes",
                    async () => await _unitOfWork.Pacientes.GetRecentesAsync(5),
                    TimeSpan.FromMinutes(5)
                );

                PacientesRecentes = new ObservableCollection<Paciente>(pacientesRecentes);

                UltimaAtualizacao = DateTime.Now;
                StatusMessage = $"✅ Sistema ativo - Atualizado às {UltimaAtualizacao:HH:mm:ss}";

                _logger.LogInformation("✅ Estatísticas carregadas: {Total} pacientes, {Hoje} consultas hoje",
                    TotalPacientes, ConsultasHoje);

            }, "Carregar estatísticas", _logger);
        }
        finally
        {
            IsLoadingStats = false;
        }
    }

    /// <summary>
    /// Refresh forçado (invalida cache e recarrega)
    /// </summary>
    private async Task RefreshEstatisticasAsync()
    {
        _logger.LogInformation("🔄 Refresh forçado de estatísticas...");

        // Invalidar cache do dashboard
        _cache.RemoveByPrefix(CacheKeys.PrefixDashboard);
        _cache.Remove("Dashboard:ConsultasSemana");
        _cache.Remove("Dashboard:ConsultasMes");
        _cache.Remove("Dashboard:PacientesRecentes");

        // Recarregar
        await CarregarEstatisticasAsync();
    }

    #endregion

    #region === DISPOSE ===

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _refreshTimer?.Stop();
            _refreshTimer?.Dispose();
            _unitOfWork?.Dispose();
        }
        _disposed = true;
    }

    #endregion
}
