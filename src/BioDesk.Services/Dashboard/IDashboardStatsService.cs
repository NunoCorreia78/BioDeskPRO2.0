using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using OxyPlot;

namespace BioDesk.Services.Dashboard;

/// <summary>
/// Interface para geração de estatísticas do Dashboard
/// Responsável por criar dados para gráficos e métricas visuais
/// </summary>
public interface IDashboardStatsService
{
    /// <summary>
    /// Gerar gráfico de contagem de pacientes por mês
    /// </summary>
    Task<PlotModel> GeneratePacientesPorMesChartAsync();

    /// <summary>
    /// Gerar gráfico de distribuição de idades
    /// </summary>
    Task<PlotModel> GenerateDistribuicaoIdadeChartAsync();

    /// <summary>
    /// Obter estatísticas básicas do dashboard
    /// </summary>
    Task<DashboardStats> GetDashboardStatsAsync();
}

/// <summary>
/// Modelo de dados para estatísticas do Dashboard
/// </summary>
public class DashboardStats
{
    public int TotalPacientes { get; set; }
    public int PacientesEsteAno { get; set; }
    public int PacientesEsteMes { get; set; }
    public double IdadeMedia { get; set; }
    public string PacienteMaisRecente { get; set; } = string.Empty;
}