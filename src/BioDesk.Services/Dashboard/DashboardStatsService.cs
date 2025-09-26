using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BioDesk.Services.Pacientes;
using BioDesk.Domain.Entities;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;
using System.Globalization;

namespace BioDesk.Services.Dashboard;

/// <summary>
/// Implementação do serviço de estatísticas do Dashboard
/// Gera dados para gráficos OxyPlot com base nos pacientes registados
/// </summary>
public class DashboardStatsService : IDashboardStatsService
{
    private readonly IPacienteService _pacienteService;
    private readonly ILogger<DashboardStatsService> _logger;

    public DashboardStatsService(
        IPacienteService pacienteService,
        ILogger<DashboardStatsService> logger)
    {
        _pacienteService = pacienteService;
        _logger = logger;
    }

    /// <summary>
    /// Gerar gráfico de contagem de pacientes por mês
    /// </summary>
    public async Task<PlotModel> GeneratePacientesPorMesChartAsync()
    {
        try
        {
            var pacientes = await _pacienteService.SearchAsync(string.Empty);

            // Agrupar pacientes por mês/ano da data de criação
            var pacientesPorMes = pacientes
                .GroupBy(p => new { p.CriadoEm.Year, p.CriadoEm.Month })
                .OrderBy(g => g.Key.Year)
                .ThenBy(g => g.Key.Month)
                .Take(12) // Últimos 12 meses
                .ToList();

            var plotModel = new PlotModel
            {
                Title = "Pacientes Registrados por Mês",
                TitleFontSize = 16,
                Background = OxyColors.Transparent
            };

            // Configurar eixos - Para BarSeries: CategoryAxis no Y (Left), LinearAxis no X (Bottom)
            plotModel.Axes.Add(new CategoryAxis
            {
                Position = AxisPosition.Left,
                Title = "Mês",
                ItemsSource = pacientesPorMes.Select(g => 
                    new DateTime(g.Key.Year, g.Key.Month, 1).ToString("MMM/yyyy", new CultureInfo("pt-PT"))).ToArray()
            });

            plotModel.Axes.Add(new LinearAxis
            {
                Position = AxisPosition.Bottom,
                Title = "Número de Pacientes",
                Minimum = 0
            });

            // Criar série de barras
            var barSeries = new BarSeries
            {
                Title = "Pacientes",
                FillColor = OxyColor.FromRgb(156, 175, 151), // Verde terroso
                StrokeColor = OxyColor.FromRgb(135, 155, 131),
                StrokeThickness = 1
            };

            foreach (var grupo in pacientesPorMes)
            {
                barSeries.Items.Add(new BarItem(grupo.Count()));
            }

            plotModel.Series.Add(barSeries);

            _logger.LogInformation($"Gráfico de pacientes por mês gerado com {pacientesPorMes.Count} grupos");

            return plotModel;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar gráfico de pacientes por mês");
            return CreateErrorPlotModel("Erro ao carregar dados");
        }
    }

    /// <summary>
    /// Gerar gráfico de distribuição de idades - Desabilitado após remoção de DataNascimento
    /// </summary>
    public Task<PlotModel> GenerateDistribuicaoIdadeChartAsync()
    {
        try
        {
            // Gráfico desabilitado após remoção de DataNascimento
            var plotModel = new PlotModel
            {
                Title = "Distribuição de Idades - Funcionalidade Desabilitada",
                TitleFontSize = 16,
                Background = OxyColors.Transparent
            };

            return Task.FromResult(plotModel);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar gráfico de distribuição de idades");
            return Task.FromResult(CreateErrorPlotModel("Erro ao carregar distribuição"));
        }
    }

    /// <summary>
    /// Obter estatísticas básicas do dashboard - Simplificado após remoção de DataNascimento
    /// </summary>
    public async Task<DashboardStats> GetDashboardStatsAsync()
    {
        try
        {
            var pacientes = await _pacienteService.SearchAsync(string.Empty);

            var stats = new DashboardStats
            {
                TotalPacientes = pacientes.Count,
                // Estatísticas por idade desabilitadas após remoção de DataNascimento
                PacientesEsteAno = 0,
                PacientesEsteMes = 0,
                IdadeMedia = 0,
                PacienteMaisRecente = pacientes
                    .OrderByDescending(p => p.CriadoEm)
                    .FirstOrDefault()?.Nome ?? "Nenhum"
            };

            _logger.LogInformation($"Estatísticas calculadas: {stats.TotalPacientes} pacientes total");

            return stats;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao calcular estatísticas do dashboard");
            return new DashboardStats();
        }
    }

    /// <summary>
    /// Criar gráfico de erro para quando há problemas
    /// </summary>
    private static PlotModel CreateErrorPlotModel(string mensagem)
    {
        var plotModel = new PlotModel
        {
            Title = mensagem,
            TitleFontSize = 14,
            Background = OxyColors.Transparent,
            PlotAreaBorderColor = OxyColors.LightGray
        };

        return plotModel;
    }
}