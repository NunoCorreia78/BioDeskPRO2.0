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
    /// Gerar gráfico de distribuição de idades
    /// </summary>
    public async Task<PlotModel> GenerateDistribuicaoIdadeChartAsync()
    {
        try
        {
            var pacientes = await _pacienteService.SearchAsync(string.Empty);
            var hoje = DateTime.Today;

            // Calcular idades e agrupar
            var idades = pacientes
                .Select(p => (int)((hoje - p.DataNascimento).TotalDays / 365.25))
                .Where(idade => idade >= 0)
                .ToList();

            // Agrupar por faixas etárias
            var faixasEtarias = new[]
            {
                new { Nome = "0-18", Min = 0, Max = 18 },
                new { Nome = "19-30", Min = 19, Max = 30 },
                new { Nome = "31-45", Min = 31, Max = 45 },
                new { Nome = "46-60", Min = 46, Max = 60 },
                new { Nome = "60+", Min = 61, Max = int.MaxValue }
            };

            var distribuicao = faixasEtarias
                .Select(faixa => new
                {
                    faixa.Nome,
                    Quantidade = idades.Count(i => i >= faixa.Min && i <= faixa.Max)
                })
                .Where(item => item.Quantidade > 0)
                .ToList();

            var plotModel = new PlotModel
            {
                Title = "Distribuição de Idades",
                TitleFontSize = 16,
                Background = OxyColors.Transparent
            };

            // Criar série de pizza
            var pieSeries = new PieSeries
            {
                StrokeThickness = 2,
                InsideLabelPosition = 0.5,
                OutsideLabelFormat = "{1}: {2:0}%",
                TickDistance = 0
            };

            var cores = new[]
            {
                OxyColor.FromRgb(156, 175, 151), // Verde terroso
                OxyColor.FromRgb(135, 155, 131), // Verde mais escuro
                OxyColor.FromRgb(174, 188, 170), // Verde claro
                OxyColor.FromRgb(195, 205, 192), // Verde muito claro
                OxyColor.FromRgb(115, 135, 111)  // Verde escuro
            };

            for (int i = 0; i < distribuicao.Count; i++)
            {
                var item = distribuicao[i];
                pieSeries.Slices.Add(new PieSlice(item.Nome, item.Quantidade)
                {
                    Fill = cores[i % cores.Length]
                });
            }

            plotModel.Series.Add(pieSeries);

            _logger.LogInformation($"Gráfico de distribuição de idades gerado com {distribuicao.Count} faixas");

            return plotModel;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar gráfico de distribuição de idades");
            return CreateErrorPlotModel("Erro ao carregar distribuição");
        }
    }

    /// <summary>
    /// Obter estatísticas básicas do dashboard
    /// </summary>
    public async Task<DashboardStats> GetDashboardStatsAsync()
    {
        try
        {
            var pacientes = await _pacienteService.SearchAsync(string.Empty);
            var hoje = DateTime.Today;
            var inicioAno = new DateTime(hoje.Year, 1, 1);
            var inicioMes = new DateTime(hoje.Year, hoje.Month, 1);

            var stats = new DashboardStats
            {
                TotalPacientes = pacientes.Count,
                PacientesEsteAno = pacientes.Count(p => p.DataNascimento >= inicioAno),
                PacientesEsteMes = pacientes.Count(p => p.DataNascimento >= inicioMes),
                IdadeMedia = pacientes.Any() 
                    ? pacientes.Average(p => (hoje - p.DataNascimento).TotalDays / 365.25)
                    : 0,
                PacienteMaisRecente = pacientes
                    .OrderByDescending(p => p.DataNascimento)
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