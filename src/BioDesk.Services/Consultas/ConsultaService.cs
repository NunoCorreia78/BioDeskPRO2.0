using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using OxyPlot;
using OxyPlot.Axes;
using OxyPlot.Series;

namespace BioDesk.Services.Consultas;

/// <summary>
/// Implementação do serviço de gestão de consultas
/// Responsável por operações CRUD e estatísticas de consultas
/// </summary>
public class ConsultaService : IConsultaService
{
    private readonly BioDeskContext _context;
    private readonly ILogger<ConsultaService> _logger;

    public ConsultaService(BioDeskContext context, ILogger<ConsultaService> logger)
    {
        _context = context;
        _logger = logger;
    }

    /// <summary>
    /// Criar nova consulta
    /// </summary>
    public async Task<Consulta> CriarConsultaAsync(Consulta consulta)
    {
        try
        {
            consulta.DataCriacao = DateTime.Now;
            
            _context.Consultas.Add(consulta);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Consulta criada com sucesso: {ConsultaId}", consulta.Id);
            return consulta;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao criar consulta");
            throw;
        }
    }

    /// <summary>
    /// Obter consultas por paciente
    /// </summary>
    public async Task<IEnumerable<Consulta>> ObterConsultasPorPacienteAsync(int pacienteId)
    {
        try
        {
            return await _context.Consultas
                .Where(c => c.PacienteId == pacienteId)
                .Include(c => c.Paciente)
                .OrderByDescending(c => c.DataConsulta)
                .ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter consultas do paciente {PacienteId}", pacienteId);
            throw;
        }
    }

    /// <summary>
    /// Obter todas as consultas com filtros opcionais
    /// </summary>
    public async Task<IEnumerable<Consulta>> ObterConsultasAsync(DateTime? dataInicio = null, DateTime? dataFim = null)
    {
        try
        {
            var query = _context.Consultas.Include(c => c.Paciente).AsQueryable();

            if (dataInicio.HasValue)
                query = query.Where(c => c.DataConsulta >= dataInicio.Value);

            if (dataFim.HasValue)
                query = query.Where(c => c.DataConsulta <= dataFim.Value);

            return await query.OrderByDescending(c => c.DataConsulta).ToListAsync();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter consultas");
            throw;
        }
    }

    /// <summary>
    /// Atualizar consulta existente
    /// </summary>
    public async Task<Consulta> AtualizarConsultaAsync(Consulta consulta)
    {
        try
        {
            consulta.DataUltimaEdicao = DateTime.Now;
            
            _context.Consultas.Update(consulta);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Consulta atualizada com sucesso: {ConsultaId}", consulta.Id);
            return consulta;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao atualizar consulta {ConsultaId}", consulta.Id);
            throw;
        }
    }

    /// <summary>
    /// Excluir consulta
    /// </summary>
    public async Task<bool> ExcluirConsultaAsync(int consultaId)
    {
        try
        {
            var consulta = await _context.Consultas.FindAsync(consultaId);
            if (consulta == null)
            {
                _logger.LogWarning("Consulta não encontrada: {ConsultaId}", consultaId);
                return false;
            }

            _context.Consultas.Remove(consulta);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Consulta excluída com sucesso: {ConsultaId}", consultaId);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao excluir consulta {ConsultaId}", consultaId);
            throw;
        }
    }

    /// <summary>
    /// Obter estatísticas de consultas para o Dashboard
    /// </summary>
    public async Task<ConsultaStats> GetConsultaStatsAsync()
    {
        try
        {
            var hoje = DateTime.Today;
            var inicioSemana = hoje.AddDays(-(int)hoje.DayOfWeek + 1); // Segunda-feira
            var fimSemana = inicioSemana.AddDays(5); // Sábado

            var consultas = await _context.Consultas
                .Include(c => c.Paciente)
                .ToListAsync();

            var consultasEstaSemana = consultas
                .Where(c => c.DataConsulta.Date >= inicioSemana && c.DataConsulta.Date <= fimSemana)
                .ToList();

            return new ConsultaStats
            {
                TotalConsultas = consultas.Count,
                ConsultasEstaSemana = consultasEstaSemana.Count,
                PrimeirasConsultas = consultas.Count(c => c.IsPrimeiraConsulta),
                ConsultasSeguimento = consultas.Count(c => !c.IsPrimeiraConsulta),
                ConsultasAgendadas = consultas.Count(c => c.Status == "Agendada"),
                ConsultasRealizadas = consultas.Count(c => c.Status == "Realizada"),
                ValorTotalSemana = consultasEstaSemana
                    .Where(c => c.Valor.HasValue && c.Status == "Realizada")
                    .Sum(c => c.Valor!.Value)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter estatísticas de consultas");
            throw;
        }
    }

    /// <summary>
    /// Gerar gráfico de consultas por semana
    /// </summary>
    public async Task<PlotModel> GenerateConsultasPorSemanaChartAsync()
    {
        try
        {
            var consultas = await _context.Consultas
                .Where(c => c.Status == "Realizada")
                .ToListAsync();

            // Agrupar consultas por semana (últimas 8 semanas)
            var consultasPorSemana = consultas
                .Where(c => c.DataConsulta >= DateTime.Today.AddDays(-56)) // 8 semanas
                .GroupBy(c => CultureInfo.CurrentCulture.Calendar.GetWeekOfYear(
                    c.DataConsulta, CalendarWeekRule.FirstDay, DayOfWeek.Monday))
                .OrderBy(g => g.Key)
                .ToList();

            var plotModel = new PlotModel
            {
                Title = "Consultas Realizadas por Semana (Últimas 8 Semanas)",
                TitleFontSize = 14
            };

            var columnSeries = new BarSeries
            {
                Title = "Consultas",
                FillColor = OxyColor.FromRgb(156, 175, 151) // Cor terrosa
            };

            foreach (var grupo in consultasPorSemana)
            {
                columnSeries.Items.Add(new BarItem(grupo.Count()));
            }

            plotModel.Series.Add(columnSeries);

            // Configurar eixos
            plotModel.Axes.Add(new CategoryAxis
            {
                Position = AxisPosition.Left,
                Title = "Semana"
            });

            plotModel.Axes.Add(new LinearAxis
            {
                Position = AxisPosition.Bottom,
                Title = "Número de Consultas",
                Minimum = 0
            });

            return plotModel;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar gráfico de consultas por semana");
            throw;
        }
    }

    /// <summary>
    /// Gerar gráfico de primeiras consultas vs seguimento
    /// </summary>
    public async Task<PlotModel> GenerateTiposConsultaChartAsync()
    {
        try
        {
            var consultas = await _context.Consultas
                .Where(c => c.Status == "Realizada")
                .ToListAsync();

            var primeiras = consultas.Count(c => c.IsPrimeiraConsulta);
            var seguimento = consultas.Count(c => !c.IsPrimeiraConsulta);

            var plotModel = new PlotModel
            {
                Title = "Distribuição por Tipo de Consulta",
                TitleFontSize = 14
            };

            var pieSeries = new PieSeries
            {
                StrokeThickness = 2.0,
                InsideLabelPosition = 0.8,
                AngleSpan = 360,
                StartAngle = 0
            };

            pieSeries.Slices.Add(new PieSlice("Primeira Consulta", primeiras)
            {
                Fill = OxyColor.FromRgb(156, 175, 151), // Verde terroso
                IsExploded = false
            });

            pieSeries.Slices.Add(new PieSlice("Seguimento", seguimento)
            {
                Fill = OxyColor.FromRgb(227, 233, 222), // Verde claro
                IsExploded = false
            });

            plotModel.Series.Add(pieSeries);
            return plotModel;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gerar gráfico de tipos de consulta");
            throw;
        }
    }
}