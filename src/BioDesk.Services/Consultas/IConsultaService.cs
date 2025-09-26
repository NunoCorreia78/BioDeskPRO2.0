using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Entities;
using OxyPlot;

namespace BioDesk.Services.Consultas;

/// <summary>
/// Interface para gestão de consultas
/// Responsável por operações CRUD e estatísticas de consultas
/// </summary>
public interface IConsultaService
{
    /// <summary>
    /// Criar nova consulta
    /// </summary>
    Task<Consulta> CriarConsultaAsync(Consulta consulta);

    /// <summary>
    /// Obter consultas por paciente
    /// </summary>
    Task<IEnumerable<Consulta>> ObterConsultasPorPacienteAsync(int pacienteId);

    /// <summary>
    /// Obter todas as consultas com filtros opcionais
    /// </summary>
    Task<IEnumerable<Consulta>> ObterConsultasAsync(DateTime? dataInicio = null, DateTime? dataFim = null);

    /// <summary>
    /// Atualizar consulta existente
    /// </summary>
    Task<Consulta> AtualizarConsultaAsync(Consulta consulta);

    /// <summary>
    /// Excluir consulta
    /// </summary>
    Task<bool> ExcluirConsultaAsync(int consultaId);

    /// <summary>
    /// Obter estatísticas de consultas para o Dashboard
    /// </summary>
    Task<ConsultaStats> GetConsultaStatsAsync();

    /// <summary>
    /// Gerar gráfico de consultas por semana
    /// </summary>
    Task<PlotModel> GenerateConsultasPorSemanaChartAsync();

    /// <summary>
    /// Gerar gráfico de primeiras consultas vs seguimento
    /// </summary>
    Task<PlotModel> GenerateTiposConsultaChartAsync();
}

/// <summary>
/// Modelo de dados para estatísticas de consultas
/// </summary>
public class ConsultaStats
{
    public int TotalConsultas { get; set; }
    public int ConsultasEstaSemana { get; set; }
    public int PrimeirasConsultas { get; set; }
    public int ConsultasSeguimento { get; set; }
    public int ConsultasAgendadas { get; set; }
    public int ConsultasRealizadas { get; set; }
    public decimal ValorTotalSemana { get; set; }
}