using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace BioDesk.Services.Activity;

/// <summary>
/// Serviço para tracking de atividade recente no sistema
/// Monitoriza ações dos utilizadores, pacientes recentes, emails, etc.
/// </summary>
public interface IActivityService
{
    /// <summary>
    /// Obter lista de pacientes recentes (últimos 7 dias)
    /// </summary>
    Task<List<PacienteRecenteItem>> GetPacientesRecentesAsync(int dias = 7);

    /// <summary>
    /// Obter atividade recente geral do sistema
    /// </summary>
    Task<List<AtividadeItem>> GetAtividadeRecenteAsync(int count = 20);

    /// <summary>
    /// Registar nova atividade no sistema
    /// </summary>
    Task RegistrarAtividadeAsync(TipoAtividade tipo, string descricao, object? metadata = null);

    /// <summary>
    /// Obter estatísticas de emails
    /// </summary>
    Task<EmailStats> GetEmailStatsAsync();
}

/// <summary>
/// Item de paciente recente para o dashboard
/// </summary>
public class PacienteRecenteItem
{
    public int Id { get; set; }
    public string Nome { get; set; } = string.Empty;
    public DateTime DataCriacao { get; set; }
    public string Email { get; set; } = string.Empty;
    public string TempoDecorrido => CalcularTempoDecorrido(DataCriacao);

    private static string CalcularTempoDecorrido(DateTime data)
    {
        var diferenca = DateTime.Now - data;
        if (diferenca.TotalMinutes < 1) return "Agora mesmo";
        if (diferenca.TotalMinutes < 60) return $"há {(int)diferenca.TotalMinutes} min";
        if (diferenca.TotalHours < 24) return $"há {(int)diferenca.TotalHours}h";
        if (diferenca.TotalDays < 7) return $"há {(int)diferenca.TotalDays} dias";
        return data.ToString("dd/MM/yyyy");
    }
}

/// <summary>
/// Item de atividade geral do sistema
/// </summary>
public class AtividadeItem
{
    public int Id { get; set; }
    public TipoAtividade Tipo { get; set; }
    public string Descricao { get; set; } = string.Empty;
    public DateTime DataHora { get; set; }
    public string? Metadata { get; set; }
    public string Icon => GetIconForTipo(Tipo);
    public string TempoDecorrido => CalcularTempoDecorrido(DataHora);

    private static string GetIconForTipo(TipoAtividade tipo) => tipo switch
    {
        TipoAtividade.PacienteCriado => "👤",
        TipoAtividade.EmailEnviado => "📧",
        TipoAtividade.EmailPendente => "⏳",
        TipoAtividade.SystemAction => "⚙️",
        TipoAtividade.Login => "🔑",
        _ => "ℹ️"
    };

    private static string CalcularTempoDecorrido(DateTime data)
    {
        var diferenca = DateTime.Now - data;
        if (diferenca.TotalMinutes < 1) return "Agora mesmo";
        if (diferenca.TotalMinutes < 60) return $"há {(int)diferenca.TotalMinutes} min";
        if (diferenca.TotalHours < 24) return $"há {(int)diferenca.TotalHours}h";
        return data.ToString("dd/MM HH:mm");
    }
}

/// <summary>
/// Tipos de atividade monitorizados
/// </summary>
public enum TipoAtividade
{
    PacienteCriado,
    EmailEnviado,
    EmailPendente,
    SystemAction,
    Login
}

/// <summary>
/// Estatísticas de emails
/// </summary>
public class EmailStats
{
    public int EmailsEnviados { get; set; }
    public int EmailsPendentes { get; set; }
    public int EmailsFalhados { get; set; }
    public DateTime UltimoEnvio { get; set; }
}