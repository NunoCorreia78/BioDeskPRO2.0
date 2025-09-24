using BioDesk.Services.Pacientes;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace BioDesk.Services.Activity;

/// <summary>
/// Implementação do serviço de atividade recente
/// Utiliza dados reais dos pacientes e simula sistema de email/logging
/// </summary>
public class ActivityService : IActivityService
{
    private readonly IPacienteService _pacienteService;
    private readonly ILogger<ActivityService> _logger;
    
    // Simulação de atividades em memória (em produção seria base de dados)
    private static readonly List<AtividadeItem> _atividades = new();
    private static readonly EmailStats _emailStats = new()
    {
        EmailsEnviados = 15,
        EmailsPendentes = 3,
        EmailsFalhados = 1,
        UltimoEnvio = DateTime.Now.AddHours(-2)
    };

    public ActivityService(IPacienteService pacienteService, ILogger<ActivityService> logger)
    {
        _pacienteService = pacienteService;
        _logger = logger;
        
        // Inicializar com algumas atividades de exemplo
        InicializarAtividadesExemplo();
    }

    public async Task<List<PacienteRecenteItem>> GetPacientesRecentesAsync(int dias = 7)
    {
        try
        {
            var pacientes = await _pacienteService.SearchAsync(string.Empty);
            var dataLimite = DateTime.Now.AddDays(-dias);

            var pacientesRecentes = pacientes
                .Where(p => p.CriadoEm >= dataLimite)
                .OrderByDescending(p => p.CriadoEm)
                .Take(10)
                .Select(p => new PacienteRecenteItem
                {
                    Id = p.Id,
                    Nome = p.Nome,
                    Email = p.Email,
                    DataCriacao = p.CriadoEm
                })
                .ToList();

            return pacientesRecentes;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter pacientes recentes");
            return new List<PacienteRecenteItem>();
        }
    }

    public async Task<List<AtividadeItem>> GetAtividadeRecenteAsync(int count = 20)
    {
        try
        {
            // Combinar atividades registradas com pacientes recentes
            var atividadesPacientes = await CriarAtividadesPacientes();
            
            var todasAtividades = _atividades
                .Concat(atividadesPacientes)
                .OrderByDescending(a => a.DataHora)
                .Take(count)
                .ToList();

            return todasAtividades;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter atividade recente");
            return new List<AtividadeItem>();
        }
    }

    public async Task RegistrarAtividadeAsync(TipoAtividade tipo, string descricao, object? metadata = null)
    {
        try
        {
            var atividade = new AtividadeItem
            {
                Id = _atividades.Count + 1,
                Tipo = tipo,
                Descricao = descricao,
                DataHora = DateTime.Now,
                Metadata = metadata?.ToString()
            };

            _atividades.Add(atividade);
            
            // Limitar histórico a 100 itens
            if (_atividades.Count > 100)
            {
                _atividades.RemoveAt(0);
            }

            _logger.LogInformation("Atividade registrada: {Tipo} - {Descricao}", tipo, descricao);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao registrar atividade: {Descricao}", descricao);
        }

        await Task.CompletedTask;
    }

    public async Task<EmailStats> GetEmailStatsAsync()
    {
        // Simular algumas atualizações
        _emailStats.EmailsEnviados += new Random().Next(0, 3);
        if (new Random().Next(1, 10) > 7)
        {
            _emailStats.EmailsPendentes += 1;
            _emailStats.UltimoEnvio = DateTime.Now;
        }

        return await Task.FromResult(_emailStats);
    }

    private async Task<List<AtividadeItem>> CriarAtividadesPacientes()
    {
        var pacientes = await _pacienteService.SearchAsync(string.Empty);
        
        return pacientes
            .OrderByDescending(p => p.CriadoEm)
            .Take(5)
            .Select(p => new AtividadeItem
            {
                Id = p.Id + 1000, // Offset para evitar conflitos
                Tipo = TipoAtividade.PacienteCriado,
                Descricao = $"Novo paciente: {p.Nome}",
                DataHora = p.CriadoEm,
                Metadata = $"Email: {p.Email}"
            })
            .ToList();
    }

    private void InicializarAtividadesExemplo()
    {
        if (_atividades.Any()) return;

        var agora = DateTime.Now;
        var atividades = new[]
        {
            new AtividadeItem
            {
                Id = 1,
                Tipo = TipoAtividade.SystemAction,
                Descricao = "Sistema iniciado com sucesso",
                DataHora = agora.AddMinutes(-30)
            },
            new AtividadeItem
            {
                Id = 2,
                Tipo = TipoAtividade.EmailEnviado,
                Descricao = "Email de confirmação enviado para João Silva",
                DataHora = agora.AddMinutes(-15)
            },
            new AtividadeItem
            {
                Id = 3,
                Tipo = TipoAtividade.EmailPendente,
                Descricao = "3 emails pendentes na fila",
                DataHora = agora.AddMinutes(-5)
            }
        };

        _atividades.AddRange(atividades);
    }
}