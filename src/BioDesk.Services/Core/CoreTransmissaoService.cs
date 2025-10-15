using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;

namespace BioDesk.Services.Core;

/// <summary>
/// Estado da transmissão
/// </summary>
public enum EstadoTransmissao
{
    Parada = 0,
    Preparando = 1,
    EmExecucao = 2,
    Pausada = 3,
    Concluida = 4,
    ErroFatal = 5
}

/// <summary>
/// Tipo de transmissão
/// </summary>
public enum TipoTransmissao
{
    /// <summary>
    /// Transmissão local (paciente presente, conexão energética direta)
    /// </summary>
    Local = 1,

    /// <summary>
    /// Transmissão remota (paciente ausente, usa assinatura informacional)
    /// Requer nome + data nascimento + foto para criar campo quântico
    /// </summary>
    Remota = 2
}

/// <summary>
/// Informações sobre transmissão em execução
/// </summary>
public class StatusTransmissao
{
    /// <summary>
    /// Estado atual
    /// </summary>
    public EstadoTransmissao Estado { get; set; }

    /// <summary>
    /// Tipo de transmissão
    /// </summary>
    public TipoTransmissao Tipo { get; set; }

    /// <summary>
    /// Paciente alvo
    /// </summary>
    public Paciente? Paciente { get; set; }

    /// <summary>
    /// Itens sendo transmitidos
    /// </summary>
    public List<ItemBancoCore> Itens { get; set; } = new();

    /// <summary>
    /// Progresso (0-100%)
    /// </summary>
    public double Progresso { get; set; }

    /// <summary>
    /// Duração planejada (minutos)
    /// </summary>
    public int DuracaoMinutos { get; set; }

    /// <summary>
    /// Tempo decorrido
    /// </summary>
    public TimeSpan TempoDecorrido { get; set; }

    /// <summary>
    /// Timestamp de início
    /// </summary>
    public DateTime IniciadoEm { get; set; }

    /// <summary>
    /// Potência da transmissão (0-100%)
    /// Hardware TiePie permite controle de potência
    /// </summary>
    public double Potencia { get; set; } = 100.0;

    /// <summary>
    /// Mensagem de status/erro
    /// </summary>
    public string Mensagem { get; set; } = string.Empty;
}

/// <summary>
/// Parâmetros para iniciar transmissão
/// </summary>
public class ParametrosTransmissao
{
    /// <summary>
    /// Tipo de transmissão (Local ou Remota)
    /// </summary>
    public TipoTransmissao Tipo { get; set; }

    /// <summary>
    /// Paciente alvo (obrigatório)
    /// </summary>
    public Paciente Paciente { get; set; } = null!;

    /// <summary>
    /// Itens a transmitir (obrigatório)
    /// </summary>
    public List<ItemBancoCore> Itens { get; set; } = new();

    /// <summary>
    /// Duração da transmissão em minutos (padrão: 30)
    /// </summary>
    public int DuracaoMinutos { get; set; } = 30;

    /// <summary>
    /// Potência da transmissão 0-100% (padrão: 100)
    /// </summary>
    public double Potencia { get; set; } = 100.0;

    /// <summary>
    /// Tipo de RNG a usar
    /// </summary>
    public TipoRng TipoRng { get; set; } = TipoRng.HardwareTiePie;

    /// <summary>
    /// Seed do paciente (gerado pelo CoreAnaliseService)
    /// </summary>
    public int SeedPaciente { get; set; }

    /// <summary>
    /// Notas adicionais sobre a transmissão
    /// </summary>
    public string? Notas { get; set; }
}

/// <summary>
/// Interface para serviço de transmissão Core
/// </summary>
public interface ICoreTransmissaoService
{
    /// <summary>
    /// Status atual da transmissão
    /// </summary>
    StatusTransmissao Status { get; }

    /// <summary>
    /// Evento disparado quando status muda
    /// </summary>
    event EventHandler<StatusTransmissao>? StatusChanged;

    /// <summary>
    /// Inicia transmissão
    /// </summary>
    Task IniciarAsync(ParametrosTransmissao parametros);

    /// <summary>
    /// Pausa transmissão em execução
    /// </summary>
    Task PausarAsync();

    /// <summary>
    /// Retoma transmissão pausada
    /// </summary>
    Task RetomarAsync();

    /// <summary>
    /// Para transmissão
    /// </summary>
    Task PararAsync();
}

/// <summary>
/// Implementação do serviço de transmissão Core
/// Simula transmissão de informação quântica local ou remota
/// </summary>
public class CoreTransmissaoService : ICoreTransmissaoService, IDisposable
{
    private readonly RngServiceFactory _rngFactory;
    private readonly ILogger<CoreTransmissaoService> _logger;
    private IRngService? _rng;
    private CancellationTokenSource? _cts;
    private Task? _transmissaoTask;
    private DateTime _inicioTransmissao;
    private DateTime _pausaTimestamp;
    private TimeSpan _tempoPausaAcumulado;
    private bool _disposed;

    public StatusTransmissao Status { get; private set; } = new();

    public event EventHandler<StatusTransmissao>? StatusChanged;

    public CoreTransmissaoService(
        RngServiceFactory rngFactory,
        ILogger<CoreTransmissaoService> logger)
    {
        _rngFactory = rngFactory;
        _logger = logger;
        Status.Estado = EstadoTransmissao.Parada;
    }

    /// <summary>
    /// Inicia transmissão
    /// </summary>
    public async Task IniciarAsync(ParametrosTransmissao parametros)
    {
        if (Status.Estado == EstadoTransmissao.EmExecucao)
        {
            _logger.LogWarning("⚠️ Tentativa de iniciar transmissão com outra já em execução");
            throw new InvalidOperationException("Já existe uma transmissão em execução");
        }

        if (parametros.Itens.Count == 0)
        {
            throw new ArgumentException("Nenhum item selecionado para transmissão");
        }

        _logger.LogInformation($"📡 Iniciando transmissão {parametros.Tipo} para {parametros.Paciente.NomeCompleto}");
        _logger.LogInformation($"   Items: {parametros.Itens.Count}, Duração: {parametros.DuracaoMinutos}min, Potência: {parametros.Potencia}%");

        // Criar RNG
        _rng = _rngFactory.Create(parametros.TipoRng);
        if (!_rng.IsAvailable)
        {
            _logger.LogWarning($"⚠️ RNG {parametros.TipoRng} não disponível - usando fallback");
            _rng = _rngFactory.CreateBest();
        }

        // Configurar status inicial
        Status = new StatusTransmissao
        {
            Estado = EstadoTransmissao.Preparando,
            Tipo = parametros.Tipo,
            Paciente = parametros.Paciente,
            Itens = new List<ItemBancoCore>(parametros.Itens),
            DuracaoMinutos = parametros.DuracaoMinutos,
            Potencia = parametros.Potencia,
            IniciadoEm = DateTime.UtcNow,
            Mensagem = "Preparando transmissão..."
        };
        NotifyStatusChanged();

        // Iniciar transmissão em background
        _cts = new CancellationTokenSource();
        _inicioTransmissao = DateTime.UtcNow;
        _tempoPausaAcumulado = TimeSpan.Zero;

        _transmissaoTask = Task.Run(async () =>
        {
            await ExecutarTransmissaoAsync(parametros, _cts.Token);
        }, _cts.Token);

        await Task.Delay(500); // Pequeno delay para garantir que task iniciou
    }

    /// <summary>
    /// Executa loop de transmissão
    /// </summary>
    private async Task ExecutarTransmissaoAsync(ParametrosTransmissao parametros, CancellationToken ct)
    {
        try
        {
            Status.Estado = EstadoTransmissao.EmExecucao;
            Status.Mensagem = parametros.Tipo == TipoTransmissao.Local
                ? "Transmitindo informação quântica (paciente presente)"
                : "Transmitindo informação quântica (remoto)";
            NotifyStatusChanged();

            var duracaoTotal = TimeSpan.FromMinutes(parametros.DuracaoMinutos);
            var updateInterval = TimeSpan.FromMilliseconds(500); // Update UI 2x por segundo

            while (!ct.IsCancellationRequested)
            {
                // Calcular tempo decorrido (excluindo pausas)
                var tempoDecorrido = DateTime.UtcNow - _inicioTransmissao - _tempoPausaAcumulado;

                if (tempoDecorrido >= duracaoTotal)
                {
                    // Transmissão completa
                    Status.Progresso = 100;
                    Status.TempoDecorrido = duracaoTotal;
                    Status.Estado = EstadoTransmissao.Concluida;
                    Status.Mensagem = $"Transmissão concluída - {parametros.Itens.Count} itens transmitidos";
                    NotifyStatusChanged();

                    _logger.LogInformation($"✅ Transmissão concluída após {duracaoTotal.TotalMinutes:F1} minutos");
                    break;
                }

                // Atualizar progresso
                Status.Progresso = Math.Round((tempoDecorrido.TotalMinutes / parametros.DuracaoMinutos) * 100.0, 1);
                Status.TempoDecorrido = tempoDecorrido;

                // Simular atividade RNG (gerar valores para manter "campo quântico" ativo)
                // Em implementação real com hardware TiePie, isto seria envio de frequências
                if (_rng != null)
                {
                    _ = _rng.NextWithSeed(parametros.SeedPaciente, 0, 100);
                }

                NotifyStatusChanged();

                await Task.Delay(updateInterval, ct);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("⏹️ Transmissão cancelada pelo utilizador");
            Status.Estado = EstadoTransmissao.Parada;
            Status.Mensagem = "Transmissão interrompida";
            NotifyStatusChanged();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro durante transmissão");
            Status.Estado = EstadoTransmissao.ErroFatal;
            Status.Mensagem = $"Erro: {ex.Message}";
            NotifyStatusChanged();
        }
    }

    /// <summary>
    /// Pausa transmissão
    /// </summary>
    public async Task PausarAsync()
    {
        if (Status.Estado != EstadoTransmissao.EmExecucao)
        {
            throw new InvalidOperationException("Nenhuma transmissão em execução para pausar");
        }

        _logger.LogInformation("⏸️ Pausando transmissão");
        _pausaTimestamp = DateTime.UtcNow;
        Status.Estado = EstadoTransmissao.Pausada;
        Status.Mensagem = "Transmissão pausada";
        NotifyStatusChanged();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Retoma transmissão pausada
    /// </summary>
    public async Task RetomarAsync()
    {
        if (Status.Estado != EstadoTransmissao.Pausada)
        {
            throw new InvalidOperationException("Nenhuma transmissão pausada para retomar");
        }

        _logger.LogInformation("▶️ Retomando transmissão");

        // Acumular tempo de pausa
        _tempoPausaAcumulado += DateTime.UtcNow - _pausaTimestamp;

        Status.Estado = EstadoTransmissao.EmExecucao;
        Status.Mensagem = Status.Tipo == TipoTransmissao.Local
            ? "Transmitindo informação quântica (paciente presente)"
            : "Transmitindo informação quântica (remoto)";
        NotifyStatusChanged();

        await Task.CompletedTask;
    }

    /// <summary>
    /// Para transmissão
    /// </summary>
    public async Task PararAsync()
    {
        if (Status.Estado == EstadoTransmissao.Parada)
        {
            return;
        }

        _logger.LogInformation("⏹️ Parando transmissão");

        _cts?.Cancel();

        if (_transmissaoTask != null)
        {
            try
            {
                await _transmissaoTask;
            }
            catch (OperationCanceledException)
            {
                // Esperado
            }
        }

        Status.Estado = EstadoTransmissao.Parada;
        Status.Progresso = 0;
        Status.Mensagem = "Transmissão parada";
        NotifyStatusChanged();

        _cts?.Dispose();
        _cts = null;
        _transmissaoTask = null;
    }

    private void NotifyStatusChanged()
    {
        StatusChanged?.Invoke(this, Status);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _transmissaoTask?.Wait(TimeSpan.FromSeconds(2));
            _transmissaoTask?.Dispose();
        }
        _disposed = true;
    }
}
