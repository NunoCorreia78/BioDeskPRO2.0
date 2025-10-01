using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using BioDesk.Services.Email;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel para Aba 5: Comunicação & Seguimento
/// Suporta envio de emails offline com fila automática
/// </summary>
public partial class ComunicacaoViewModel : ViewModelBase
{
    private readonly ILogger<ComunicacaoViewModel> _logger;
    private readonly IEmailService _emailService;
    private readonly BioDeskDbContext _dbContext;

    [ObservableProperty] private Paciente? _pacienteAtual;
    [ObservableProperty] private ObservableCollection<Comunicacao> _historicoComunicacoes = new();

    // Formulário de envio
    [ObservableProperty] private TipoComunicacao _tipoSelecionado = TipoComunicacao.Email;
    [ObservableProperty] private string _destinatario = string.Empty;

    /// <summary>
    /// Auto-preencher Destinatario quando PacienteAtual muda
    /// </summary>
    partial void OnPacienteAtualChanged(Paciente? value)
    {
        if (value?.Contacto != null && !string.IsNullOrWhiteSpace(value.Contacto.EmailPrincipal))
        {
            Destinatario = value.Contacto.EmailPrincipal;
            _logger.LogInformation("📧 Auto-preenchido email do paciente: {Email}", Destinatario);
        }
        else
        {
            _logger.LogWarning("⚠️ Paciente sem email no contacto");
        }
    }
    [ObservableProperty] private string _assunto = string.Empty;
    [ObservableProperty] private string _corpo = string.Empty;
    [ObservableProperty] private bool _agendarFollowUp = false;
    [ObservableProperty] private int _diasFollowUp = 7;

    // Estatísticas
    [ObservableProperty] private int _totalEmails;
    [ObservableProperty] private int _totalSMS;
    [ObservableProperty] private int _totalChamadas;
    [ObservableProperty] private double _taxaAbertura;
    [ObservableProperty] private DateTime? _ultimaComunicacao;
    [ObservableProperty] private DateTime? _proximoFollowUp;
    [ObservableProperty] private int _mensagensNaFila;
    [ObservableProperty] private bool _temConexao = true;

    // Templates
    public ObservableCollection<string> Templates { get; } = new()
    {
        "Prescrição",
        "Confirmação de Consulta",
        "Follow-up",
        "Lembrete",
        "Personalizado"
    };

    [ObservableProperty] private string _templateSelecionado = "Personalizado";

    public ComunicacaoViewModel(
        ILogger<ComunicacaoViewModel> logger,
        IEmailService emailService,
        BioDeskDbContext dbContext)
    {
        _logger = logger;
        _emailService = emailService;
        _dbContext = dbContext;

        _logger.LogInformation("ComunicacaoViewModel inicializado");

        // Verificar conexão a cada 30 segundos
        Task.Run(async () =>
        {
            while (true)
            {
                TemConexao = _emailService.TemConexao;
                MensagensNaFila = await _emailService.ContarMensagensNaFilaAsync();
                await Task.Delay(TimeSpan.FromSeconds(30));
            }
        });
    }

    partial void OnTemplateSelecionadoChanged(string value)
    {
        if (PacienteAtual == null) return;

        Corpo = value switch
        {
            "Prescrição" => $@"Olá {PacienteAtual.NomeCompleto},

Conforme conversado na consulta, segue em anexo a prescrição recomendada.

Qualquer dúvida, estou à disposição.

Cumprimentos,
[Nome do Terapeuta]",

            "Confirmação de Consulta" => $@"Olá {PacienteAtual.NomeCompleto},

Confirmamos a sua consulta para [DATA/HORA].

Em caso de necessidade de reagendar, por favor contacte-nos.

Cumprimentos,
[Clínica]",

            "Follow-up" => $@"Olá {PacienteAtual.NomeCompleto},

Como está a decorrer o tratamento? Sente melhorias?

Estou disponível para qualquer esclarecimento.

Cumprimentos,
[Nome do Terapeuta]",

            "Lembrete" => $@"Olá {PacienteAtual.NomeCompleto},

Lembrete: [DETALHE DO LEMBRETE]

Cumprimentos,
[Clínica]",

            _ => string.Empty
        };
    }

    [RelayCommand]
    private async Task EnviarEmailAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (PacienteAtual == null)
            {
                ErrorMessage = "Nenhum paciente selecionado!";
                return;
            }

            // Validações
            if (string.IsNullOrWhiteSpace(Destinatario))
            {
                ErrorMessage = "Email do destinatário é obrigatório!";
                return;
            }

            if (string.IsNullOrWhiteSpace(Assunto))
            {
                ErrorMessage = "Assunto é obrigatório!";
                return;
            }

            if (string.IsNullOrWhiteSpace(Corpo))
            {
                ErrorMessage = "Corpo da mensagem é obrigatório!";
                return;
            }

            IsLoading = true;

            // Criar comunicação na DB (mesmo se offline)
            var comunicacao = new Comunicacao
            {
                PacienteId = PacienteAtual.Id,
                Tipo = TipoSelecionado,
                Destinatario = Destinatario,
                Assunto = Assunto,
                Corpo = Corpo,
                TemplateUtilizado = TemplateSelecionado,
                Status = StatusComunicacao.Agendado,
                DataCriacao = DateTime.Now,
                ProximaTentativa = DateTime.Now // Tentar enviar imediatamente
            };

            // Agendar follow-up se selecionado
            if (AgendarFollowUp)
            {
                comunicacao.DataFollowUp = DateTime.Now.AddDays(DiasFollowUp);
                comunicacao.MensagemFollowUp = $"Follow-up automático após {DiasFollowUp} dias";
            }

            await _dbContext.Comunicacoes.AddAsync(comunicacao);
            await _dbContext.SaveChangesAsync();

            _logger.LogInformation("✅ Comunicação criada na DB (ID: {Id})", comunicacao.Id);

            // Tentar enviar imediatamente
            var emailMessage = new EmailMessage
            {
                To = Destinatario,
                ToName = PacienteAtual.NomeCompleto,
                Subject = Assunto,
                Body = Corpo,
                IsHtml = true
            };

            var resultado = await _emailService.EnviarAsync(emailMessage);

            // Atualizar status
            if (resultado.Sucesso)
            {
                comunicacao.IsEnviado = true;
                comunicacao.Status = StatusComunicacao.Enviado;
                comunicacao.DataEnvio = DateTime.Now;
                SuccessMessage = "Email enviado com sucesso!";
            }
            else
            {
                if (resultado.AdicionadoNaFila)
                {
                    SuccessMessage = "Sem conexão. Email adicionado à fila e será enviado automaticamente.";
                }
                else
                {
                    ErrorMessage = resultado.Mensagem ?? "Erro ao enviar email";
                }
            }

            await _dbContext.SaveChangesAsync();

            // Limpar formulário
            Assunto = string.Empty;
            Corpo = string.Empty;
            AgendarFollowUp = false;

            // Recarregar histórico
            await CarregarHistoricoAsync();

            IsLoading = false;

        }, "Erro ao enviar email", _logger);
    }

    [RelayCommand]
    private void LimparFormulario()
    {
        Assunto = string.Empty;
        Corpo = string.Empty;
        AgendarFollowUp = false;
        TemplateSelecionado = "Personalizado";
    }

    public async Task SetPaciente(Paciente paciente)
    {
        PacienteAtual = paciente;
        Destinatario = paciente.Contacto?.EmailPrincipal ?? string.Empty;
        
        await CarregarHistoricoAsync();
        await CarregarEstatisticasAsync();
    }

    private async Task CarregarHistoricoAsync()
    {
        if (PacienteAtual == null) return;

        IsLoading = true;

        var historico = await _dbContext.Comunicacoes
            .Where(c => c.PacienteId == PacienteAtual.Id && !c.IsDeleted)
            .OrderByDescending(c => c.DataCriacao)
            .Take(50)
            .ToListAsync();

        HistoricoComunicacoes = new ObservableCollection<Comunicacao>(historico);

        IsLoading = false;
    }

    private async Task CarregarEstatisticasAsync()
    {
        if (PacienteAtual == null) return;

        var todas = await _dbContext.Comunicacoes
            .Where(c => c.PacienteId == PacienteAtual.Id && !c.IsDeleted)
            .ToListAsync();

        TotalEmails = todas.Count(c => c.Tipo == TipoComunicacao.Email);
        TotalSMS = todas.Count(c => c.Tipo == TipoComunicacao.SMS);
        TotalChamadas = todas.Count(c => c.Tipo == TipoComunicacao.Chamada);

        var emailsEnviados = todas.Where(c => c.Tipo == TipoComunicacao.Email && c.IsEnviado).ToList();
        TaxaAbertura = emailsEnviados.Count > 0 
            ? emailsEnviados.Count(e => e.FoiAberto) / (double)emailsEnviados.Count
            : 0;

        UltimaComunicacao = todas.OrderByDescending(c => c.DataEnvio).FirstOrDefault()?.DataEnvio;

        ProximoFollowUp = await _dbContext.Comunicacoes
            .Where(c => c.PacienteId == PacienteAtual.Id && c.DataFollowUp.HasValue && !c.FollowUpEnviado)
            .OrderBy(c => c.DataFollowUp)
            .Select(c => c.DataFollowUp)
            .FirstOrDefaultAsync();
    }
}
