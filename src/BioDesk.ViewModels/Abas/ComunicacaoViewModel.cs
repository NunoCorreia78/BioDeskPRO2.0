using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using BioDesk.Services.Email;
using BioDesk.Services.Documentos;
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
    private readonly IDocumentoService _documentoService;

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

    // ⭐ NOVO: Gestão de anexos
    [ObservableProperty] private ObservableCollection<string> _anexos = new();
    [ObservableProperty] private string _statusAnexos = string.Empty;

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
        BioDeskDbContext dbContext,
        IDocumentoService documentoService)
    {
        _logger = logger;
        _emailService = emailService;
        _dbContext = dbContext;
        _documentoService = documentoService;

        _logger.LogInformation("ComunicacaoViewModel inicializado");

        // ⭐ CORREÇÃO: Verificar conexão E recarregar histórico a cada 30 segundos
        Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    TemConexao = _emailService.TemConexao;
                    MensagensNaFila = await _emailService.ContarMensagensNaFilaAsync();

                    // ⭐ NOVO: Recarregar histórico para ver emails enviados pelo processador em background
                    if (PacienteAtual != null)
                    {
                        // Precisa ser executado na UI thread por causa da ObservableCollection
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(async () =>
                        {
                            await CarregarHistoricoAsync();
                        });

                        _logger.LogDebug("🔄 Histórico recarregado automaticamente");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erro ao atualizar status de conexão/histórico");
                }

                await Task.Delay(TimeSpan.FromSeconds(30));
            }
        });
    }

    partial void OnTemplateSelecionadoChanged(string value)
    {
        if (PacienteAtual == null) return;

        // ⭐ CORREÇÃO: Preencher ASSUNTO automaticamente
        Assunto = value switch
        {
            "Prescrição" => "Prescrição de Tratamento",
            "Confirmação de Consulta" => "Confirmação de Consulta",
            "Follow-up" => "Acompanhamento de Tratamento",
            "Lembrete" => "Lembrete",
            _ => string.Empty
        };

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

    /// <summary>
    /// ⭐ NOVO: Anexar ficheiro ao email
    /// </summary>
    [RelayCommand]
    private void AnexarFicheiro()
    {
        try
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Selecionar Ficheiro para Anexar",
                Filter = "Todos os ficheiros (*.*)|*.*|PDFs (*.pdf)|*.pdf|Imagens (*.png;*.jpg)|*.png;*.jpg",
                Multiselect = true
            };

            if (dialog.ShowDialog() == true)
            {
                foreach (var file in dialog.FileNames)
                {
                    if (!Anexos.Contains(file))
                    {
                        Anexos.Add(file);
                        _logger.LogInformation("📎 Anexo adicionado: {File}", file);
                    }
                }

                StatusAnexos = $"{Anexos.Count} ficheiro(s) anexado(s)";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao anexar ficheiro");
            ErrorMessage = $"Erro ao anexar ficheiro: {ex.Message}";
        }
    }

    /// <summary>
    /// ⭐ NOVO: Remover anexo da lista
    /// </summary>
    [RelayCommand]
    private void RemoverAnexo(string caminhoFicheiro)
    {
        Anexos.Remove(caminhoFicheiro);
        AtualizarStatusAnexos();
        _logger.LogInformation("🗑️ Anexo removido: {File}", caminhoFicheiro);
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

            // ⭐ CORREÇÃO: Gravar anexos na BD
            foreach (var caminhoFicheiro in Anexos)
            {
                var anexo = new AnexoComunicacao
                {
                    ComunicacaoId = comunicacao.Id,
                    CaminhoArquivo = caminhoFicheiro,
                    NomeArquivo = System.IO.Path.GetFileName(caminhoFicheiro),
                    TamanhoBytes = new System.IO.FileInfo(caminhoFicheiro).Length,
                    DataCriacao = DateTime.Now
                };
                await _dbContext.Set<AnexoComunicacao>().AddAsync(anexo);
            }
            await _dbContext.SaveChangesAsync();

            // ⭐ CORREÇÃO: Tentar enviar IMEDIATAMENTE (não esperar pelos 30s do processador)
            var emailMessage = new EmailMessage
            {
                To = Destinatario,
                ToName = PacienteAtual.NomeCompleto,
                Subject = Assunto,
                Body = Corpo,
                IsHtml = true,
                Attachments = Anexos.ToList() // ⭐ Passar anexos
            };

            // ⚡ CRÍTICO: Tentar envio IMEDIATO
            var resultado = await _emailService.EnviarAsync(emailMessage);

            // Atualizar status conforme resultado
            if (resultado.Sucesso)
            {
                // ✅ SUCESSO: Enviado imediatamente
                comunicacao.IsEnviado = true;
                comunicacao.Status = StatusComunicacao.Enviado;
                comunicacao.DataEnvio = DateTime.Now;
                comunicacao.UltimoErro = null;
                SuccessMessage = "✅ Email enviado com sucesso!";
                _logger.LogInformation("✅ Email ID {Id} enviado IMEDIATAMENTE", comunicacao.Id);
            }
            else
            {
                if (resultado.AdicionadoNaFila)
                {
                    // ⚠️ SEM REDE: Fica Agendado para processador tentar
                    SuccessMessage = "⚠️ Sem conexão. Email agendado para envio automático quando a rede retornar.";
                    _logger.LogWarning("⚠️ Email ID {Id} agendado (sem rede)", comunicacao.Id);
                }
                else
                {
                    // ❌ ERRO: Falhou mas fica Agendado para retry automático
                    comunicacao.UltimoErro = resultado.Mensagem;
                    comunicacao.TentativasEnvio = 1; // Primeira tentativa falhou
                    comunicacao.ProximaTentativa = DateTime.Now.AddMinutes(2); // Retry em 2 minutos

                    SuccessMessage = $"⚠️ Erro ao enviar agora. Email agendado para retry automático em 2 minutos.\n{resultado.Mensagem}";
                    _logger.LogWarning("⚠️ Email ID {Id} agendado para retry (erro: {Error})", comunicacao.Id, resultado.Mensagem);
                }
            }

            await _dbContext.SaveChangesAsync();

            // Limpar formulário
            Assunto = string.Empty;
            Corpo = string.Empty;
            AgendarFollowUp = false;
            Anexos.Clear(); // ⭐ Limpar anexos
            StatusAnexos = string.Empty;

            // Recarregar histórico
            await CarregarHistoricoAsync();

            IsLoading = false;

        }, "Erro ao enviar email", _logger);
    }

    /// <summary>
    /// ⭐ NOVO: Cancelar email agendado (impede envio automático)
    /// </summary>
    [RelayCommand]
    private async Task CancelarEmailAsync(Comunicacao comunicacao)
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (comunicacao.Status != StatusComunicacao.Agendado)
            {
                ErrorMessage = "Apenas emails 'Agendados' podem ser cancelados!";
                return;
            }

            IsLoading = true;

            comunicacao.Status = StatusComunicacao.Falhado; // Marcar como Falhado para processador ignorar
            comunicacao.UltimoErro = "Cancelado pelo utilizador";
            await _dbContext.SaveChangesAsync();

            SuccessMessage = "Email cancelado com sucesso!";
            _logger.LogInformation("🚫 Email ID {Id} cancelado pelo utilizador", comunicacao.Id);

            // Recarregar histórico
            await CarregarHistoricoAsync();

            IsLoading = false;

        }, "Erro ao cancelar email", _logger);
    }

    [RelayCommand]
    private void LimparFormulario()
    {
        Assunto = string.Empty;
        Corpo = string.Empty;
        AgendarFollowUp = false;
        TemplateSelecionado = "Personalizado";
        Anexos.Clear();
        StatusAnexos = string.Empty;
    }

    /// <summary>
    /// ⭐ NOVO: Abre pasta documental do paciente
    /// </summary>
    [RelayCommand]
    private async Task AbrirPastaPacienteAsync()
    {
        if (PacienteAtual == null)
        {
            ErrorMessage = "Nenhum paciente selecionado!";
            return;
        }

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            await _documentoService.AbrirPastaPacienteAsync(PacienteAtual.Id, PacienteAtual.NomeCompleto);
            _logger.LogInformation("📂 Pasta aberta para paciente {Id}", PacienteAtual.Id);
            IsLoading = false;
        }, "Erro ao abrir pasta do paciente", _logger);
    }

    /// <summary>
    /// ⭐ NOVO: Adiciona anexo usando diálogo de ficheiros
    /// Abre automaticamente na pasta do paciente se existir
    /// </summary>
    [RelayCommand]
    private void AdicionarAnexo()
    {
        if (PacienteAtual == null)
        {
            ErrorMessage = "Nenhum paciente selecionado!";
            return;
        }

        try
        {
            var openFileDialog = new OpenFileDialog
            {
                Title = "Selecionar Anexos",
                Filter = "Todos os ficheiros (*.*)|*.*|PDFs (*.pdf)|*.pdf|Imagens (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg",
                Multiselect = true
            };

            // ⭐ NOVO: Abre automaticamente na pasta do paciente
            var pastaPaciente = _documentoService.ObterPastaPaciente(PacienteAtual.Id, PacienteAtual.NomeCompleto);
            if (_documentoService.PastaExiste(PacienteAtual.Id, PacienteAtual.NomeCompleto))
            {
                openFileDialog.InitialDirectory = pastaPaciente;
            }

            if (openFileDialog.ShowDialog() == true)
            {
                foreach (var ficheiro in openFileDialog.FileNames)
                {
                    if (!Anexos.Contains(ficheiro))
                    {
                        Anexos.Add(ficheiro);
                    }
                }

                AtualizarStatusAnexos();
                _logger.LogInformation("📎 {Count} anexos adicionados", openFileDialog.FileNames.Length);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Erro ao adicionar anexo: {ex.Message}";
            _logger.LogError(ex, "Erro ao adicionar anexo");
        }
    }

    private void AtualizarStatusAnexos()
    {
        if (Anexos.Count == 0)
        {
            StatusAnexos = "Nenhum anexo";
        }
        else if (Anexos.Count == 1)
        {
            StatusAnexos = $"1 anexo ({System.IO.Path.GetFileName(Anexos[0])})";
        }
        else
        {
            StatusAnexos = $"{Anexos.Count} anexos";
        }
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
