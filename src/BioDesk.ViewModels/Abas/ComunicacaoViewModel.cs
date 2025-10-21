using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using Microsoft.Win32;
using BioDesk.Data;
using BioDesk.Domain.Entities;
using BioDesk.Services.Email;
using BioDesk.Services.Documentos;
using BioDesk.Services.Templates;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel para Aba 5: ComunicaÃ§Ã£o & Seguimento
/// Suporta envio de emails offline com fila automÃ¡tica
/// </summary>
public partial class ComunicacaoViewModel : ViewModelBase
{
    private readonly ILogger<ComunicacaoViewModel> _logger;
    private readonly IEmailService _emailService;
    private readonly IServiceScopeFactory _scopeFactory; // â­ CORREÃ‡ÃƒO: Usa scope factory para DbContext isolado
    private readonly IDocumentoService _documentoService;
    private readonly IDocumentosPacienteService _documentosPacienteService;
    private readonly ITemplatesPdfService _templatesPdfService;

    [ObservableProperty] private Paciente? _pacienteAtual;
    [ObservableProperty] private ObservableCollection<Comunicacao> _historicoComunicacoes = new();

    /// <summary>
    /// InformaÃ§Ã£o do cabeÃ§alho do histÃ³rico
    /// </summary>
    public int TotalEnviados => HistoricoComunicacoes?.Count(c => c.Status == StatusComunicacao.Enviado) ?? 0;

    public string ProximoAgendamento
    {
        get
        {
            var proximo = HistoricoComunicacoes?
                .Where(c => c.Status == StatusComunicacao.Agendado && c.ProximaTentativa.HasValue)
                .OrderBy(c => c.ProximaTentativa)
                .FirstOrDefault();

            if (proximo == null)
                return "Sem agendamentos";

            var tempo = proximo.ProximaTentativa!.Value - DateTime.Now;
            if (tempo.TotalMinutes < 1)
                return "Em breve...";
            if (tempo.TotalMinutes < 60)
                return $"Em {(int)tempo.TotalMinutes} minutos";
            if (tempo.TotalHours < 24)
                return $"Em {(int)tempo.TotalHours}h";
            return proximo.ProximaTentativa.Value.ToString("dd/MM HH:mm");
        }
    }

    /// <summary>
    /// Notifica UI quando o histÃ³rico muda
    /// </summary>
    partial void OnHistoricoComunicacoesChanged(ObservableCollection<Comunicacao> value)
    {
        OnPropertyChanged(nameof(TotalEnviados));
        OnPropertyChanged(nameof(ProximoAgendamento));
    }

    // â­ NOVO: GestÃ£o de documentos do paciente
    [ObservableProperty] private ObservableCollection<DocumentoPacienteViewModel> _documentosPaciente = new();
    [ObservableProperty] private bool _carregandoDocumentos = false;
    [ObservableProperty] private string _statusDocumentos = "Nenhum documento encontrado";

    // FormulÃ¡rio de envio
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
            _logger.LogInformation("ðŸ“§ Auto-preenchido email do paciente: {Email}", Destinatario);
        }
        else
        {
            _logger.LogWarning("âš ï¸ Paciente sem email no contacto");
        }

        // â­ NOVO: Carregar documentos do paciente automaticamente
        if (value != null)
        {
            _ = CarregarDocumentosPacienteAsync();
        }
        else
        {
            DocumentosPaciente.Clear();
            StatusDocumentos = "Nenhum paciente selecionado";
        }
    }
    [ObservableProperty] private string _assunto = string.Empty;
    [ObservableProperty] private string _corpo = string.Empty;

    // â­ Agendamento de envio do email
    [ObservableProperty] private bool _agendarEnvio = false;
    [ObservableProperty] private DateTime _dataEnvioAgendado = DateTime.Now.AddDays(1).Date.AddHours(9); // AmanhÃ£ Ã s 9h por padrÃ£o

    // â­ NOVO: GestÃ£o de anexos
    [ObservableProperty] private ObservableCollection<string> _anexos = new();
    [ObservableProperty] private string _statusAnexos = string.Empty;

    // EstatÃ­sticas
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
        "Envio de Documentos", // â­ NOVO: Template para anexar documentos
        "prescrição",
        "Confirmação de Consulta",
        "Follow-up",
        "Lembrete",
        "Personalizado"
    };

    [ObservableProperty] private string _templateSelecionado = "Personalizado";

    public ComunicacaoViewModel(
        ILogger<ComunicacaoViewModel> logger,
        IEmailService emailService,
        IServiceScopeFactory scopeFactory, // â­ CORREÃ‡ÃƒO: Scope factory para DbContext isolado
        IDocumentoService documentoService,
        IDocumentosPacienteService documentosPacienteService,
        ITemplatesPdfService templatesPdfService)
    {
        _logger = logger;
        _emailService = emailService;
        _scopeFactory = scopeFactory;
        _documentoService = documentoService;
        _documentosPacienteService = documentosPacienteService;
        _templatesPdfService = templatesPdfService;

        _logger.LogInformation("ComunicacaoViewModel inicializado");
    }

    /// <summary>
    /// â­ CORREÃ‡ÃƒO: Task de background para verificar conexÃ£o
    /// </summary>
    private void IniciarMonitorConexao()
    {
        // â­ CORREÃ‡ÃƒO: Verificar conexÃ£o E recarregar histÃ³rico a cada 30 segundos
        Task.Run(async () =>
        {
            while (true)
            {
                try
                {
                    TemConexao = _emailService.TemConexao;
                    MensagensNaFila = await _emailService.ContarMensagensNaFilaAsync();

                    // â­ NOVO: Recarregar histÃ³rico para ver emails enviados pelo processador em background
                    if (PacienteAtual != null)
                    {
                        // Precisa ser executado na UI thread por causa da ObservableCollection
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(async () =>
                        {
                            await CarregarHistoricoAsync();
                        });

                        _logger.LogDebug("ðŸ”„ HistÃ³rico recarregado automaticamente");
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Erro ao atualizar status de conexÃ£o/histÃ³rico");
                }

                await Task.Delay(TimeSpan.FromSeconds(30));
            }
        });
    }

    partial void OnTemplateSelecionadoChanged(string value)
    {
        if (PacienteAtual == null) return;

        // â­ CORREÃ‡ÃƒO: Preencher ASSUNTO automaticamente
        Assunto = value switch
        {
            "Envio de Documentos" => "DocumentaÃ§Ã£o Anexa", // â­ NOVO
            "prescrição" => "prescrição de Tratamento",
            "Confirmação de Consulta" => "Confirmação de Consulta",
            "Follow-up" => "Acompanhamento de Tratamento",
            "Lembrete" => "Lembrete",
            _ => string.Empty
        };

        Corpo = value switch
        {
            "Envio de Documentos" => $@"Olá {PacienteAtual.NomeCompleto},

Conforme solicitado, segue em anexo a ddocumentação necessária.

Se tiver alguma dúvida, estou Ã  disposiÃ§Ã£o.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
ðŸ“§ nunocorreiaterapiasnaturais@gmail.com | ðŸ“ž +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "prescrição" => $@"Olá {PacienteAtual.NomeCompleto},

Conforme conversado na consulta, segue em anexo a prescrição recomendada.

Qualquer dúvida, estou Ã  disposiÃ§Ã£o.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
ðŸ“§ nunocorreiaterapiasnaturais@gmail.com | ðŸ“ž +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "Confirmação de Consulta" => $@"Olá {PacienteAtual.NomeCompleto},

Confirmamos a sua consulta para [DATA/HORA].

Em caso de necessidade de reagendar, por favor contacte-nos.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
ðŸ“§ nunocorreiaterapiasnaturais@gmail.com | ðŸ“ž +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "Follow-up" => $@"Olá {PacienteAtual.NomeCompleto},

Como está a decorrer o tratamento? Sente melhorias?

Estou disponível para qualquer esclarecimento.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
ðŸ“§ nunocorreiaterapiasnaturais@gmail.com | ðŸ“ž +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "Lembrete" => $@"Olá {PacienteAtual.NomeCompleto},

Lembrete: [DETALHE DO LEMBRETE]

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
ðŸ“§ nunocorreiaterapiasnaturais@gmail.com | ðŸ“ž +351 964 860 387
🌿 Cuidar de si, naturalmente",

            _ => string.Empty
        };
    }

    /// <summary>
    /// â­ NOVO: Anexar ficheiro ao email
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
                        _logger.LogInformation("ðŸ“Ž Anexo adicionado: {File}", file);
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
    /// â­ NOVO: Remover anexo da lista
    /// </summary>
    [RelayCommand]
    private void RemoverAnexo(string caminhoFicheiro)
    {
        Anexos.Remove(caminhoFicheiro);
        AtualizarStatusAnexos();
        _logger.LogInformation("ðŸ—‘ï¸ Anexo removido: {File}", caminhoFicheiro);
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

            // ValidaÃ§Ãµes
            if (string.IsNullOrWhiteSpace(Destinatario))
            {
                ErrorMessage = "Email do destinatÃ¡rio Ã© obrigatÃ³rio!";
                return;
            }

            // â­ Validar formato de email (apenas warning, nÃ£o bloqueia)
            if (!IsValidEmail(Destinatario))
            {
                _logger.LogWarning("âš ï¸ Email com formato suspeito: {Email}", Destinatario);
                // Continua mesmo assim (pode ser email interno/teste)
            }

            if (string.IsNullOrWhiteSpace(Assunto))
            {
                ErrorMessage = "Assunto Ã© obrigatÃ³rio!";
                return;
            }

            if (string.IsNullOrWhiteSpace(Corpo))
            {
                ErrorMessage = "Corpo da mensagem Ã© obrigatÃ³rio!";
                return;
            }

            IsLoading = true;

            // â­ NOVO: Verificar se deve agendar o envio para data futura
            if (AgendarEnvio && DataEnvioAgendado > DateTime.Now)
            {
                // â­ CORREÃ‡ÃƒO: Usar scope isolado para DbContext
                using var scope = _scopeFactory.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

                // AGENDAR para envio futuro (nÃ£o enviar imediatamente)
                var comunicacaoAgendada = new Comunicacao
                {
                    PacienteId = PacienteAtual.Id,
                    Tipo = TipoSelecionado,
                    Destinatario = Destinatario,
                    Assunto = Assunto,
                    Corpo = Corpo,
                    TemplateUtilizado = TemplateSelecionado,
                    Status = StatusComunicacao.Agendado,
                    IsEnviado = false,
                    DataCriacao = DateTime.Now,
                    DataEnvio = null,
                    ProximaTentativa = DataEnvioAgendado, // â­ Data escolhida pelo utilizador
                    TentativasEnvio = 0,
                    UltimoErro = null
                };

                await dbContext.Comunicacoes.AddAsync(comunicacaoAgendada);

                // â­ CRÃTICO: Salvar primeiro para obter ID
                await dbContext.SaveChangesAsync();

                // Gravar anexos na BD (agora com ID correto)
                foreach (var caminhoFicheiro in Anexos)
                {
                    var anexo = new AnexoComunicacao
                    {
                        ComunicacaoId = comunicacaoAgendada.Id, // â­ Agora tem ID vÃ¡lido
                        CaminhoArquivo = caminhoFicheiro,
                        NomeArquivo = System.IO.Path.GetFileName(caminhoFicheiro),
                        TamanhoBytes = new System.IO.FileInfo(caminhoFicheiro).Length,
                        DataCriacao = DateTime.Now
                    };
                    await dbContext.Set<AnexoComunicacao>().AddAsync(anexo);
                }

                // Salvar anexos
                if (Anexos.Any())
                {
                    await dbContext.SaveChangesAsync();
                }

                var tempoDiferenca = DataEnvioAgendado - DateTime.Now;
                string mensagemTempo = tempoDiferenca.TotalHours < 24
                    ? $"em {(int)tempoDiferenca.TotalHours}h"
                    : DataEnvioAgendado.ToString("dd/MM Ã s HH:mm");

                SuccessMessage = $"ðŸ“… Email agendado para envio {mensagemTempo}";
                _logger.LogInformation("ðŸ“… Email ID {Id} agendado para {Data}", comunicacaoAgendada.Id, DataEnvioAgendado);

                // Limpar formulÃ¡rio
                Assunto = string.Empty;
                Corpo = string.Empty;
                TemplateSelecionado = "Personalizado"; // â­ CORREÃ‡ÃƒO: Limpar dropdown
                AgendarEnvio = false;
                DataEnvioAgendado = DateTime.Now.AddDays(1).Date.AddHours(9);
                Anexos.Clear();
                StatusAnexos = string.Empty;

                // Recarregar histÃ³rico
                await CarregarHistoricoAsync();

                IsLoading = false;
                return; // â­ IMPORTANTE: NÃ£o continuar para envio imediato
            }

            // âš¡ ENVIO IMEDIATO (cÃ³digo original)
            // Isso evita duplicaÃ§Ã£o pelo EmailProcessorService background task
            var emailMessage = new EmailMessage
            {
                To = Destinatario,
                ToName = PacienteAtual.NomeCompleto,
                Subject = Assunto,
                Body = Corpo,
                IsHtml = true,
                Attachments = Anexos.ToList()
            };

            var resultado = await _emailService.EnviarAsync(emailMessage);

            // â­ CORREÃ‡ÃƒO: Usar scope isolado para DbContext
            using var scope2 = _scopeFactory.CreateScope();
            var dbContext2 = scope2.ServiceProvider.GetRequiredService<BioDeskDbContext>();

            // Criar comunicaÃ§Ã£o na DB com STATUS CORRETO desde o inÃ­cio
            var comunicacao = new Comunicacao
            {
                PacienteId = PacienteAtual.Id,
                Tipo = TipoSelecionado,
                Destinatario = Destinatario,
                Assunto = Assunto,
                Corpo = Corpo,
                TemplateUtilizado = TemplateSelecionado,
                Status = resultado.Sucesso ? StatusComunicacao.Enviado : StatusComunicacao.Agendado,
                IsEnviado = resultado.Sucesso,
                DataCriacao = DateTime.Now,
                DataEnvio = resultado.Sucesso ? DateTime.Now : null,
                ProximaTentativa = resultado.Sucesso ? null : DateTime.Now.AddMinutes(2),
                TentativasEnvio = resultado.Sucesso ? 0 : 1,
                UltimoErro = resultado.Sucesso ? null : resultado.Mensagem
            };

            await dbContext2.Comunicacoes.AddAsync(comunicacao);

            // â­ CRÃTICO: Salvar primeiro para obter ID da comunicaÃ§Ã£o
            await dbContext2.SaveChangesAsync();

            // Gravar anexos na BD (agora com ID correto)
            foreach (var caminhoFicheiro in Anexos)
            {
                var anexo = new AnexoComunicacao
                {
                    ComunicacaoId = comunicacao.Id, // â­ Agora tem ID vÃ¡lido
                    CaminhoArquivo = caminhoFicheiro,
                    NomeArquivo = System.IO.Path.GetFileName(caminhoFicheiro),
                    TamanhoBytes = new System.IO.FileInfo(caminhoFicheiro).Length,
                    DataCriacao = DateTime.Now
                };
                await dbContext2.Set<AnexoComunicacao>().AddAsync(anexo);
            }

            // Salvar anexos
            if (Anexos.Any())
            {
                await dbContext2.SaveChangesAsync();
            }

            // Mensagem de feedback conforme resultado
            if (resultado.Sucesso)
            {
                SuccessMessage = "âœ… Email enviado com sucesso!";
                _logger.LogInformation("âœ… Email ID {Id} enviado IMEDIATAMENTE (Status={Status})", comunicacao.Id, comunicacao.Status);
            }
            else
            {
                if (resultado.AdicionadoNaFila)
                {
                    SuccessMessage = "âš ï¸ Sem conexÃ£o. Email agendado para envio automÃ¡tico.";
                    _logger.LogWarning("âš ï¸ Email ID {Id} agendado (sem rede, Status={Status})", comunicacao.Id, comunicacao.Status);
                }
                else
                {
                    SuccessMessage = $"âš ï¸ Erro ao enviar. Email agendado para retry em 2 minutos.";
                    _logger.LogWarning("âš ï¸ Email ID {Id} agendado para retry (erro: {Error}, Status={Status})", comunicacao.Id, resultado.Mensagem, comunicacao.Status);
                }
            }

            // Limpar formulÃ¡rio
            Assunto = string.Empty;
            Corpo = string.Empty;
            TemplateSelecionado = "Personalizado"; // â­ CORREÃ‡ÃƒO: Limpar dropdown
            Anexos.Clear(); // â­ Limpar anexos
            StatusAnexos = string.Empty;

            // Recarregar histÃ³rico
            await CarregarHistoricoAsync();

            IsLoading = false;

        }, "Erro ao enviar email", _logger);
    }

    /// <summary>
    /// â­ NOVO: Cancelar email agendado (impede envio automÃ¡tico)
    /// </summary>
    [RelayCommand]
    private async Task CancelarEmailAsync(Comunicacao comunicacao)
    {
        if (comunicacao == null)
        {
            ErrorMessage = "âŒ Nenhuma comunicaÃ§Ã£o selecionada!";
            return;
        }

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("ðŸš« Tentando cancelar email ID {Id} com status {Status}", comunicacao.Id, comunicacao.Status);

            if (comunicacao.Status != StatusComunicacao.Agendado)
            {
                ErrorMessage = $"âŒ Apenas emails 'Agendados' podem ser cancelados!\nStatus atual: {comunicacao.Status}";
                _logger.LogWarning("âš ï¸ Email ID {Id} nÃ£o pode ser cancelado (Status: {Status})", comunicacao.Id, comunicacao.Status);
                return;
            }

            IsLoading = true;

            // â­ CORREÃ‡ÃƒO: Usar scope isolado para DbContext
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

            // Buscar entidade do DbContext para garantir tracking EF Core
            var comunicacaoDb = await dbContext.Comunicacoes.FindAsync(comunicacao.Id);

            if (comunicacaoDb == null)
            {
                ErrorMessage = "âŒ Email nÃ£o encontrado na base de dados!";
                _logger.LogError("Email ID {Id} nÃ£o encontrado na BD", comunicacao.Id);
                IsLoading = false;
                return;
            }

            comunicacaoDb.Status = StatusComunicacao.Falhado;
            comunicacaoDb.UltimoErro = "Cancelado pelo utilizador";
            await dbContext.SaveChangesAsync();

            SuccessMessage = "âœ… Email cancelado com sucesso!";
            _logger.LogInformation("âœ… Email ID {Id} cancelado pelo utilizador", comunicacao.Id);

            // Recarregar histÃ³rico
            await CarregarHistoricoAsync();

            IsLoading = false;

        }, "Erro ao cancelar email", _logger);
    }


    /// <summary>
    /// 🔧 DIAGNÓSTICO: Forçar processamento imediato da fila de emails
    /// </summary>
    [RelayCommand]
    private async Task ProcessarFilaManualmenteAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogWarning("🔧 [ProcessarFilaManual] INICIANDO processamento MANUAL da fila...");
            IsLoading = true;
            
            await _emailService.ProcessarFilaAsync();
            
            _logger.LogWarning("✅ [ProcessarFilaManual] Processamento manual CONCLUÍDO!");
            
            // Recarregar histórico para ver atualizações
            await CarregarHistoricoAsync();
            
            SuccessMessage = "✅ Fila processada! Verifique o histórico e os logs.";
            IsLoading = false;
            
        }, "Erro ao processar fila manualmente", _logger);
    }

    [RelayCommand]
    private void LimparFormulario()
    {
        Assunto = string.Empty;
        Corpo = string.Empty;
        TemplateSelecionado = "Personalizado";
        Anexos.Clear();
        StatusAnexos = string.Empty;
    }

    /// <summary>
    /// â­ NOVO: Abre pasta documental do paciente
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
            _logger.LogInformation("ðŸ“‚ Pasta aberta para paciente {Id}", PacienteAtual.Id);
            IsLoading = false;
        }, "Erro ao abrir pasta do paciente", _logger);
    }

    /// <summary>
    /// â­ NOVO: Adiciona anexo usando diÃ¡logo de ficheiros
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

            // â­ NOVO: Abre automaticamente na pasta do paciente
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
                _logger.LogInformation("ðŸ“Ž {Count} anexos adicionados", openFileDialog.FileNames.Length);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Erro ao adicionar anexo: {ex.Message}";
            _logger.LogError(ex, "Erro ao adicionar anexo");
        }
    }

    /// <summary>
    /// â­ NOVO: Abre pop-up para selecionar templates PDF
    /// Templates selecionados sÃ£o adicionados automaticamente aos anexos
    /// </summary>
    [RelayCommand]
    private async Task SelecionarTemplatesPdfAsync()
    {
        if (PacienteAtual == null)
        {
            ErrorMessage = "Nenhum paciente selecionado!";
            return;
        }

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            // Criar lista de templates disponÃ­veis
            var templates = await _templatesPdfService.ListarTemplatesAsync();

            if (!templates.Any())
            {
                ErrorMessage = "Nenhum template PDF encontrado na pasta Templates/PDFs/";
                _logger.LogWarning("âš ï¸ Pasta de templates vazia");
                return;
            }

            // âœ… Adicionar templates diretamente aos anexos
            // IntegraÃ§Ã£o com pop-up serÃ¡ feita na View (code-behind) para respeitar MVVM
            foreach (var template in templates)
            {
                if (!Anexos.Contains(template.CaminhoCompleto))
                {
                    Anexos.Add(template.CaminhoCompleto);
                }
            }

            AtualizarStatusAnexos();

            _logger.LogInformation("âœ… {Count} templates disponÃ­veis para anexar", templates.Count);

        }, "Erro ao selecionar templates", _logger);
    }

    /// <summary>
    /// â­ NOVO: Abre file picker para adicionar novo template PDF Ã  pasta Templates/PDFs/
    /// </summary>
    [RelayCommand]
    private async Task AdicionarNovoTemplatePdfAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            await Task.CompletedTask; // diálogo é síncrono

            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Selecionar Template(s) PDF",
                Filter = "Ficheiros PDF (*.pdf)|*.pdf",
                Multiselect = true,
                CheckFileExists = true
            };

            if (dialog.ShowDialog() != true)
            {
                _logger.LogDebug("Utilizador cancelou seleção de template");
                return;
            }

            var templatesPdfFullPath = System.IO.Path.Combine(
                BioDesk.Services.PathService.TemplatesPath, "PDFs");

            System.IO.Directory.CreateDirectory(templatesPdfFullPath);

            int adicionados = 0;
            int atualizados = 0;
            var ficheirosSelecionados = dialog.FileNames != null && dialog.FileNames.Length > 0
                ? dialog.FileNames
                : new[] { dialog.FileName };

            foreach (var sourceFile in ficheirosSelecionados)
            {
                var fileName = System.IO.Path.GetFileName(sourceFile);
                if (string.IsNullOrWhiteSpace(fileName))
                    continue;

                var destFile = System.IO.Path.Combine(templatesPdfFullPath, fileName);

                if (System.IO.File.Exists(destFile))
                {
                    var msgBox = System.Windows.MessageBox.Show(
                        $"O ficheiro '{fileName}' já existe na pasta de templates.\n\nDeseja substituir?",
                        "Template Existente",
                        System.Windows.MessageBoxButton.YesNo,
                        System.Windows.MessageBoxImage.Question);
                    if (msgBox != System.Windows.MessageBoxResult.Yes)
                        continue;

                    atualizados++;
                }
                else
                {
                    adicionados++;
                }

                System.IO.File.Copy(sourceFile, destFile, overwrite: true);
                _logger.LogInformation("Template PDF copiado para {Destino}", destFile);
            }

            SuccessMessage = $"{adicionados} adicionado(s), {atualizados} atualizado(s).";
        }, "Erro ao adicionar template", _logger);
    }
    /// âœ… Atualiza o status de anexos (pÃºblico para ser chamado do code-behind)
    /// </summary>
    public void AtualizarStatusAnexos()
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

        try
        {
            // â­ CORREÃ‡ÃƒO CRÃTICA: Usar scope isolado para evitar threading issues
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

            var historico = await dbContext.Comunicacoes
                .AsNoTracking() // â­ Garantir dados frescos da BD (nÃ£o cache)
                .Where(c => c.PacienteId == PacienteAtual.Id && !c.IsDeleted)
                .OrderByDescending(c => c.DataCriacao)
                .Take(10)  // â­ Limitar aos Ãºltimos 10 para melhor performance
                .ToListAsync();

            HistoricoComunicacoes.Clear();
            foreach (var comunicacao in historico)
            {
                HistoricoComunicacoes.Add(comunicacao);
            }

            _logger.LogInformation("ðŸ“‹ HistÃ³rico recarregado: {Count} comunicaÃ§Ãµes para paciente {PacienteId}",
                historico.Count, PacienteAtual.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "âŒ Erro ao carregar histÃ³rico de comunicaÃ§Ãµes");
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task CarregarEstatisticasAsync()
    {
        if (PacienteAtual == null) return;

        // â­ CORREÃ‡ÃƒO: Usar scope isolado
        using var scope = _scopeFactory.CreateScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

        var todas = await dbContext.Comunicacoes
            .AsNoTracking()
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

        // â­ CORREÃ‡ÃƒO: Scope jÃ¡ está ativo (mesmo mÃ©todo), reutilizar dbContext
        ProximoFollowUp = await dbContext.Comunicacoes
            .AsNoTracking()
            .Where(c => c.PacienteId == PacienteAtual.Id && c.DataFollowUp.HasValue && !c.FollowUpEnviado)
            .OrderBy(c => c.DataFollowUp)
            .Select(c => c.DataFollowUp)
            .FirstOrDefaultAsync();
    }

    // ============================
    // â­ NOVO: GESTÃƒO DE DOCUMENTOS DO PACIENTE
    // ============================

    /// <summary>
    /// Carrega todos os documentos (PDFs) do paciente atual
    /// Busca em: Consentimentos/, Prescricoes/, Pacientes/[Nome]/
    /// </summary>
    [RelayCommand]
    private async Task CarregarDocumentosPacienteAsync()
    {
        // ðŸ”¥ GUARD ABSOLUTO: Se paciente null OU sem Id â†’ LIMPAR E SAIR
        if (PacienteAtual == null || PacienteAtual.Id == 0)
        {
            DocumentosPaciente.Clear();
            StatusDocumentos = PacienteAtual == null
                ? "Nenhum paciente selecionado"
                : "Paciente ainda nÃ£o foi salvo";
            _logger.LogWarning("âš ï¸ Tentativa de carregar documentos sem paciente vÃ¡lido");
            return;
        }

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            CarregandoDocumentos = true;
            StatusDocumentos = "A carregar documentos...";

            var documentos = await _documentosPacienteService.ObterDocumentosDoPacienteAsync(
                PacienteAtual.Id,
                PacienteAtual.NomeCompleto);

            DocumentosPaciente.Clear();
            foreach (var doc in documentos)
            {
                DocumentosPaciente.Add(new DocumentoPacienteViewModel(doc));
            }

            StatusDocumentos = DocumentosPaciente.Count switch
            {
                0 => "Nenhum documento encontrado",
                1 => "1 documento encontrado",
                _ => $"{DocumentosPaciente.Count} documentos encontrados"
            };

            _logger.LogInformation("ðŸ“„ Carregados {Count} documentos do paciente {PacienteId}",
                DocumentosPaciente.Count, PacienteAtual.Id);

            CarregandoDocumentos = false;
        });
    }

    /// <summary>
    /// Anexa os documentos selecionados ao email
    /// </summary>
    [RelayCommand]
    private void AnexarDocumentosSelecionados()
    {
        try
        {
            var selecionados = DocumentosPaciente
                .Where(d => d.Selecionado)
                .ToList();

            if (!selecionados.Any())
            {
                ErrorMessage = "Nenhum documento selecionado!";
                return;
            }

            int adicionados = 0;
            foreach (var doc in selecionados)
            {
                if (!Anexos.Contains(doc.CaminhoCompleto))
                {
                    Anexos.Add(doc.CaminhoCompleto);
                    adicionados++;
                    _logger.LogInformation("ðŸ“Ž Documento anexado: {Nome}", doc.Nome);
                }
            }

            AtualizarStatusAnexos();

            // Limpar seleÃ§Ã£o apÃ³s anexar
            foreach (var doc in selecionados)
            {
                doc.Selecionado = false;
            }

            _logger.LogInformation("âœ… {Count} documento(s) anexado(s) ao email", adicionados);

            if (adicionados > 0)
            {
                StatusDocumentos = $"{adicionados} documento(s) anexado(s) ao email";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "âŒ Erro ao anexar documentos selecionados");
            ErrorMessage = $"Erro ao anexar documentos: {ex.Message}";
        }
    }

    /// <summary>
    /// Seleciona/deseleciona todos os documentos
    /// âš ï¸ ACEITA object para compatibilidade com XAML (converte string/bool)
    /// </summary>
    [RelayCommand]
    private void SelecionarTodosDocumentos(object? parameter)
    {
        bool selecionar = parameter switch
        {
            bool b => b,
            string s when bool.TryParse(s, out var result) => result,
            _ => false
        };

        foreach (var doc in DocumentosPaciente)
        {
            doc.Selecionado = selecionar;
        }

        _logger.LogInformation("{Action} todos os documentos",
            selecionar ? "Selecionados" : "Desmarcados");
    }

    /// <summary>
    /// â­ NOVO: Abre documento PDF no visualizador padrÃ£o do sistema
    /// </summary>
    [RelayCommand]
    private void AbrirDocumento(DocumentoPacienteViewModel? documento)
    {
        if (documento == null)
        {
            _logger.LogWarning("âš ï¸ Tentativa de abrir documento null");
            return;
        }

        try
        {
            if (!File.Exists(documento.CaminhoCompleto))
            {
                ErrorMessage = $"Documento nÃ£o encontrado: {documento.Nome}";
                _logger.LogWarning("ðŸ“„ Documento nÃ£o existe: {Caminho}", documento.CaminhoCompleto);
                return;
            }

            _logger.LogInformation("ðŸ“‚ Abrindo documento: {Nome}", documento.Nome);

            var processStartInfo = new ProcessStartInfo
            {
                FileName = documento.CaminhoCompleto,
                UseShellExecute = true
            };

            Process.Start(processStartInfo);

            _logger.LogInformation("âœ… Documento aberto com sucesso: {Nome}", documento.Nome);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "âŒ Erro ao abrir documento: {Nome}", documento.Nome);
            ErrorMessage = $"Erro ao abrir documento: {ex.Message}";
        }
    }

    /// <summary>
    /// Valida se o email tem formato correto (user@domain.com)
    /// </summary>
    private bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;

        try
        {
            // ValidaÃ§Ã£o bÃ¡sica: deve conter @ e domÃ­nio
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}
