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
/// ViewModel para Aba 5: Comunicação & Seguimento
/// Suporta envio de emails offline com fila automática
/// </summary>
public partial class ComunicacaoViewModel : ViewModelBase
{
    private readonly ILogger<ComunicacaoViewModel> _logger;
    private readonly IEmailService _emailService;
    private readonly IServiceScopeFactory _scopeFactory; // ⭐ CORREÇÃO: Usa scope factory para DbContext isolado
    private readonly IDocumentoService _documentoService;
    private readonly IDocumentosPacienteService _documentosPacienteService;
    private readonly ITemplatesPdfService _templatesPdfService;

    [ObservableProperty] private Paciente? _pacienteAtual;
    [ObservableProperty] private ObservableCollection<Comunicacao> _historicoComunicacoes = new();

    /// <summary>
    /// Informação do cabeçalho do histórico
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
    /// Notifica UI quando o histórico muda
    /// </summary>
    partial void OnHistoricoComunicacoesChanged(ObservableCollection<Comunicacao> value)
    {
        OnPropertyChanged(nameof(TotalEnviados));
        OnPropertyChanged(nameof(ProximoAgendamento));
    }

    // ⭐ NOVO: Gestão de documentos do paciente
    [ObservableProperty] private ObservableCollection<DocumentoPacienteViewModel> _documentosPaciente = new();
    [ObservableProperty] private bool _carregandoDocumentos = false;
    [ObservableProperty] private string _statusDocumentos = "Nenhum documento encontrado";

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

        // ⭐ NOVO: Carregar documentos do paciente automaticamente
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

    // ⭐ Agendamento de envio do email
    [ObservableProperty] private bool _agendarEnvio = false;
    [ObservableProperty] private DateTime _dataEnvioAgendado = DateTime.Now.AddDays(1).Date.AddHours(9); // Amanhã às 9h por padrão

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
        "Envio de Documentos", // ⭐ NOVO: Template para anexar documentos
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
        IServiceScopeFactory scopeFactory, // ⭐ CORREÇÃO: Scope factory para DbContext isolado
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
    /// ⭐ CORREÇÃO: Task de background para verificar conexão
    /// </summary>
    private void IniciarMonitorConexao()
    {
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
            "Envio de Documentos" => "Documentação Anexa", // ⭐ NOVO
            "Prescrição" => "Prescrição de Tratamento",
            "Confirmação de Consulta" => "Confirmação de Consulta",
            "Follow-up" => "Acompanhamento de Tratamento",
            "Lembrete" => "Lembrete",
            _ => string.Empty
        };

        Corpo = value switch
        {
            "Envio de Documentos" => $@"Olá {PacienteAtual.NomeCompleto},

Conforme solicitado, segue em anexo a documentação necessária.

Se tiver alguma dúvida, estou à disposição.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
📧 nunocorreiaterapiasnaturais@gmail.com | 📞 +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "Prescrição" => $@"Olá {PacienteAtual.NomeCompleto},

Conforme conversado na consulta, segue em anexo a prescrição recomendada.

Qualquer dúvida, estou à disposição.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
📧 nunocorreiaterapiasnaturais@gmail.com | 📞 +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "Confirmação de Consulta" => $@"Olá {PacienteAtual.NomeCompleto},

Confirmamos a sua consulta para [DATA/HORA].

Em caso de necessidade de reagendar, por favor contacte-nos.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
📧 nunocorreiaterapiasnaturais@gmail.com | 📞 +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "Follow-up" => $@"Olá {PacienteAtual.NomeCompleto},

Como está a decorrer o tratamento? Sente melhorias?

Estou disponível para qualquer esclarecimento.

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
📧 nunocorreiaterapiasnaturais@gmail.com | 📞 +351 964 860 387
🌿 Cuidar de si, naturalmente",

            "Lembrete" => $@"Olá {PacienteAtual.NomeCompleto},

Lembrete: [DETALHE DO LEMBRETE]

Cumprimentos,

Nuno Correia - Terapias Naturais
Naturopatia - Osteopatia - Medicina Bioenergética
📧 nunocorreiaterapiasnaturais@gmail.com | 📞 +351 964 860 387
🌿 Cuidar de si, naturalmente",

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

            // ⭐ Validar formato de email (apenas warning, não bloqueia)
            if (!IsValidEmail(Destinatario))
            {
                _logger.LogWarning("⚠️ Email com formato suspeito: {Email}", Destinatario);
                // Continua mesmo assim (pode ser email interno/teste)
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

            // ⭐ NOVO: Verificar se deve agendar o envio para data futura
            if (AgendarEnvio && DataEnvioAgendado > DateTime.Now)
            {
                // ⭐ CORREÇÃO: Usar scope isolado para DbContext
                using var scope = _scopeFactory.CreateScope();
                var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

                // AGENDAR para envio futuro (não enviar imediatamente)
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
                    ProximaTentativa = DataEnvioAgendado, // ⭐ Data escolhida pelo utilizador
                    TentativasEnvio = 0,
                    UltimoErro = null
                };

                await dbContext.Comunicacoes.AddAsync(comunicacaoAgendada);

                // ⭐ CRÍTICO: Salvar primeiro para obter ID
                await dbContext.SaveChangesAsync();

                // Gravar anexos na BD (agora com ID correto)
                foreach (var caminhoFicheiro in Anexos)
                {
                    var anexo = new AnexoComunicacao
                    {
                        ComunicacaoId = comunicacaoAgendada.Id, // ⭐ Agora tem ID válido
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
                    : DataEnvioAgendado.ToString("dd/MM às HH:mm");

                SuccessMessage = $"📅 Email agendado para envio {mensagemTempo}";
                _logger.LogInformation("📅 Email ID {Id} agendado para {Data}", comunicacaoAgendada.Id, DataEnvioAgendado);

                // Limpar formulário
                Assunto = string.Empty;
                Corpo = string.Empty;
                TemplateSelecionado = "Personalizado"; // ⭐ CORREÇÃO: Limpar dropdown
                AgendarEnvio = false;
                DataEnvioAgendado = DateTime.Now.AddDays(1).Date.AddHours(9);
                Anexos.Clear();
                StatusAnexos = string.Empty;

                // Recarregar histórico
                await CarregarHistoricoAsync();

                IsLoading = false;
                return; // ⭐ IMPORTANTE: Não continuar para envio imediato
            }

            // ⚡ ENVIO IMEDIATO (código original)
            // Isso evita duplicação pelo EmailProcessorService background task
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

            // ⭐ CORREÇÃO: Usar scope isolado para DbContext
            using var scope2 = _scopeFactory.CreateScope();
            var dbContext2 = scope2.ServiceProvider.GetRequiredService<BioDeskDbContext>();

            // Criar comunicação na DB com STATUS CORRETO desde o início
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

            // ⭐ CRÍTICO: Salvar primeiro para obter ID da comunicação
            await dbContext2.SaveChangesAsync();

            // Gravar anexos na BD (agora com ID correto)
            foreach (var caminhoFicheiro in Anexos)
            {
                var anexo = new AnexoComunicacao
                {
                    ComunicacaoId = comunicacao.Id, // ⭐ Agora tem ID válido
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
                SuccessMessage = "✅ Email enviado com sucesso!";
                _logger.LogInformation("✅ Email ID {Id} enviado IMEDIATAMENTE (Status={Status})", comunicacao.Id, comunicacao.Status);
            }
            else
            {
                if (resultado.AdicionadoNaFila)
                {
                    SuccessMessage = "⚠️ Sem conexão. Email agendado para envio automático.";
                    _logger.LogWarning("⚠️ Email ID {Id} agendado (sem rede, Status={Status})", comunicacao.Id, comunicacao.Status);
                }
                else
                {
                    SuccessMessage = $"⚠️ Erro ao enviar. Email agendado para retry em 2 minutos.";
                    _logger.LogWarning("⚠️ Email ID {Id} agendado para retry (erro: {Error}, Status={Status})", comunicacao.Id, resultado.Mensagem, comunicacao.Status);
                }
            }

            // Limpar formulário
            Assunto = string.Empty;
            Corpo = string.Empty;
            TemplateSelecionado = "Personalizado"; // ⭐ CORREÇÃO: Limpar dropdown
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
        if (comunicacao == null)
        {
            ErrorMessage = "❌ Nenhuma comunicação selecionada!";
            return;
        }

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("🚫 Tentando cancelar email ID {Id} com status {Status}", comunicacao.Id, comunicacao.Status);

            if (comunicacao.Status != StatusComunicacao.Agendado)
            {
                ErrorMessage = $"❌ Apenas emails 'Agendados' podem ser cancelados!\n\nStatus atual: {comunicacao.Status}";
                _logger.LogWarning("⚠️ Email ID {Id} não pode ser cancelado (Status: {Status})", comunicacao.Id, comunicacao.Status);
                return;
            }

            IsLoading = true;

            // ⭐ CORREÇÃO: Usar scope isolado para DbContext
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

            // Buscar entidade do DbContext para garantir tracking EF Core
            var comunicacaoDb = await dbContext.Comunicacoes.FindAsync(comunicacao.Id);

            if (comunicacaoDb == null)
            {
                ErrorMessage = "❌ Email não encontrado na base de dados!";
                _logger.LogError("Email ID {Id} não encontrado na BD", comunicacao.Id);
                IsLoading = false;
                return;
            }

            comunicacaoDb.Status = StatusComunicacao.Falhado;
            comunicacaoDb.UltimoErro = "Cancelado pelo utilizador";
            await dbContext.SaveChangesAsync();

            SuccessMessage = "✅ Email cancelado com sucesso!";
            _logger.LogInformation("✅ Email ID {Id} cancelado pelo utilizador", comunicacao.Id);

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

    /// <summary>
    /// ⭐ NOVO: Abre pop-up para selecionar templates PDF
    /// Templates selecionados são adicionados automaticamente aos anexos
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
            // Criar lista de templates disponíveis
            var templates = await _templatesPdfService.ListarTemplatesAsync();

            if (!templates.Any())
            {
                ErrorMessage = "Nenhum template PDF encontrado na pasta Templates/PDFs/";
                _logger.LogWarning("⚠️ Pasta de templates vazia");
                return;
            }

            // ✅ Adicionar templates diretamente aos anexos
            // Integração com pop-up será feita na View (code-behind) para respeitar MVVM
            foreach (var template in templates)
            {
                if (!Anexos.Contains(template.CaminhoCompleto))
                {
                    Anexos.Add(template.CaminhoCompleto);
                }
            }

            AtualizarStatusAnexos();

            _logger.LogInformation("✅ {Count} templates disponíveis para anexar", templates.Count);

        }, "Erro ao selecionar templates", _logger);
    }

    /// <summary>
    /// ⭐ NOVO: Abre file picker para adicionar novo template PDF à pasta Templates/PDFs/
    /// </summary>
    [RelayCommand]
    private async Task AdicionarNovoTemplatePdfAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            await Task.CompletedTask; // Suprime warning CS1998 (diálogo é síncrono)

            // Abrir file picker para selecionar PDF
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Selecionar Template PDF",
                Filter = "Ficheiros PDF (*.pdf)|*.pdf",
                Multiselect = false,
                CheckFileExists = true
            };

            if (dialog.ShowDialog() != true)
            {
                _logger.LogDebug("📋 Utilizador cancelou seleção de template");
                return;
            }

            var sourceFile = dialog.FileName;
            var fileName = System.IO.Path.GetFileName(sourceFile);

            // Usar PathService para obter caminho dos templates (Debug/Release)
            var templatesPdfFullPath = System.IO.Path.Combine(
                BioDesk.Services.PathService.TemplatesPath, "PDFs");

            // Garantir que pasta existe
            System.IO.Directory.CreateDirectory(templatesPdfFullPath);

            var destFile = System.IO.Path.Combine(templatesPdfFullPath, fileName);

            // Verificar se já existe
            if (System.IO.File.Exists(destFile))
            {
                var msgBox = System.Windows.MessageBox.Show(
                    $"O ficheiro '{fileName}' já existe na pasta de templates.\n\nDeseja substituir?",
                    "Template Existente",
                    System.Windows.MessageBoxButton.YesNo,
                    System.Windows.MessageBoxImage.Question);

                if (msgBox != System.Windows.MessageBoxResult.Yes)
                {
                    _logger.LogDebug("📋 Utilizador cancelou substituição de template existente");
                    return;
                }
            }

            // Copiar ficheiro
            System.IO.File.Copy(sourceFile, destFile, overwrite: true);

            SuccessMessage = $"✅ Template '{fileName}' adicionado com sucesso!";
            _logger.LogInformation("📋 Template adicionado: {File} → {Dest}", sourceFile, destFile);

        }, "Erro ao adicionar template", _logger);
    }

    /// <summary>
    /// ✅ Atualiza o status de anexos (público para ser chamado do code-behind)
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
            // ⭐ CORREÇÃO CRÍTICA: Usar scope isolado para evitar threading issues
            using var scope = _scopeFactory.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

            var historico = await dbContext.Comunicacoes
                .AsNoTracking() // ⭐ Garantir dados frescos da BD (não cache)
                .Where(c => c.PacienteId == PacienteAtual.Id && !c.IsDeleted)
                .OrderByDescending(c => c.DataCriacao)
                .Take(10)  // ⭐ Limitar aos últimos 10 para melhor performance
                .ToListAsync();

            HistoricoComunicacoes.Clear();
            foreach (var comunicacao in historico)
            {
                HistoricoComunicacoes.Add(comunicacao);
            }

            _logger.LogInformation("📋 Histórico recarregado: {Count} comunicações para paciente {PacienteId}",
                historico.Count, PacienteAtual.Id);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar histórico de comunicações");
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task CarregarEstatisticasAsync()
    {
        if (PacienteAtual == null) return;

        // ⭐ CORREÇÃO: Usar scope isolado
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

        // ⭐ CORREÇÃO: Scope já está ativo (mesmo método), reutilizar dbContext
        ProximoFollowUp = await dbContext.Comunicacoes
            .AsNoTracking()
            .Where(c => c.PacienteId == PacienteAtual.Id && c.DataFollowUp.HasValue && !c.FollowUpEnviado)
            .OrderBy(c => c.DataFollowUp)
            .Select(c => c.DataFollowUp)
            .FirstOrDefaultAsync();
    }

    // ============================
    // ⭐ NOVO: GESTÃO DE DOCUMENTOS DO PACIENTE
    // ============================

    /// <summary>
    /// Carrega todos os documentos (PDFs) do paciente atual
    /// Busca em: Consentimentos/, Prescricoes/, Pacientes/[Nome]/
    /// </summary>
    [RelayCommand]
    private async Task CarregarDocumentosPacienteAsync()
    {
        // 🔥 GUARD ABSOLUTO: Se paciente null OU sem Id → LIMPAR E SAIR
        if (PacienteAtual == null || PacienteAtual.Id == 0)
        {
            DocumentosPaciente.Clear();
            StatusDocumentos = PacienteAtual == null
                ? "Nenhum paciente selecionado"
                : "Paciente ainda não foi salvo";
            _logger.LogWarning("⚠️ Tentativa de carregar documentos sem paciente válido");
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

            _logger.LogInformation("📄 Carregados {Count} documentos do paciente {PacienteId}",
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
                    _logger.LogInformation("📎 Documento anexado: {Nome}", doc.Nome);
                }
            }

            AtualizarStatusAnexos();

            // Limpar seleção após anexar
            foreach (var doc in selecionados)
            {
                doc.Selecionado = false;
            }

            _logger.LogInformation("✅ {Count} documento(s) anexado(s) ao email", adicionados);

            if (adicionados > 0)
            {
                StatusDocumentos = $"{adicionados} documento(s) anexado(s) ao email";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao anexar documentos selecionados");
            ErrorMessage = $"Erro ao anexar documentos: {ex.Message}";
        }
    }

    /// <summary>
    /// Seleciona/deseleciona todos os documentos
    /// ⚠️ ACEITA object para compatibilidade com XAML (converte string/bool)
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
    /// ⭐ NOVO: Abre documento PDF no visualizador padrão do sistema
    /// </summary>
    [RelayCommand]
    private void AbrirDocumento(DocumentoPacienteViewModel? documento)
    {
        if (documento == null)
        {
            _logger.LogWarning("⚠️ Tentativa de abrir documento null");
            return;
        }

        try
        {
            if (!File.Exists(documento.CaminhoCompleto))
            {
                ErrorMessage = $"Documento não encontrado: {documento.Nome}";
                _logger.LogWarning("📄 Documento não existe: {Caminho}", documento.CaminhoCompleto);
                return;
            }

            _logger.LogInformation("📂 Abrindo documento: {Nome}", documento.Nome);

            var processStartInfo = new ProcessStartInfo
            {
                FileName = documento.CaminhoCompleto,
                UseShellExecute = true
            };

            Process.Start(processStartInfo);

            _logger.LogInformation("✅ Documento aberto com sucesso: {Nome}", documento.Nome);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao abrir documento: {Nome}", documento.Nome);
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
            // Validação básica: deve conter @ e domínio
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }
}
