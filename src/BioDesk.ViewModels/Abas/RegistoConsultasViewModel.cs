using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pdf;
using BioDesk.Services.Documentos;
using BioDesk.ViewModels.Base;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using FluentValidation;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels.Abas;

public partial class RegistoConsultasViewModel : ViewModelBase, IDisposable
{
    private readonly ILogger<RegistoConsultasViewModel> _logger;
    private readonly IUnitOfWork _unitOfWork;
    private readonly PrescricaoPdfService _pdfService;
    private readonly IDocumentoService _documentoService;

    private readonly TimeSpan _autoSaveDelay = TimeSpan.FromSeconds(1.5);
    private readonly SemaphoreSlim _autoSaveSemaphore = new(1, 1);
    private CancellationTokenSource? _autoSaveCancellation;
    private Task _pendingAutoSaveTask = Task.CompletedTask;
    private int _autoSaveVersion;
    private bool _suspendAutoSave;
    private bool _disposed;

    [ObservableProperty] private Paciente? _pacienteAtual;
    [ObservableProperty] private ObservableCollection<Sessao> _sessoes = new();
    [ObservableProperty] private string _notas = string.Empty; // ✅ RENOMEADO de "_avaliacao"

    // ✅ NOVO: Terapia Atual dividida em 3 colunas
    [ObservableProperty] private string _medicacao = string.Empty;
    [ObservableProperty] private string _suplementacao = string.Empty;
    [ObservableProperty] private string _terapias = string.Empty;

    [ObservableProperty] private bool _mostrarPrescricao = false; // ✅ CORRIGIDO: Começa fechado
    [ObservableProperty] private ObservableCollection<SuplementoItem> _suplementos = new();
    [ObservableProperty] private string _observacoesPrescricao = string.Empty;
    [ObservableProperty] private DateTime _dataConsulta = DateTime.Now; // ✅ CORRIGIDO: Agora tem setter para TwoWay binding

    // ✅ NOVO: Modal de Detalhes da Consulta
    [ObservableProperty] private Sessao? _consultaSelecionada;
    [ObservableProperty] private bool _mostrarDetalhes = false;

    partial void OnMedicacaoChanged(string value) => HandleTerapiaAtualAlterada();
    partial void OnSuplementacaoChanged(string value) => HandleTerapiaAtualAlterada();
    partial void OnTerapiasChanged(string value) => HandleTerapiaAtualAlterada();

    public RegistoConsultasViewModel(
        ILogger<RegistoConsultasViewModel> logger,
        INavigationService navigationService,
        IUnitOfWork unitOfWork,
        PrescricaoPdfService pdfService,
        IDocumentoService documentoService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _pdfService = pdfService ?? throw new ArgumentNullException(nameof(pdfService));
        _documentoService = documentoService ?? throw new ArgumentNullException(nameof(documentoService));

        // 🔍 DEBUG: ViewModel construído
        _logger.LogWarning("🔧 RegistoConsultasViewModel CONSTRUÍDO!");
    }

    private void HandleTerapiaAtualAlterada()
    {
        if (_suspendAutoSave || PacienteAtual == null)
        {
            return;
        }

        CancelPendingAutoSave();
        DisposeAutoSaveCancellation();

        _autoSaveCancellation = new CancellationTokenSource();
        var token = _autoSaveCancellation.Token;
        var version = Interlocked.Increment(ref _autoSaveVersion);

        _pendingAutoSaveTask = DebounceGuardarTerapiaAtualAsync(version, token);
    }

    private async Task DebounceGuardarTerapiaAtualAsync(int version, CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(_autoSaveDelay, cancellationToken);

            if (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            if (version != Volatile.Read(ref _autoSaveVersion))
            {
                return;
            }

            await GuardarTerapiaAtualAsync(cancellationToken);
        }
        catch (OperationCanceledException)
        {
            // Ignorar cancelamentos explícitos
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro inesperado no auto-save da terapia atual");
        }
    }

    private async Task FlushAutoSaveAsync()
    {
        if (PacienteAtual == null)
        {
            return;
        }

        CancelPendingAutoSave();

        try
        {
            await _pendingAutoSaveTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Cancelamento esperado quando forçado
        }

        DisposeAutoSaveCancellation();

        Interlocked.Increment(ref _autoSaveVersion);
        await GuardarTerapiaAtualAsync();
    }

    private async Task GuardarTerapiaAtualAsync(CancellationToken cancellationToken = default)
    {
        if (PacienteAtual == null || cancellationToken.IsCancellationRequested)
        {
            return;
        }

        var terapiaAtualCompleta = ConstruirTextoTerapiaAtual();

        var lockTaken = false;

        try
        {
            await _autoSaveSemaphore.WaitAsync(cancellationToken);
            lockTaken = true;

            if (PacienteAtual == null || cancellationToken.IsCancellationRequested)
            {
                return;
            }

            if (string.Equals(PacienteAtual.TerapiaAtual, terapiaAtualCompleta, StringComparison.Ordinal))
            {
                return;
            }

            if (PacienteAtual.Id == 0)
            {
                PacienteAtual.TerapiaAtual = terapiaAtualCompleta;
                SuccessMessage = "💾 Terapia atual guardada para guardar junto com o paciente";
                return;
            }

            await ExecuteWithErrorHandlingAsync(async () =>
            {
                var pacienteDb = await _unitOfWork.Pacientes.GetByIdAsync(PacienteAtual.Id);
                if (pacienteDb == null)
                {
                    _logger.LogWarning("⚠️ Paciente ID {PacienteId} não encontrado ao guardar terapia", PacienteAtual.Id);
                    return;
                }

                if (string.Equals(pacienteDb.TerapiaAtual, terapiaAtualCompleta, StringComparison.Ordinal))
                {
                    PacienteAtual.TerapiaAtual = terapiaAtualCompleta;
                    return;
                }

                pacienteDb.TerapiaAtual = terapiaAtualCompleta;
                pacienteDb.DataUltimaAtualizacao = DateTime.Now;

                await _unitOfWork.SaveChangesAsync();

                PacienteAtual.TerapiaAtual = terapiaAtualCompleta;
                SuccessMessage = "💾 Terapia atual guardada automaticamente";
            }, "ao guardar terapia atual automaticamente", _logger);
        }
        catch (OperationCanceledException)
        {
            // Cancelado - não fazer nada
        }
        finally
        {
            if (lockTaken)
            {
                _autoSaveSemaphore.Release();
            }
        }
    }

    private string ConstruirTextoTerapiaAtual()
    {
        return $"Medicação: {Medicacao ?? string.Empty}\n\nSuplementação: {Suplementacao ?? string.Empty}\n\nTerapias: {Terapias ?? string.Empty}";
    }

    [RelayCommand]
    private async Task GuardarConsultaAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (PacienteAtual == null)
            {
                ErrorMessage = "❌ Nenhum paciente selecionado";
                return;
            }

            await FlushAutoSaveAsync();

            var validator = new ConsultaValidator();
            var result = await validator.ValidateAsync(this);
            if (!result.IsValid)
            {
                ErrorMessage = string.Join("\n", result.Errors.Select(e => e.ErrorMessage));
                return;
            }

            _logger.LogInformation("💾 Salvando consulta na BD para paciente ID {PacienteId}", PacienteAtual.Id);

            // ✅ ATUALIZAR TERAPIA ATUAL DO PACIENTE (concatenar 3 campos)
            var terapiaAtualCompleta = ConstruirTextoTerapiaAtual();
            if (PacienteAtual.TerapiaAtual != terapiaAtualCompleta)
            {
                PacienteAtual.TerapiaAtual = terapiaAtualCompleta;
                _unitOfWork.Pacientes.Update(PacienteAtual);
                _logger.LogInformation("💊 Terapia Atual atualizada no paciente");
            }

            // ✅ CRIAR NOVA SESSÃO E SALVAR NA BD
            var novaSessao = new Sessao
            {
                PacienteId = PacienteAtual.Id,
                DataHora = DataConsulta,
                Motivo = Notas.Length > 50 ? Notas.Substring(0, 50) : Notas,
                Avaliacao = Notas, // ✅ Notas vai para campo Avaliacao da BD
                Plano = string.Empty, // ✅ Campo Plano não é mais usado
                CriadoEm = DateTime.Now,
                IsDeleted = false
            };

            await _unitOfWork.Sessoes.AddAsync(novaSessao);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("✅ Consulta ID {Id} salva com sucesso!", novaSessao.Id);

            SuccessMessage = "✅ Consulta guardada na base de dados!";

            // Limpar apenas os campos específicos da consulta
            Notas = string.Empty;
            DataConsulta = DateTime.Now;

            // Recarregar lista
            await CarregarSessoesAsync(PacienteAtual.Id);

        }, "Erro ao guardar consulta");
    }

    [RelayCommand]
    private void AbrirPrescricao()
    {
        Suplementos.Clear();
        AdicionarSuplemento();
        MostrarPrescricao = true;
    }

    [RelayCommand] private void AdicionarSuplemento() => Suplementos.Add(new SuplementoItem());
    [RelayCommand] private void RemoverSuplemento(SuplementoItem item) => Suplementos.Remove(item);
    [RelayCommand] private void FecharPrescricao() => MostrarPrescricao = false;

    [RelayCommand]
    private async Task GerarPdfPrescricaoAsync()
    {
        _logger.LogInformation("🎯 Iniciando geração de PDF de prescrição...");

        try
        {
            _logger.LogWarning("📋 PASSO 1: Validando paciente...");

            // ✅ VALIDAÇÃO 1: Paciente
            if (PacienteAtual == null)
            {
                _logger.LogError("❌ ERRO: Nenhum paciente selecionado!");
                MessageBox.Show(
                    "❌ Nenhum paciente selecionado!\n\nPor favor, selecione um paciente antes de gerar a prescrição.",
                    "Erro - Paciente não selecionado",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            _logger.LogWarning("✅ Paciente OK: {Nome}", PacienteAtual.NomeCompleto);
            _logger.LogWarning("📋 PASSO 2: Validando suplementos...");

            // ✅ VALIDAÇÃO 2: Suplementos
            if (Suplementos == null || Suplementos.Count == 0)
            {
                _logger.LogError("❌ ERRO: Nenhum suplemento adicionado!");
                MessageBox.Show(
                    "❌ Adicione pelo menos um suplemento à prescrição!\n\nClique no botão '+ Adicionar' para incluir suplementos.",
                    "Erro - Sem suplementos",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            _logger.LogWarning("✅ Suplementos OK: {Count} itens", Suplementos.Count);
            _logger.LogWarning("� PASSO 3: Preparando dados...");

            IsLoading = true;

            // ⚠️ REMOVIDO: Diagnostico = Avaliacao (NÃO ir buscar dados da ficha)
            // ✅ NOVO: Campo Diagnostico preenchido manualmente pelo utilizador
            var dados = new DadosPrescricao
            {
                NomePaciente = PacienteAtual.NomeCompleto,
                DataPrescricao = DateTime.Now,
                Diagnostico = ObservacoesPrescricao ?? "", // ✅ CAMPO MANUAL (não vem da ficha)
                Itens = Suplementos.Select(s => new ItemPrescricao
                {
                    Nome = s.Suplemento ?? "Suplemento não especificado",
                    Dosagem = s.Dosagem ?? "",                           // ✅ USAR campo Dosagem
                    Frequencia = s.FormaTomar ?? "Conforme indicado",
                    Observacoes = s.Observacoes ?? ""                    // ✅ USAR campo Observacoes
                }).ToList()
            };

            _logger.LogWarning("✅ Dados preparados: {Count} itens", dados.Itens.Count);
            _logger.LogWarning("📋 PASSO 4: Chamando PrescricaoPdfService.GerarPdfPrescricao...");

            // ✅ PASSO 1: GERAR PDF temporário
            string caminhoTemporario;
            try
            {
                caminhoTemporario = _pdfService.GerarPdfPrescricao(dados);
                _logger.LogWarning("✅ PDF gerado: {Caminho}", caminhoTemporario);

                if (!File.Exists(caminhoTemporario))
                {
                    _logger.LogError("❌ ERRO: Ficheiro não existe em: {Caminho}", caminhoTemporario);
                    throw new FileNotFoundException($"PDF não foi criado no caminho: {caminhoTemporario}");
                }

                _logger.LogWarning("✅ Ficheiro confirmado: {Bytes} bytes", new FileInfo(caminhoTemporario).Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ ERRO CRÍTICO ao gerar PDF com QuestPDF");
                MessageBox.Show(
                    $"❌ ERRO ao gerar PDF!\n\nDetalhes técnicos:\n{ex.Message}\n\nStack Trace:\n{ex.StackTrace}",
                    "Erro na Geração do PDF",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                IsLoading = false;
                return;
            }

            _logger.LogWarning("📋 PASSO 5: Copiando para pasta do paciente...");

            // ✅ PASSO 2: COPIAR para pasta do paciente
            string caminhoFinal;
            try
            {
                caminhoFinal = await _documentoService.CopiarFicheiroParaPacienteAsync(
                    caminhoTemporario,
                    PacienteAtual.Id,
                    PacienteAtual.NomeCompleto,
                    TipoDocumento.Prescricoes
                );
                _logger.LogWarning("✅ PDF copiado para: {CaminhoFinal}", caminhoFinal);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ ERRO ao copiar PDF para pasta do paciente");
                MessageBox.Show(
                    $"⚠️ PDF foi gerado mas NÃO foi guardado na pasta do paciente!\n\nDetalhes:\n{ex.Message}\n\nPDF temporário: {caminhoTemporario}",
                    "Erro ao Guardar PDF",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                IsLoading = false;
                return;
            }

            _logger.LogWarning("📋 PASSO 6: Abrindo PDF...");

            // ✅ PASSO 3: ABRIR PDF
            bool pdfAberto = false;
            try
            {
                await Task.Run(() => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
                {
                    FileName = caminhoFinal,
                    UseShellExecute = true
                }));
                _logger.LogWarning("✅ PDF aberto no visualizador");
                pdfAberto = true;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "⚠️ PDF guardado mas não foi possível abrir automaticamente");
                pdfAberto = false;
            }

            _logger.LogWarning("📋 PASSO 7: Mostrando mensagem de sucesso...");

            // ✅ MENSAGEM DE SUCESSO GARANTIDA!
            var nomeArquivo = System.IO.Path.GetFileName(caminhoFinal);
            var mensagem = pdfAberto
                ? $"✅ PDF GERADO COM SUCESSO!\n\n📄 Ficheiro: {nomeArquivo}\n📂 Localização: Prescricoes/\n\n🎉 O PDF foi aberto automaticamente no visualizador!"
                : $"✅ PDF GERADO COM SUCESSO!\n\n📄 Ficheiro: {nomeArquivo}\n📂 Localização: Prescricoes/\n\n⚠️ Abra manualmente em:\n{caminhoFinal}";

            MessageBox.Show(
                mensagem,
                "Prescrição Gerada com Sucesso",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            _logger.LogWarning("🎉🎉🎉 PROCESSO COMPLETO! PDF GERADO COM SUCESSO! 🎉🎉🎉");
            SuccessMessage = $"✅ PDF guardado: {nomeArquivo}";

            IsLoading = false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌❌❌ ERRO CRÍTICO INESPERADO! ❌❌❌");
            MessageBox.Show(
                $"❌ ERRO CRÍTICO inesperado!\n\nDetalhes:\n{ex.Message}\n\n{ex.StackTrace}",
                "Erro Crítico",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            IsLoading = false;
        }
    }

    // ✅ NOVO: Comandos para modal de detalhes
    [RelayCommand]
    private void AbrirDetalhesConsulta(Sessao sessao)
    {
        ConsultaSelecionada = sessao;
        MostrarDetalhes = true;
        _logger.LogInformation("📄 Detalhes da consulta abertos: {DataHora}", sessao.DataHora);
    }

    [RelayCommand]
    private void FecharDetalhesConsulta()
    {
        MostrarDetalhes = false;
        ConsultaSelecionada = null;
    }

    public async Task SetPacienteAsync(Paciente paciente)
    {
        if (PacienteAtual != null)
        {
            await FlushAutoSaveAsync();
        }

        PacienteAtual = paciente;

        _suspendAutoSave = true;
        _autoSaveVersion = 0;

        try
        {
            // ✅ CARREGAR TERAPIA ATUAL e dividir em 3 campos (se existir)
            if (!string.IsNullOrWhiteSpace(paciente.TerapiaAtual))
            {
                var partes = paciente.TerapiaAtual.Split(new[] { "\n\n" }, StringSplitOptions.None);
                Medicacao = partes.Length > 0 ? partes[0].Replace("Medicação: ", "") : string.Empty;
                Suplementacao = partes.Length > 1 ? partes[1].Replace("Suplementação: ", "") : string.Empty;
                Terapias = partes.Length > 2 ? partes[2].Replace("Terapias: ", "") : string.Empty;
            }
            else
            {
                Medicacao = string.Empty;
                Suplementacao = string.Empty;
                Terapias = string.Empty;
            }
        }
        finally
        {
            _suspendAutoSave = false;
        }

        await CarregarSessoesAsync(paciente.Id);
    }

    private void CancelPendingAutoSave()
    {
        try
        {
            _autoSaveCancellation?.Cancel();
        }
        catch (ObjectDisposedException)
        {
            // Já foi descartado
        }
    }

    private void DisposeAutoSaveCancellation()
    {
        if (_autoSaveCancellation != null)
        {
            _autoSaveCancellation.Dispose();
            _autoSaveCancellation = null;
        }

        _pendingAutoSaveTask = Task.CompletedTask;
    }

    private async Task CarregarSessoesAsync(int id)
    {
        IsLoading = true;

        try
        {
            _logger.LogInformation("📋 Carregando sessões do paciente ID {PacienteId}", id);

            // ✅ CARREGAR DA BD REAL (não mais mock)
            var sessoesDb = await _unitOfWork.Sessoes.GetByPacienteIdAsync(id);
            Sessoes = new ObservableCollection<Sessao>(sessoesDb);

            _logger.LogInformation("✅ {Count} sessões carregadas", Sessoes.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar sessões");
            ErrorMessage = "Erro ao carregar histórico de consultas";
        }
        finally
        {
            IsLoading = false;
        }
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            CancelPendingAutoSave();

            DisposeAutoSaveCancellation();
            _autoSaveSemaphore.Dispose();
        }

        _disposed = true;
    }
}

public partial class SuplementoItem : ObservableObject
{
    [ObservableProperty] private string _suplemento = string.Empty;
    [ObservableProperty] private string _dosagem = string.Empty;         // ✅ NOVO
    [ObservableProperty] private string _formaTomar = string.Empty;
    [ObservableProperty] private string _observacoes = string.Empty;     // ✅ NOVO
}

public class ConsultaValidator : AbstractValidator<RegistoConsultasViewModel>
{
    public ConsultaValidator()
    {
        RuleFor(x => x.Notas).NotEmpty().WithMessage("Campo Notas obrigatório").MaximumLength(3000);
        // Terapia atual não é obrigatória, mas se preenchida deve ter limite
        When(x => !string.IsNullOrWhiteSpace(x.Medicacao), () =>
        {
            RuleFor(x => x.Medicacao).MaximumLength(1000);
        });
        When(x => !string.IsNullOrWhiteSpace(x.Suplementacao), () =>
        {
            RuleFor(x => x.Suplementacao).MaximumLength(1000);
        });
        When(x => !string.IsNullOrWhiteSpace(x.Terapias), () =>
        {
            RuleFor(x => x.Terapias).MaximumLength(1000);
        });
    }
}
