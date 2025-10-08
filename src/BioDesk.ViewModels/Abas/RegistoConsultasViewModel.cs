using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
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

public partial class RegistoConsultasViewModel : ViewModelBase
{
    private readonly ILogger<RegistoConsultasViewModel> _logger;
    private readonly IUnitOfWork _unitOfWork;
    private readonly PrescricaoPdfService _pdfService;
    private readonly IDocumentoService _documentoService;

    [ObservableProperty] private Paciente? _pacienteAtual;
    [ObservableProperty] private ObservableCollection<Sessao> _sessoes = new();
    [ObservableProperty] private string _avaliacao = string.Empty;
    [ObservableProperty] private string _planoTerapeutico = string.Empty;
    [ObservableProperty] private string _terapiaAtual = string.Empty; // ✅ NOVO: Medicação/Suplementação/Terapia atual
    [ObservableProperty] private bool _mostrarPrescricao = false; // ✅ CORRIGIDO: Começa fechado
    [ObservableProperty] private ObservableCollection<SuplementoItem> _suplementos = new();
    [ObservableProperty] private string _observacoesPrescricao = string.Empty;
    [ObservableProperty] private DateTime _dataConsulta = DateTime.Now; // ✅ CORRIGIDO: Agora tem setter para TwoWay binding

    // ✅ NOVO: Modal de Detalhes da Consulta
    [ObservableProperty] private Sessao? _consultaSelecionada;
    [ObservableProperty] private bool _mostrarDetalhes = false;

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

            var validator = new ConsultaValidator();
            var result = await validator.ValidateAsync(this);
            if (!result.IsValid)
            {
                ErrorMessage = string.Join("\n", result.Errors.Select(e => e.ErrorMessage));
                return;
            }

            _logger.LogInformation("💾 Salvando consulta na BD para paciente ID {PacienteId}", PacienteAtual.Id);

            // ✅ ATUALIZAR TERAPIA ATUAL DO PACIENTE (sempre que guardar consulta)
            if (PacienteAtual.TerapiaAtual != TerapiaAtual)
            {
                PacienteAtual.TerapiaAtual = TerapiaAtual;
                _unitOfWork.Pacientes.Update(PacienteAtual);
                _logger.LogInformation("💊 Terapia Atual atualizada no paciente");
            }

            // ✅ CRIAR NOVA SESSÃO E SALVAR NA BD
            var novaSessao = new Sessao
            {
                PacienteId = PacienteAtual.Id,
                DataHora = DataConsulta,
                Motivo = Avaliacao.Length > 50 ? Avaliacao.Substring(0, 50) : Avaliacao,
                Avaliacao = Avaliacao,
                Plano = PlanoTerapeutico,
                CriadoEm = DateTime.Now,
                IsDeleted = false
            };

            await _unitOfWork.Sessoes.AddAsync(novaSessao);
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("✅ Consulta ID {Id} salva com sucesso!", novaSessao.Id);

            SuccessMessage = "✅ Consulta guardada na base de dados!";

            // Limpar formulário
            Avaliacao = string.Empty;
            PlanoTerapeutico = string.Empty;
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

    public void SetPaciente(Paciente paciente)
    {
        PacienteAtual = paciente;
        TerapiaAtual = paciente.TerapiaAtual ?? string.Empty; // ✅ NOVO: Carregar terapia atual do paciente
        _ = CarregarSessoesAsync(paciente.Id);
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
        RuleFor(x => x.Avaliacao).NotEmpty().WithMessage("Avaliação obrigatória").MaximumLength(2000);
        RuleFor(x => x.PlanoTerapeutico).NotEmpty().WithMessage("Plano obrigatório").MaximumLength(3000);
    }
}
