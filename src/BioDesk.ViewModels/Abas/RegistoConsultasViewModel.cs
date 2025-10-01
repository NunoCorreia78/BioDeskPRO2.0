using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pdf;
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

    [ObservableProperty] private Paciente? _pacienteAtual;
    [ObservableProperty] private ObservableCollection<Sessao> _sessoes = new();
    [ObservableProperty] private string _avaliacao = string.Empty;
    [ObservableProperty] private string _planoTerapeutico = string.Empty;
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
        PrescricaoPdfService pdfService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _pdfService = pdfService ?? throw new ArgumentNullException(nameof(pdfService));
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
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (PacienteAtual == null)
            {
                ErrorMessage = "❌ Nenhum paciente selecionado";
                return;
            }

            IsLoading = true;
            _logger.LogInformation("📄 Gerando PDF de prescrição para: {Nome}", PacienteAtual.NomeCompleto);

            var dados = new DadosPrescricao
            {
                NomePaciente = PacienteAtual.NomeCompleto,
                DataPrescricao = DateTime.Now,
                Diagnostico = Avaliacao,
                Itens = Suplementos.Select(s => new ItemPrescricao
                {
                    Nome = s.Suplemento,
                    Dosagem = "",  // SuplementoItem não tem campo Dosagem
                    Frequencia = s.FormaTomar,
                    Observacoes = ""
                }).ToList(),
                InstrucoesGerais = ObservacoesPrescricao,
                DuracaoTratamento = "30 dias" // Pode ser customizado
            };

            // ✅ GERAR PDF REAL usando QuestPDF
            var caminhoArquivo = _pdfService.GerarPdfPrescricao(dados);

            SuccessMessage = $"✅ PDF gerado com sucesso: {System.IO.Path.GetFileName(caminhoArquivo)}";
            _logger.LogInformation("✅ PDF gerado: {Caminho}", caminhoArquivo);

            // Abrir PDF automaticamente
            await Task.Run(() => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = caminhoArquivo,
                UseShellExecute = true
            }));

            IsLoading = false;
        }, "Erro ao gerar PDF de prescrição", _logger);
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
    [ObservableProperty] private string _formaTomar = string.Empty;
}

public class ConsultaValidator : AbstractValidator<RegistoConsultasViewModel>
{
    public ConsultaValidator()
    {
        RuleFor(x => x.Avaliacao).NotEmpty().WithMessage("Avaliação obrigatória").MaximumLength(2000);
        RuleFor(x => x.PlanoTerapeutico).NotEmpty().WithMessage("Plano obrigatório").MaximumLength(3000);
    }
}
