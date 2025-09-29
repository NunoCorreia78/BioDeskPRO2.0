using System;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels.Abas;

/// <summary>
/// ViewModel para Aba 3: Consentimentos Informados
/// Gestão completa de consentimentos para tratamentos
/// </summary>
public partial class ConsentimentosViewModel : ObservableValidator
{
    private readonly ILogger<ConsentimentosViewModel> _logger;

    public ConsentimentosViewModel(ILogger<ConsentimentosViewModel> logger)
    {
        _logger = logger;

        // Inicializar coleções
        ConsentimentosExistentes = new ObservableCollection<ConsentimentoInformado>();
        TiposTratamento = new[] { "Selecione...", "Fitoterapia", "Homeopatia", "Acupunctura", "Massagem", "Outros" };
        EstadosFiltro = new[] { "Todos", "Ativos", "Revogados", "Expirados" };
        FrequenciasSessoes = new[] { "Selecione...", "Diária", "Semanal", "Quinzenal", "Mensal", "Conforme necessário" };

        // Valores padrão
        FiltroEstado = "Todos";
        NumeroSessoesPrevistas = 1;
        CustoPorSessao = 0;

        // Carregar dados de exemplo
        CarregarConsentimentosExemplo();

        AtualizarContadores();

        _logger.LogInformation("ConsentimentosViewModel inicializado");
    }

    #region === GESTÃO DE CONSENTIMENTOS EXISTENTES ===

    public ObservableCollection<ConsentimentoInformado> ConsentimentosExistentes { get; }

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConsentimentosFiltrados))]
    private string _filtroEstado = "Todos";

    public ObservableCollection<ConsentimentoInformado> ConsentimentosFiltrados
    {
        get
        {
            var filtrados = ConsentimentosExistentes.AsEnumerable();

            if (FiltroEstado != "Todos")
            {
                filtrados = FiltroEstado switch
                {
                    "Ativos" => filtrados.Where(c => c.Estado == "Ativo"),
                    "Revogados" => filtrados.Where(c => c.Estado == "Revogado"),
                    "Expirados" => filtrados.Where(c => c.Estado == "Expirado"),
                    _ => filtrados
                };
            }

            return new ObservableCollection<ConsentimentoInformado>(filtrados);
        }
    }

    [ObservableProperty]
    private int _totalConsentimentos;

    [ObservableProperty]
    private int _consentimentosAtivos;

    #endregion

    #region === NOVO CONSENTIMENTO - PASSO 1: SELEÇÃO ===

    [ObservableProperty]
    [Required]
    [NotifyPropertyChangedFor(nameof(MostraDescricaoAutomatica))]
    private string _tipoTratamentoSelecionado = "Selecione...";

    // Método partial para executar automaticamente quando TipoTratamentoSelecionado muda
    partial void OnTipoTratamentoSelecionadoChanged(string value)
    {
        if (value != "Selecione..." && value != "Outros")
        {
            CarregarTemplate();
        }
    }

    [ObservableProperty]
    [Required]
    private string _descricaoTratamento = string.Empty;

    [ObservableProperty]
    private string? _personalizacaoEspecifica;

    public bool MostraDescricaoAutomatica => TipoTratamentoSelecionado != "Selecione..." && TipoTratamentoSelecionado != "Outros";

    #endregion

    #region === NOVO CONSENTIMENTO - PASSO 2: INFORMAÇÃO DETALHADA ===

    [ObservableProperty]
    [Required]
    private string _naturezaProcedimento = string.Empty;

    [ObservableProperty]
    [Required]
    private string _beneficiosEsperados = string.Empty;

    [ObservableProperty]
    [Required]
    private string _riscosEfeitosSecundarios = string.Empty;

    [ObservableProperty]
    [Required]
    private string _alternativasDisponiveis = string.Empty;

    [ObservableProperty]
    [Required]
    private string _contraindicacoes = string.Empty;

    #endregion

    #region === NOVO CONSENTIMENTO - PASSO 2: CONFIRMAÇÃO DE LEITURA MÉDICO-LEGAL ===

    // Propriedades para confirmação de leitura obrigatória
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TodasSecoesConfirmadas))]
    [NotifyPropertyChangedFor(nameof(PodeFinalizarConsentimento))]
    private bool _confirmouNatureza;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TodasSecoesConfirmadas))]
    [NotifyPropertyChangedFor(nameof(PodeFinalizarConsentimento))]
    private bool _confirmouBeneficios;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TodasSecoesConfirmadas))]
    [NotifyPropertyChangedFor(nameof(PodeFinalizarConsentimento))]
    private bool _confirmouRiscos;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TodasSecoesConfirmadas))]
    [NotifyPropertyChangedFor(nameof(PodeFinalizarConsentimento))]
    private bool _confirmouContraindicacoes;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(TodasSecoesConfirmadas))]
    [NotifyPropertyChangedFor(nameof(PodeFinalizarConsentimento))]
    private bool _confirmouAlternativas;

    public bool TodasSecoesConfirmadas => ConfirmouNatureza &&
                                         ConfirmouBeneficios &&
                                         ConfirmouRiscos &&
                                         ConfirmouContraindicacoes &&
                                         ConfirmouAlternativas;

    #endregion

    #region === NOVO CONSENTIMENTO - PASSO 3: ASPETOS PRÁTICOS ===

    [ObservableProperty]
    [Range(1, 100)]
    [NotifyPropertyChangedFor(nameof(CustoTotalEstimado))]
    private int _numeroSessoesPrevistas = 1;

    [ObservableProperty]
    [Required]
    private string _frequenciaSessoes = "Selecione...";

    [ObservableProperty]
    [Range(0, 1000)]
    [NotifyPropertyChangedFor(nameof(CustoTotalEstimado))]
    private decimal _custoPorSessao = 0;

    public decimal CustoTotalEstimado => NumeroSessoesPrevistas * CustoPorSessao;

    [ObservableProperty]
    [Required]
    private string _politicaCancelamento = string.Empty;



    #endregion

    #region === NOVO CONSENTIMENTO - PASSO 4: CONSENTIMENTO INFORMADO FORMAL ===

    // === IDENTIFICAÇÃO DO PACIENTE ===
    [ObservableProperty]
    [Required]
    [NotifyPropertyChangedFor(nameof(PodeAssinarConsentimento))]
    private string _nomeCompletoAssinatura = string.Empty;

    [ObservableProperty]
    [Required]
    [NotifyPropertyChangedFor(nameof(PodeAssinarConsentimento))]
    private string _documentoIdentificacao = string.Empty;

    // === DECLARAÇÕES LEGAIS OBRIGATÓRIAS ===
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PodeAssinarConsentimento))]
    [NotifyPropertyChangedFor(nameof(ConsentimentoValidoLegalmente))]
    private bool _compreendoNatureza;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PodeAssinarConsentimento))]
    [NotifyPropertyChangedFor(nameof(ConsentimentoValidoLegalmente))]
    private bool _fuiInformadoRiscos;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PodeAssinarConsentimento))]
    [NotifyPropertyChangedFor(nameof(ConsentimentoValidoLegalmente))]
    private bool _tiveOportunidadePerguntas;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(PodeAssinarConsentimento))]
    [NotifyPropertyChangedFor(nameof(ConsentimentoValidoLegalmente))]
    private bool _consintoTratamento;

    [ObservableProperty]
    private string? _questoesPreocupacoes;

    // === ASSINATURA DIGITAL COM VALOR LEGAL ===
    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ConsentimentoValidoLegalmente))]
    private string? _assinaturaDigital;

    [ObservableProperty]
    private DateTime? _dataAssinatura;

    [ObservableProperty]
    private string? _enderecoIP;

    [ObservableProperty]
    private string? _hashAssinatura;

    // === PROPRIEDADES CALCULADAS PARA VALIDAÇÃO LEGAL ===
    public bool PodeAssinarConsentimento => !string.IsNullOrWhiteSpace(NomeCompletoAssinatura) &&
                                           !string.IsNullOrWhiteSpace(DocumentoIdentificacao) &&
                                           CompreendoNatureza &&
                                           FuiInformadoRiscos &&
                                           TiveOportunidadePerguntas &&
                                           ConsintoTratamento;

    public bool ConsentimentoValidoLegalmente => PodeAssinarConsentimento &&
                                               !string.IsNullOrWhiteSpace(AssinaturaDigital) &&
                                               DataAssinatura.HasValue;

    public bool PodeFinalizarConsentimento => ConsentimentoValidoLegalmente;

    #endregion

    #region === ARRAYS DE OPÇÕES ===

    public string[] TiposTratamento { get; }
    public string[] EstadosFiltro { get; }
    public string[] FrequenciasSessoes { get; }

    #endregion

    #region === COMMANDS ===

    [RelayCommand]
    private void CarregarTemplate()
    {
        if (TipoTratamentoSelecionado == "Selecione..." || TipoTratamentoSelecionado == "Outros")
            return;

        if (ConsentimentoTemplates.Templates.TryGetValue(TipoTratamentoSelecionado, out var template))
        {
            DescricaoTratamento = template.DescricaoTratamento;
            NaturezaProcedimento = template.NaturezaProcedimento;
            BeneficiosEsperados = template.BeneficiosEsperados;
            RiscosEfeitosSecundarios = template.RiscosEfeitosSecundarios;
            AlternativasDisponiveis = template.AlternativasDisponiveis;
            Contraindicacoes = template.Contraindicacoes;
            FrequenciaSessoes = template.FrequenciaSessoes;
            PoliticaCancelamento = template.PoliticaCancelamento;

            _logger.LogInformation("Template carregado para {TipoTratamento}", TipoTratamentoSelecionado);
        }
    }

    [RelayCommand]
    private void LimparAssinatura()
    {
        AssinaturaDigital = null;
        DataAssinatura = null;
        _logger.LogInformation("Assinatura limpa");
    }

    [RelayCommand]
    private void AceitarAssinatura()
    {
        // TODO: Implementar captura de assinatura digital
        AssinaturaDigital = "BASE64_ASSINATURA_SIMULADA";
        DataAssinatura = DateTime.Now;
        EnderecoIP = "192.168.1.100"; // TODO: Obter IP real

        _logger.LogInformation("Assinatura aceite");
    }

    [RelayCommand]
    private void FinalizarConsentimento()
    {
        if (!PodeFinalizarConsentimento)
        {
            _logger.LogWarning("Tentativa de finalizar consentimento incompleto");
            return;
        }

        var novoConsentimento = new ConsentimentoInformado
        {
            TipoTratamento = TipoTratamentoSelecionado,
            DescricaoTratamento = DescricaoTratamento,
            PersonalizacaoEspecifica = PersonalizacaoEspecifica,
            NaturezaProcedimento = NaturezaProcedimento,
            BeneficiosEsperados = BeneficiosEsperados,
            RiscosEfeitosSecundarios = RiscosEfeitosSecundarios,
            AlternativasDisponiveis = AlternativasDisponiveis,
            Contraindicacoes = Contraindicacoes,
            NumeroSessoesPrevistas = NumeroSessoesPrevistas,
            FrequenciaSessoes = FrequenciaSessoes,
            CustoPorSessao = CustoPorSessao,
            CustoTotalEstimado = CustoTotalEstimado,
            PoliticaCancelamento = PoliticaCancelamento,
            CompreendoNatureza = CompreendoNatureza,
            FuiInformadoRiscos = FuiInformadoRiscos,
            TiveOportunidadePerguntas = TiveOportunidadePerguntas,
            ConsintoTratamento = ConsintoTratamento,
            QuestoesPreocupacoes = QuestoesPreocupacoes,
            AssinaturaDigital = AssinaturaDigital,
            DataAssinatura = DataAssinatura,
            EnderecoIP = EnderecoIP,
            DataCriacao = DateTime.Now,
            Estado = "Ativo"
        };

        ConsentimentosExistentes.Insert(0, novoConsentimento);
        AtualizarContadores();

        _logger.LogInformation("Consentimento finalizado para {TipoTratamento}", TipoTratamentoSelecionado);
    }

    [RelayCommand]
    private void AssinarDigitalmente()
    {
        try
        {
            // Simular captura de assinatura digital com dados legais
            AssinaturaDigital = $"ASSINATURA_DIGITAL_{Guid.NewGuid():N}";
            DataAssinatura = DateTime.Now;
            EnderecoIP = "192.168.1.100"; // Em produção seria obtido dinamicamente

            // Gerar hash para integridade legal
            var dadosAssinatura = $"{NomeCompletoAssinatura}|{DocumentoIdentificacao}|{DataAssinatura:yyyy-MM-dd-HH-mm-ss}|{AssinaturaDigital}";
            HashAssinatura = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(dadosAssinatura))
                                   .Substring(0, 16) + "..."; // Hash simplificado para demonstração

            _logger.LogInformation("Assinatura digital capturada para: {Nome} ({Documento})",
                                  NomeCompletoAssinatura, DocumentoIdentificacao);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao capturar assinatura digital");
        }
    }

    [RelayCommand]
    private void RevogarConsentimento(ConsentimentoInformado? consentimento)
    {
        if (consentimento != null && consentimento.Estado == "Ativo")
        {
            consentimento.Estado = "Revogado";
            consentimento.DataRevogacao = DateTime.Now;
            consentimento.MotivoRevogacao = "Revogado pelo paciente";

            AtualizarContadores();
            OnPropertyChanged(nameof(ConsentimentosFiltrados));

            _logger.LogInformation("Consentimento revogado: {TipoTratamento}", consentimento.TipoTratamento);
        }
    }

    #endregion

    #region === MÉTODOS AUXILIARES ===

    private void LimparFormularioNovoConsentimento()
    {
        TipoTratamentoSelecionado = "Selecione...";
        DescricaoTratamento = string.Empty;
        PersonalizacaoEspecifica = null;
        NaturezaProcedimento = string.Empty;
        BeneficiosEsperados = string.Empty;
        RiscosEfeitosSecundarios = string.Empty;
        AlternativasDisponiveis = string.Empty;
        Contraindicacoes = string.Empty;
        NumeroSessoesPrevistas = 1;
        FrequenciaSessoes = "Selecione...";
        CustoPorSessao = 0;
        PoliticaCancelamento = string.Empty;
        CompreendoNatureza = false;
        FuiInformadoRiscos = false;
        TiveOportunidadePerguntas = false;
        ConsintoTratamento = false;
        QuestoesPreocupacoes = null;
        AssinaturaDigital = null;
        DataAssinatura = null;
        EnderecoIP = null;
    }

    private void AtualizarContadores()
    {
        TotalConsentimentos = ConsentimentosExistentes.Count;
        ConsentimentosAtivos = ConsentimentosExistentes.Count(c => c.Estado == "Ativo");
    }

    private void CarregarConsentimentosExemplo()
    {
        ConsentimentosExistentes.Add(new ConsentimentoInformado
        {
            Id = 1,
            TipoTratamento = "Fitoterapia",
            DescricaoTratamento = "Tratamento com plantas medicinais para ansiedade",
            DataCriacao = DateTime.Now.AddDays(-30),
            Estado = "Ativo",
            NumeroSessoesPrevistas = 10,
            CustoPorSessao = 45,
            CustoTotalEstimado = 450
        });

        ConsentimentosExistentes.Add(new ConsentimentoInformado
        {
            Id = 2,
            TipoTratamento = "Acupunctura",
            DescricaoTratamento = "Tratamento para dores lombares",
            DataCriacao = DateTime.Now.AddDays(-15),
            Estado = "Ativo",
            NumeroSessoesPrevistas = 8,
            CustoPorSessao = 50,
            CustoTotalEstimado = 400
        });

        ConsentimentosExistentes.Add(new ConsentimentoInformado
        {
            Id = 3,
            TipoTratamento = "Massagem",
            DescricaoTratamento = "Massagem relaxante mensal",
            DataCriacao = DateTime.Now.AddDays(-60),
            Estado = "Revogado",
            DataRevogacao = DateTime.Now.AddDays(-10),
            MotivoRevogacao = "Mudança de terapeuta",
            NumeroSessoesPrevistas = 12,
            CustoPorSessao = 40,
            CustoTotalEstimado = 480
        });
    }

    #endregion
}
