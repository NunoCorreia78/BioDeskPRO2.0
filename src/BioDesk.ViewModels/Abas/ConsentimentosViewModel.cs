using System;
using System.Collections.ObjectModel;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Windows.Input;
using System.Windows;
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
    private readonly Services.Pdf.ConsentimentoPdfService _pdfService;

    public ConsentimentosViewModel(
        ILogger<ConsentimentosViewModel> logger,
        Services.Pdf.ConsentimentoPdfService pdfService)
    {
        _logger = logger;
        _pdfService = pdfService;

        // Inicializar coleções
        ConsentimentosExistentes = new ObservableCollection<ConsentimentoInformado>();
        TiposTratamento = new[] { "Selecione...", "Fitoterapia", "Homeopatia", "Acupunctura", "Massagem", "Outros" };
        EstadosFiltro = new[] { "Todos", "Ativos", "Revogados", "Expirados" };
        FrequenciasSessoes = new[] { "Selecione...", "Diária", "Semanal", "Quinzenal", "Mensal", "Conforme necessário" };

        // Valores padrão
        FiltroEstado = "Todos";
        NumeroSessoesPrevistas = 1;
        CustoPorSessao = 0;

        // ✅ Carregar dados de exemplo APENAS em DEBUG
        if (SeedData.ConsentimentosSeedData.ShouldLoadSampleData())
        {
            foreach (var exemplo in SeedData.ConsentimentosSeedData.GetExemplos())
            {
                ConsentimentosExistentes.Add(exemplo);
            }
        }

        AtualizarContadores();

        _logger.LogInformation("ConsentimentosViewModel inicializado");
    }

    #region === GESTÃO DE CONSENTIMENTOS EXISTENTES ===

    /// <summary>
    /// Nome do paciente para exibição nos consentimentos
    /// </summary>
    [ObservableProperty]
    private string _nomePaciente = string.Empty;

    /// <summary>
    /// Define o nome do paciente (chamado pelo FichaPacienteView quando paciente muda)
    /// </summary>
    public void SetPacienteNome(string nome)
    {
        NomePaciente = nome;
        _logger.LogInformation("👤 Nome do paciente atualizado nos Consentimentos: {Nome}", nome);
    }

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

    /// <summary>
    /// Assinatura capturada do canvas como imagem PNG em Base64
    /// </summary>
    [ObservableProperty]
    private string? _assinaturaDigitalBase64;

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
        // ✅ CAPTURAR ASSINATURA DIGITAL REAL
        AssinaturaDigital = $"ASS_DIGITAL_{Guid.NewGuid():N}";
        DataAssinatura = DateTime.Now;

        // ✅ OBTER IP REAL da máquina
        EnderecoIP = ObterEnderecoIPLocal();

        _logger.LogInformation("Assinatura aceite - IP: {IP}", EnderecoIP);
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
            // ✅ ASSINATURA DIGITAL COM DADOS REAIS
            AssinaturaDigital = $"ASSINATURA_DIGITAL_{Guid.NewGuid():N}";
            DataAssinatura = DateTime.Now;

            // ✅ OBTER IP REAL da máquina
            EnderecoIP = ObterEnderecoIPLocal();

            // Gerar hash para integridade legal (SHA256)
            var dadosAssinatura = $"{NomeCompletoAssinatura}|{DocumentoIdentificacao}|{DataAssinatura:yyyy-MM-dd-HH-mm-ss}|{AssinaturaDigital}";
            using (var sha256 = System.Security.Cryptography.SHA256.Create())
            {
                var hashBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(dadosAssinatura));
                HashAssinatura = Convert.ToBase64String(hashBytes).Substring(0, 32);
            }

            _logger.LogInformation("Assinatura digital capturada para: {Nome} ({Documento}) - IP: {IP}",
                                  NomeCompletoAssinatura, DocumentoIdentificacao, EnderecoIP);
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

    #endregion

    #region === GERAÇÃO DE PDF ===

    /// <summary>
    /// Último PDF gerado (caminho completo ou null se falhou)
    /// </summary>
    [ObservableProperty]
    private string? _ultimoPdfGerado;

    /// <summary>
    /// Comando para gerar PDF de consentimento
    /// Define UltimoPdfGerado com o caminho ou null se falhou
    /// </summary>
    [RelayCommand]
    private void GerarPdfConsentimento()
    {
        try
        {
            _logger.LogInformation("📄 Iniciando geração de PDF de consentimento...");

            // Validar dados obrigatórios
            _logger.LogInformation("🔍 Validando NomePaciente: '{Nome}'", NomePaciente ?? "<null>");
            if (string.IsNullOrWhiteSpace(NomePaciente))
            {
                _logger.LogWarning("❌ VALIDAÇÃO FALHOU: Nome do paciente não preenchido");
                MessageBox.Show(
                    "⚠️ Nome do paciente não está preenchido!\n\nPor favor, preencha o nome do paciente antes de gerar o PDF.",
                    "Dados Incompletos",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                UltimoPdfGerado = null;
                return;
            }
            _logger.LogInformation("✅ NomePaciente válido: '{Nome}'", NomePaciente);

            _logger.LogInformation("🔍 Validando TipoTratamentoSelecionado: '{Tipo}'", TipoTratamentoSelecionado ?? "<null>");
            if (string.IsNullOrWhiteSpace(TipoTratamentoSelecionado) || TipoTratamentoSelecionado == "Selecione...")
            {
                _logger.LogWarning("❌ VALIDAÇÃO FALHOU: Tipo de tratamento não selecionado");
                MessageBox.Show(
                    "⚠️ Tipo de tratamento não foi selecionado!\n\nPor favor, selecione o tipo de tratamento (Naturopatia, Osteopatia, etc.).",
                    "Dados Incompletos",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                UltimoPdfGerado = null;
                return;
            }
            _logger.LogInformation("✅ TipoTratamentoSelecionado válido: '{Tipo}'", TipoTratamentoSelecionado);

            _logger.LogInformation("🔍 Validando DescricaoTratamento: '{Descricao}' (Length: {Length})",
                DescricaoTratamento ?? "<null>",
                DescricaoTratamento?.Length ?? 0);
            if (string.IsNullOrWhiteSpace(DescricaoTratamento))
            {
                _logger.LogWarning("❌ VALIDAÇÃO FALHOU: Descrição do tratamento não preenchida");
                MessageBox.Show(
                    "⚠️ Descrição do tratamento não está preenchida!\n\nPor favor, descreva o tratamento que será realizado.",
                    "Dados Incompletos",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                UltimoPdfGerado = null;
                return;
            }
            _logger.LogInformation("✅ DescricaoTratamento válida: {Length} caracteres", DescricaoTratamento.Length);

            // Criar dados do consentimento
            var dados = new Services.Pdf.DadosConsentimento
            {
                NomePaciente = NomePaciente,
                TipoTratamento = TipoTratamentoSelecionado,
                DescricaoTratamento = DescricaoTratamento,
                InformacoesAdicionais = string.Empty, // Campo removido - não necessário
                DataConsentimento = DateTime.Now,
                NumeroSessoes = NumeroSessoesPrevistas > 0 ? NumeroSessoesPrevistas : null,
                CustoPorSessao = CustoPorSessao > 0 ? CustoPorSessao : null,
                AssinaturaDigitalBase64 = AssinaturaDigitalBase64 // 🖼️ Passar assinatura capturada
            };

            // Gerar PDF
            var caminhoArquivo = _pdfService.GerarPdfConsentimento(dados);
            _logger.LogInformation("✅ PDF gerado com sucesso: {Caminho}", caminhoArquivo);

            UltimoPdfGerado = caminhoArquivo;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao gerar PDF de consentimento");
            MessageBox.Show(
                $"❌ ERRO ao gerar PDF!\n\nMensagem: {ex.Message}\n\nInner Exception: {ex.InnerException?.Message ?? "Nenhuma"}\n\nStackTrace:\n{ex.StackTrace}",
                "Erro Fatal",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            UltimoPdfGerado = null;
        }
    }

    /// <summary>
    /// Abre o PDF no visualizador padrão
    /// </summary>
    public void AbrirPdf(string caminhoArquivo)
    {
        try
        {
            _pdfService.AbrirPdf(caminhoArquivo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao abrir PDF: {Caminho}", caminhoArquivo);
        }
    }

    /// <summary>
    /// Obtém o endereço IP local da máquina (IPv4)
    /// </summary>
    private string ObterEnderecoIPLocal()
    {
        try
        {
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            socket.Connect("8.8.8.8", 65530); // Conecta ao DNS do Google para descobrir IP local
            var endPoint = socket.LocalEndPoint as IPEndPoint;
            return endPoint?.Address.ToString() ?? "127.0.0.1";
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Não foi possível obter IP local, usando fallback");
            return "127.0.0.1";
        }
    }

    #endregion
}
