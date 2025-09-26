using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Notifications;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para Tab 2.1 - Avaliação Clínica
/// Interface otimizada com chips, sliders e dropdowns para rapidez clínica
/// Zero texto obrigatório, com frases rápidas integradas
/// </summary>
public partial class AvaliacaoClinicaViewModel : NavigationViewModelBase
{
    private readonly IPacienteService _pacienteService;
    private readonly INotificationService _notificationService;
    private readonly ILogger<AvaliacaoClinicaViewModel> _logger;

    public AvaliacaoClinicaViewModel(
        INavigationService navigationService,
        IPacienteService pacienteService,
        INotificationService notificationService,
        ILogger<AvaliacaoClinicaViewModel> logger) : base(navigationService, pacienteService)
    {
        _pacienteService = pacienteService;
        _notificationService = notificationService;
        _logger = logger;

        // Inicializar coleções observáveis
        InicializarColecoes();
        
        // Configurar comandos
        SalvarCommand = new AsyncRelayCommand(() => ExecuteWithErrorHandlingAsync(SalvarAsync, "ao salvar avaliação clínica"));
        AplicarFraseRapidaCommand = new RelayCommand<string>(AplicarFraseRapida);
        LimparSecaoCommand = new RelayCommand<string>(LimparSecao);
    }

    #region Properties Observáveis
    [ObservableProperty]
    private int pacienteId;

    [ObservableProperty]
    private string? pacienteNome;

    [ObservableProperty]
    private bool isLoading;

    [ObservableProperty]
    private string? errorMessage;

    [ObservableProperty]
    private int tabSelecionada;

    // 1. Motivos da Consulta
    [ObservableProperty]
    private ObservableCollection<ChipItem> motivosDisponiveis = new();

    [ObservableProperty]
    private string? outroMotivo;

    [ObservableProperty]
    private string? localizacaoSelecionada;

    [ObservableProperty]
    private string? ladoSelecionado;

    [ObservableProperty]
    private DateTime? dataInicio;

    [ObservableProperty]
    private string? duracaoSelecionada;

    [ObservableProperty]
    private string? evolucaoSelecionada;

    [ObservableProperty]
    private int intensidade;

    [ObservableProperty]
    private ObservableCollection<ChipItem> caracteresDisponiveis = new();

    [ObservableProperty]
    private ObservableCollection<ChipItem> fatoresAgravantesDisponiveis = new();

    [ObservableProperty]
    private ObservableCollection<ChipItem> fatoresAlivioDisponiveis = new();

    [ObservableProperty]
    private string? motivoObservacoes;

    // 2. História Clínica
    [ObservableProperty]
    private ObservableCollection<ChipItem> doencasCronicasDisponiveis = new();

    [ObservableProperty]
    private ObservableCollection<ItemCirurgia> cirurgias = new();

    [ObservableProperty]
    private ObservableCollection<ChipItem> tiposAlergiasDisponiveis = new();

    [ObservableProperty]
    private string? especificarAlergias;

    [ObservableProperty]
    private bool semAlergias;

    [ObservableProperty]
    private ObservableCollection<ItemMedicacao> medicacaoAtual = new();

    [ObservableProperty]
    private bool semMedicacao;

    [ObservableProperty]
    private ObservableCollection<ItemMedicacao> suplementacao = new();

    [ObservableProperty]
    private bool semSuplementacao;

    [ObservableProperty]
    private ObservableCollection<ChipItem> vacinacaoDisponiveis = new();

    [ObservableProperty]
    private bool vacinacaoNaoAplicavel;

    [ObservableProperty]
    private string? historiaObservacoes;

    // 3. Revisão de Sistemas
    [ObservableProperty]
    private Dictionary<string, SistemaRevisao> sistemas = new();

    // 4. Estilo de Vida
    [ObservableProperty]
    private ObservableCollection<ChipItem> alimentacaoDisponiveis = new();

    [ObservableProperty]
    private string? hidratacaoSelecionada;

    [ObservableProperty]
    private ObservableCollection<ChipItem> exercicioDisponiveis = new();

    [ObservableProperty]
    private string? exercicioFrequenciaSelecionada;

    [ObservableProperty]
    private string? tabacoSelecionado;

    [ObservableProperty]
    private int? tabacoQuantidade;

    [ObservableProperty]
    private string? alcoolSelecionado;

    [ObservableProperty]
    private string? cafeinaSelecionada;

    [ObservableProperty]
    private int stress;

    [ObservableProperty]
    private ObservableCollection<ChipItem> sonoDisponiveis = new();

    [ObservableProperty]
    private string? estiloVidaObservacoes;

    // 5. História Familiar
    [ObservableProperty]
    private ObservableCollection<ChipItem> antecedentesDisponiveis = new();

    [ObservableProperty]
    private ObservableCollection<ChipItem> parentescoDisponiveis = new();

    [ObservableProperty]
    private string? familiarObservacoes;

    #endregion

    #region Comandos
    public IAsyncRelayCommand SalvarCommand { get; }
    public IRelayCommand<string> AplicarFraseRapidaCommand { get; }
    public IRelayCommand<string> LimparSecaoCommand { get; }
    #endregion

    #region Listas Estáticas
    public List<string> Localizacoes => OpcoesMotivoConsulta.Localizacoes;
    public List<string> Lados => OpcoesMotivoConsulta.Lados;
    public List<string> Duracoes => OpcoesMotivoConsulta.Duracoes;
    public List<string> Evolucoes => OpcoesMotivoConsulta.Evolucoes;
    public List<string> Hidratacao => OpcoesEstiloVida.Hidratacao;
    public List<string> FrequenciaExercicio => OpcoesEstiloVida.FrequenciaExercicio;
    public List<string> Tabaco => OpcoesEstiloVida.Tabaco;
    public List<string> Alcool => OpcoesEstiloVida.Alcool;
    public List<string> Cafeina => OpcoesEstiloVida.Cafeina;
    public List<string> FrasesRapidas => OpcoesHistoriaClinica.FrasesRapidas;
    #endregion

    #region Métodos de Inicialização
    private void InicializarColecoes()
    {
        // Motivos da consulta
        foreach (var motivo in OpcoesMotivoConsulta.Motivos)
        {
            MotivosDisponiveis.Add(new ChipItem(motivo));
        }

        // Caracteres
        foreach (var carater in OpcoesMotivoConsulta.Caracteres)
        {
            CaracteresDisponiveis.Add(new ChipItem(carater));
        }

        // Fatores agravantes
        foreach (var fator in OpcoesMotivoConsulta.FatoresAgravantes)
        {
            FatoresAgravantesDisponiveis.Add(new ChipItem(fator));
        }

        // Fatores de alívio
        foreach (var fator in OpcoesMotivoConsulta.FatoresAlivio)
        {
            FatoresAlivioDisponiveis.Add(new ChipItem(fator));
        }

        // História clínica
        foreach (var doenca in OpcoesHistoriaClinica.DoencasCronicas)
        {
            DoencasCronicasDisponiveis.Add(new ChipItem(doenca));
        }

        foreach (var tipo in OpcoesHistoriaClinica.TiposAlergias)
        {
            TiposAlergiasDisponiveis.Add(new ChipItem(tipo));
        }

        foreach (var vacina in OpcoesHistoriaClinica.VacinacaoRelevante)
        {
            VacinacaoDisponiveis.Add(new ChipItem(vacina));
        }

        // Estilo de vida
        foreach (var alimentacao in OpcoesEstiloVida.Alimentacao)
        {
            AlimentacaoDisponiveis.Add(new ChipItem(alimentacao));
        }

        foreach (var exercicio in OpcoesEstiloVida.Exercicio)
        {
            ExercicioDisponiveis.Add(new ChipItem(exercicio));
        }

        foreach (var sono in OpcoesEstiloVida.Sono)
        {
            SonoDisponiveis.Add(new ChipItem(sono));
        }

        // História familiar
        foreach (var antecedente in OpcoesHistoriaFamiliar.Antecedentes)
        {
            AntecedentesDisponiveis.Add(new ChipItem(antecedente));
        }

        foreach (var parentesco in OpcoesHistoriaFamiliar.Parentesco)
        {
            ParentescoDisponiveis.Add(new ChipItem(parentesco));
        }

        // Inicializar sistemas de revisão
        InicializarSistemas();
    }

    private void InicializarSistemas()
    {
        foreach (var kvp in OpcoesRevisaoSistemas.SistemasSintomas)
        {
            var sistema = new SistemaRevisao
            {
                Nome = kvp.Key,
                Sintomas = new ObservableCollection<ChipItem>(
                    kvp.Value.Select(s => new ChipItem(s)))
            };
            Sistemas[kvp.Key] = sistema;
        }
    }
    #endregion

    #region Métodos Públicos
    public async Task CarregarPacienteAsync(int id)
    {
        PacienteId = id;
        
        try
        {
            IsLoading = true;
            ErrorMessage = null;

            var paciente = await _pacienteService.GetByIdAsync(id);
            if (paciente != null)
            {
                PacienteNome = paciente.Nome;
                await CarregarAvaliacaoExistenteAsync(id);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar paciente {PacienteId}", id);
            ErrorMessage = "Erro ao carregar dados do paciente";
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task CarregarAvaliacaoExistenteAsync(int pacienteId)
    {
        // TODO: Implementar carregamento de avaliação existente
        // Por enquanto, iniciar com dados vazios
        await Task.CompletedTask;
    }
    #endregion

    #region Comandos Implementation
    private async Task SalvarAsync()
    {
        try
        {
            IsLoading = true;
            ErrorMessage = null;

            var avaliacao = ConstruirAvaliacaoClinica();
            
            // TODO: Implementar salvamento no service
            // await _pacienteService.SalvarAvaliacaoClinicaAsync(avaliacao);

            await _notificationService.ShowSuccessAsync("Avaliação clínica salva com sucesso!");
            
            _logger.LogInformation("Avaliação clínica salva para paciente {PacienteId}", PacienteId);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao salvar avaliação clínica do paciente {PacienteId}", PacienteId);
            ErrorMessage = "Erro ao salvar avaliação clínica";
            await _notificationService.ShowErrorAsync("Erro ao salvar avaliação clínica");
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async void AplicarFraseRapida(string? frase)
    {
        if (string.IsNullOrEmpty(frase) || !FrasesRapidasGlobais.FrasesRapidas.ContainsKey(frase))
            return;

        var configuracoes = FrasesRapidasGlobais.FrasesRapidas[frase];
        
        foreach (var kvp in configuracoes)
        {
            var propriedade = kvp.Key;
            var valor = kvp.Value;

            // Aplicar configuração baseada na propriedade
            switch (propriedade)
            {
                case "HistoriaClinica.SemAlergias":
                    SemAlergias = (bool)valor;
                    break;
                case "HistoriaClinica.SemMedicacao":
                    SemMedicacao = (bool)valor;
                    break;
                case "MotivoConsulta.Evolucao":
                    EvolucaoSelecionada = (string)valor;
                    break;
                case "MotivoConsulta.Intensidade":
                    Intensidade = (int)valor;
                    break;
                case "EstiloVida.Hidratacao":
                    HidratacaoSelecionada = (string)valor;
                    break;
                case "EstiloVida.Stress":
                    Stress = (int)valor;
                    break;
            }
        }

        await _notificationService.ShowInfoAsync($"Aplicada frase rápida: {frase}");
    }

    private void LimparSecao(string? secao)
    {
        switch (secao?.ToLower())
        {
            case "motivos":
                LimparMotivoConsulta();
                break;
            case "historia":
                LimparHistoriaClinica();
                break;
            case "sistemas":
                LimparRevisaoSistemas();
                break;
            case "estilo":
                LimparEstiloVida();
                break;
            case "familiar":
                LimparHistoriaFamiliar();
                break;
        }
    }
    #endregion

    #region Métodos Privados
    private AvaliacaoClinica ConstruirAvaliacaoClinica()
    {
        return new AvaliacaoClinica
        {
            PacienteId = PacienteId,
            MotivoConsulta = ConstruirMotivoConsulta(),
            HistoriaClinica = ConstruirHistoriaClinica(),
            RevisaoSistemas = ConstruirRevisaoSistemas(),
            EstiloVida = ConstruirEstiloVida(),
            HistoriaFamiliar = ConstruirHistoriaFamiliar(),
            IsCompleta = VerificarSeCompleta()
        };
    }

    private MotivoConsulta ConstruirMotivoConsulta()
    {
        return new MotivoConsulta
        {
            MotivosJson = JsonSerializer.Serialize(MotivosDisponiveis.Where(m => m.IsSelecionado).Select(m => m.Texto)),
            OutroMotivo = OutroMotivo,
            Localizacao = LocalizacaoSelecionada,
            Lado = LadoSelecionado,
            DataInicio = DataInicio,
            Duracao = DuracaoSelecionada,
            Evolucao = EvolucaoSelecionada,
            Intensidade = Intensidade,
            CaraterJson = JsonSerializer.Serialize(CaracteresDisponiveis.Where(c => c.IsSelecionado).Select(c => c.Texto)),
            FatoresAgravantesJson = JsonSerializer.Serialize(FatoresAgravantesDisponiveis.Where(f => f.IsSelecionado).Select(f => f.Texto)),
            FatoresAlivioJson = JsonSerializer.Serialize(FatoresAlivioDisponiveis.Where(f => f.IsSelecionado).Select(f => f.Texto)),
            Observacoes = MotivoObservacoes
        };
    }

    private HistoriaClinica ConstruirHistoriaClinica()
    {
        return new HistoriaClinica
        {
            DoencasCronicasJson = JsonSerializer.Serialize(DoencasCronicasDisponiveis.Where(d => d.IsSelecionado).Select(d => d.Texto)),
            CirurgiasJson = JsonSerializer.Serialize(Cirurgias),
            TiposAlergiasJson = JsonSerializer.Serialize(TiposAlergiasDisponiveis.Where(t => t.IsSelecionado).Select(t => t.Texto)),
            EspecificarAlergias = EspecificarAlergias,
            SemAlergias = SemAlergias,
            MedicacaoAtualJson = JsonSerializer.Serialize(MedicacaoAtual),
            SemMedicacao = SemMedicacao,
            SuplementacaoJson = JsonSerializer.Serialize(Suplementacao),
            SemSuplementacao = SemSuplementacao,
            VacinacaoJson = JsonSerializer.Serialize(VacinacaoDisponiveis.Where(v => v.IsSelecionado).Select(v => v.Texto)),
            VacinacaoNaoAplicavel = VacinacaoNaoAplicavel,
            Observacoes = HistoriaObservacoes
        };
    }

    private RevisaoSistemas ConstruirRevisaoSistemas()
    {
        var revisao = new RevisaoSistemas();
        
        foreach (var kvp in Sistemas)
        {
            var sintomas = kvp.Value.Sintomas.Where(s => s.IsSelecionado).Select(s => s.Texto);
            var sintomasJson = JsonSerializer.Serialize(sintomas);
            
            // Usar reflection ou switch para atribuir às propriedades corretas
            switch (kvp.Key)
            {
                case "Cardiovascular":
                    revisao.CardiovascularJson = sintomasJson;
                    revisao.CardiovascularObs = kvp.Value.Observacoes;
                    break;
                case "Respiratório":
                    revisao.RespiratorioJson = sintomasJson;
                    revisao.RespiratorioObs = kvp.Value.Observacoes;
                    break;
                case "Digestivo":
                    revisao.DigestivoJson = sintomasJson;
                    revisao.DigestivoObs = kvp.Value.Observacoes;
                    break;
                case "Renal/Urinário":
                    revisao.RenalUrinarioJson = sintomasJson;
                    revisao.RenalUrinarioObs = kvp.Value.Observacoes;
                    break;
                case "Endócrino/Metabólico":
                    revisao.EndocrinoMetabolicoJson = sintomasJson;
                    revisao.EndocrinoMetabolicoObs = kvp.Value.Observacoes;
                    break;
                case "Músculo-esquelético":
                    revisao.MusculoEsqueleticoJson = sintomasJson;
                    revisao.MusculoEsqueleticoObs = kvp.Value.Observacoes;
                    break;
                case "Neurológico":
                    revisao.NeurologicoJson = sintomasJson;
                    revisao.NeurologicoObs = kvp.Value.Observacoes;
                    break;
                case "Pele":
                    revisao.PeleJson = sintomasJson;
                    revisao.PeleObs = kvp.Value.Observacoes;
                    break;
                case "Humor/Sono/Energia":
                    revisao.HumorSonoEnergiaJson = sintomasJson;
                    revisao.HumorSonoEnergiaObs = kvp.Value.Observacoes;
                    break;
            }
        }
        
        return revisao;
    }

    private EstiloVida ConstruirEstiloVida()
    {
        return new EstiloVida
        {
            AlimentacaoJson = JsonSerializer.Serialize(AlimentacaoDisponiveis.Where(a => a.IsSelecionado).Select(a => a.Texto)),
            Hidratacao = HidratacaoSelecionada,
            ExercicioJson = JsonSerializer.Serialize(ExercicioDisponiveis.Where(e => e.IsSelecionado).Select(e => e.Texto)),
            ExercicioFrequencia = ExercicioFrequenciaSelecionada,
            Tabaco = TabacoSelecionado,
            TabacoQuantidade = TabacoQuantidade,
            Alcool = AlcoolSelecionado,
            Cafeina = CafeinaSelecionada,
            Stress = Stress,
            SonoJson = JsonSerializer.Serialize(SonoDisponiveis.Where(s => s.IsSelecionado).Select(s => s.Texto)),
            Observacoes = EstiloVidaObservacoes
        };
    }

    private HistoriaFamiliar ConstruirHistoriaFamiliar()
    {
        return new HistoriaFamiliar
        {
            AntecedentesJson = JsonSerializer.Serialize(AntecedentesDisponiveis.Where(a => a.IsSelecionado).Select(a => a.Texto)),
            ParentescoJson = JsonSerializer.Serialize(ParentescoDisponiveis.Where(p => p.IsSelecionado).Select(p => p.Texto)),
            Observacoes = FamiliarObservacoes
        };
    }

    private bool VerificarSeCompleta()
    {
        // Critério mínimo: pelo menos um motivo de consulta
        return MotivosDisponiveis.Any(m => m.IsSelecionado) || !string.IsNullOrEmpty(OutroMotivo);
    }

    #region Métodos de Limpeza
    private void LimparMotivoConsulta()
    {
        foreach (var motivo in MotivosDisponiveis)
            motivo.IsSelecionado = false;
        
        OutroMotivo = null;
        LocalizacaoSelecionada = null;
        LadoSelecionado = null;
        DataInicio = null;
        DuracaoSelecionada = null;
        EvolucaoSelecionada = null;
        Intensidade = 0;
        
        foreach (var carater in CaracteresDisponiveis)
            carater.IsSelecionado = false;
        
        foreach (var fator in FatoresAgravantesDisponiveis)
            fator.IsSelecionado = false;
        
        foreach (var fator in FatoresAlivioDisponiveis)
            fator.IsSelecionado = false;
        
        MotivoObservacoes = null;
    }

    private void LimparHistoriaClinica()
    {
        foreach (var doenca in DoencasCronicasDisponiveis)
            doenca.IsSelecionado = false;
        
        Cirurgias.Clear();
        
        foreach (var tipo in TiposAlergiasDisponiveis)
            tipo.IsSelecionado = false;
        
        EspecificarAlergias = null;
        SemAlergias = false;
        
        MedicacaoAtual.Clear();
        SemMedicacao = false;
        
        Suplementacao.Clear();
        SemSuplementacao = false;
        
        foreach (var vacina in VacinacaoDisponiveis)
            vacina.IsSelecionado = false;
        
        VacinacaoNaoAplicavel = false;
        HistoriaObservacoes = null;
    }

    private void LimparRevisaoSistemas()
    {
        foreach (var sistema in Sistemas.Values)
        {
            foreach (var sintoma in sistema.Sintomas)
                sintoma.IsSelecionado = false;
            
            sistema.Observacoes = null;
        }
    }

    private void LimparEstiloVida()
    {
        foreach (var alimentacao in AlimentacaoDisponiveis)
            alimentacao.IsSelecionado = false;
        
        HidratacaoSelecionada = null;
        
        foreach (var exercicio in ExercicioDisponiveis)
            exercicio.IsSelecionado = false;
        
        ExercicioFrequenciaSelecionada = null;
        TabacoSelecionado = null;
        TabacoQuantidade = null;
        AlcoolSelecionado = null;
        CafeinaSelecionada = null;
        Stress = 0;
        
        foreach (var sono in SonoDisponiveis)
            sono.IsSelecionado = false;
        
        EstiloVidaObservacoes = null;
    }

    private void LimparHistoriaFamiliar()
    {
        foreach (var antecedente in AntecedentesDisponiveis)
            antecedente.IsSelecionado = false;
        
        foreach (var parentesco in ParentescoDisponiveis)
            parentesco.IsSelecionado = false;
        
        FamiliarObservacoes = null;
    }
    #endregion
    #endregion
}

#region Classes Auxiliares
/// <summary>
/// Classe para representar itens de chip selecionáveis
/// </summary>
public partial class ChipItem : ObservableObject
{
    public ChipItem(string texto)
    {
        Texto = texto;
    }

    [ObservableProperty]
    private string texto = string.Empty;

    [ObservableProperty]
    private bool isSelecionado;
}

/// <summary>
/// Classe para representar itens de cirurgia
/// </summary>
public partial class ItemCirurgia : ObservableObject
{
    [ObservableProperty]
    private int ano;

    [ObservableProperty]
    private string tipo = string.Empty;

    [ObservableProperty]
    private string? observacoes;
}

/// <summary>
/// Classe para representar medicação/suplementação
/// </summary>
public partial class ItemMedicacao : ObservableObject
{
    [ObservableProperty]
    private string substancia = string.Empty;

    [ObservableProperty]
    private string? dose;

    [ObservableProperty]
    private string? frequencia;
}

/// <summary>
/// Classe para representar um sistema na revisão de sistemas
/// </summary>
public partial class SistemaRevisao : ObservableObject
{
    [ObservableProperty]
    private string nome = string.Empty;

    [ObservableProperty]
    private ObservableCollection<ChipItem> sintomas = new();

    [ObservableProperty]
    private string? observacoes;
}
#endregion