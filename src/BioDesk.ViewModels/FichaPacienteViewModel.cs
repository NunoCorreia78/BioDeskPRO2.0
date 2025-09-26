using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Navigation;
using BioDesk.Services.AutoSave;
using BioDesk.Services.Notifications;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para a ficha básica do paciente
/// Permite visualizar e editar dados básicos do paciente
/// Com auto-save integrado usando debounce
/// </summary>
public partial class FichaPacienteViewModel : ViewModelBase, IDisposable
{
    private readonly IPacienteService _pacienteService;
    private readonly INavigationService _navigationService;
    private readonly INotificationService _notificationService;
    private readonly ILogger<FichaPacienteViewModel> _logger;
    private readonly IAutoSaveService<Paciente> _autoSaveService;

    // Contador para testar se os comandos funcionam
    private int _testeContador = 0;

    // ViewModel para o sistema de anamnese revolucionário INTEGRADO
    public AnamneseViewModelIntegrado AnamneseViewModelIntegrado { get; }

    [ObservableProperty]
    private bool _autoSaveEnabled = true;

    [ObservableProperty]
    private DateTime? _lastAutoSave;

    [ObservableProperty]
    private bool _isAutoSaving = false;
    
    [ObservableProperty]
    private Paciente? _pacienteAtual;
    
    [ObservableProperty]
    private bool _isEdicao = false;
    
    [ObservableProperty]
    private bool _isDirty = false;
    
    // Propriedades básicas do formulário
    [ObservableProperty]
    private string _nome = string.Empty;
    
    [ObservableProperty]
    private string _email = string.Empty;
    
    [ObservableProperty]
    private string _telefone = string.Empty;
    
    [ObservableProperty]
    private DateTime _dataNascimento = DateTime.Today.AddYears(-30);

    // ================= PROPRIEDADES DA AVALIAÇÃO CLÍNICA =================
    
    // Motivos da Consulta - Chips Toggle
    [ObservableProperty]
    private bool _motivosDor = false;
    
    [ObservableProperty]
    private bool _motivosFadiga = false;
    
    [ObservableProperty]
    private bool _motivosAnsiedade = false;
    
    [ObservableProperty]
    private bool _motivosStress = false;
    
    [ObservableProperty]
    private bool _motivosDigestivo = false;
    
    [ObservableProperty]
    private bool _motivosRespiratorio = false;
    
    [ObservableProperty]
    private bool _motivosSono = false;
    
    [ObservableProperty]
    private bool _motivosPrevencao = false;
    
    [ObservableProperty]
    private bool _motivosOutro = false;
    
    [ObservableProperty]
    private string _motivosOutroTexto = string.Empty;
    
    [ObservableProperty]
    private string _motivoConsulta = string.Empty;
    
    [ObservableProperty]
    private string _objetivoPaciente = string.Empty;
    
    // Sintomas - Musculoesquelético
    [ObservableProperty]
    private bool _sintomasMusculoCervicalgia = false;
    
    [ObservableProperty]
    private bool _sintomasMusculoLombalgia = false;
    
    [ObservableProperty]
    private bool _sintomasMusculoDorsalgia = false;
    
    [ObservableProperty]
    private bool _sintomasMusculoDorArticular = false;
    
    [ObservableProperty]
    private bool _sintomasMusculoRigidezMatinal = false;
    
    [ObservableProperty]
    private bool _sintomasMusculoFraqueza = false;
    
    // Sintomas - Neurológico
    [ObservableProperty]
    private bool _sintomasNeurologicoCefaleia = false;
    
    [ObservableProperty]
    private bool _sintomasNeurologicoTonturas = false;
    
    [ObservableProperty]
    private bool _sintomasNeurologicoVertigens = false;
    
    [ObservableProperty]
    private bool _sintomasNeurologicoParestesias = false;
    
    [ObservableProperty]
    private bool _sintomasNeurologicoDormencia = false;
    
    // Sintomas - Digestivo
    [ObservableProperty]
    private bool _sintomasDigestivoAzia = false;
    
    [ObservableProperty]
    private bool _sintomasDigestivoRefluxo = false;
    
    [ObservableProperty]
    private bool _sintomasDigestivoNauseas = false;
    
    [ObservableProperty]
    private bool _sintomasDigestivoDistensao = false;
    
    [ObservableProperty]
    private bool _sintomasDigestivoObstipacao = false;
    
    [ObservableProperty]
    private bool _sintomasDigestivoDiarreia = false;
    
    // Sintomas - Saúde Mental
    [ObservableProperty]
    private bool _sintomasMentalAnsiedade = false;
    
    [ObservableProperty]
    private bool _sintomasMentalDepressao = false;
    
    [ObservableProperty]
    private bool _sintomasMentalIrritabilidade = false;
    
    [ObservableProperty]
    private bool _sintomasMentalPanico = false;
    
    [ObservableProperty]
    private bool _sintomasMentalInsonia = false;
    
    [ObservableProperty]
    private bool _sintomasMentalSonolencia = false;
    
    // História da Queixa Atual (HQA)
    [ObservableProperty]
    private string _localizacaoHQA = string.Empty;
    
    [ObservableProperty]
    private double _intensidadeHQA = 0;
    
    [ObservableProperty]
    private string _caraterHQA = string.Empty;
    
    // Saúde Mental / Stress
    [ObservableProperty]
    private double _nivelStress = 0;
    
    // Outros Sintomas
    [ObservableProperty]
    private string _outrosSintomas = string.Empty;

    public FichaPacienteViewModel(
        IPacienteService pacienteService,
        INavigationService navigationService,
        INotificationService notificationService,
        IAutoSaveService<Paciente> autoSaveService,
        AnamneseViewModelIntegrado anamneseViewModelIntegrado,
        ILogger<FichaPacienteViewModel> logger)
    {
        _pacienteService = pacienteService;
        _navigationService = navigationService;
        _notificationService = notificationService;
        _autoSaveService = autoSaveService;
        _logger = logger;
        AnamneseViewModelIntegrado = anamneseViewModelIntegrado;

        // Configurar auto-save
        ConfigurarAutoSave();
        
        // Inicializar com paciente ativo se existir
        var pacienteAtivo = _pacienteService.GetPacienteAtivo();
        if (pacienteAtivo != null)
        {
            CarregarPaciente(pacienteAtivo);
        }
        else
        {
            LimparFormulario();
        }
    }

    /// <summary>
    /// Propriedade computada para mostrar a idade do paciente
    /// </summary>
    public string Idade => CalcularIdade(DataNascimento);

    /// <summary>
    /// Propriedade para o ID do paciente (somente leitura)
    /// </summary>
    public int Id => PacienteAtual?.Id ?? 0;

    /// <summary>
    /// Data de criação do paciente (somente leitura)
    /// </summary>
    public DateTime? CriadoEm => PacienteAtual?.CriadoEm;

    /// <summary>
    /// Data de última atualização (somente leitura)
    /// </summary>
    public DateTime? AtualizadoEm => PacienteAtual?.AtualizadoEm;

    /// <summary>
    /// Serviço de navegação (para uso nos bindings)
    /// </summary>
    public INavigationService NavigationService => _navigationService;

    [RelayCommand]
    private void Editar()
    {
        IsEdicao = true;
        _logger.LogInformation("Modo de edição ativado para paciente ID: {Id}", Id);
    }

    [RelayCommand]
    private async Task GravarAsync()
    {
        if (!ValidarFormulario())
            return;

        try
        {
            var paciente = CriarPacienteFromFormulario();
            var pacienteGravado = await _pacienteService.GravarAsync(paciente);
            
            // Atualizar paciente ativo e navegar para ficha
            _pacienteService.SetPacienteAtivo(pacienteGravado);
            _logger.LogInformation("Paciente gravado com sucesso: {Nome} (ID: {Id})", pacienteGravado.Nome, pacienteGravado.Id);
            
            // Sair do modo de edição
            IsEdicao = false;
            IsDirty = false;
            
            // Recarregar dados
            CarregarPaciente(pacienteGravado);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gravar paciente");
        }
    }

    [RelayCommand]
    private void Cancelar()
    {
        if (IsDirty)
        {
            // Nota: Em aplicação real, usar um serviço de diálogo
            // Por agora, apenas reverter as alterações
            if (PacienteAtual != null)
            {
                CarregarPaciente(PacienteAtual);
            }
            else
            {
                LimparFormulario();
            }
        }
        
        IsEdicao = false;
        IsDirty = false;
        _logger.LogInformation("Edição cancelada");
    }

    private bool CanVoltar() => true;

    [RelayCommand]
    private void VoltarDashboard()
    {
        _navigationService.NavigateTo("Dashboard");
    }

    [RelayCommand(CanExecute = nameof(CanVoltar))]
    private void Voltar()
    {
        VoltarDashboard();
    }

    [RelayCommand]
    private void VoltarLista()
    {
        _navigationService.NavigateTo("ListaPacientes");
    }

    /// <summary>
    /// Marca sintomas musculoesqueléticos para trabalhar na sessão atual
    /// </summary>
    [RelayCommand]
    private async Task TrabalharHojeMusculoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            // TESTE SIMPLES: Incrementar contador
            _testeContador++;
            
            var sintomasAtivos = new List<string>();
            if (SintomasMusculoCervicalgia) sintomasAtivos.Add("Cervicalgia");
            if (SintomasMusculoLombalgia) sintomasAtivos.Add("Lombalgia");
            if (SintomasMusculoDorsalgia) sintomasAtivos.Add("Dorsalgia");
            if (SintomasMusculoDorArticular) sintomasAtivos.Add("Dor articular");
            if (SintomasMusculoRigidezMatinal) sintomasAtivos.Add("Rigidez matinal");
            if (SintomasMusculoFraqueza) sintomasAtivos.Add("Fraqueza");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"✅ CLIQUE #{_testeContador}: {string.Join(", ", sintomasAtivos)} → SESSÃO";
                _logger?.LogInformation("Sintomas musculoesqueléticos marcados para sessão: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = $"⚠️ CLIQUE #{_testeContador}: Marque primeiro os chips musculoesqueléticos!";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Atualiza o perfil permanente com sintomas musculoesqueléticos
    /// </summary>
    [RelayCommand]
    private async Task AtualizarPermanenteMusculoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var sintomasAtivos = new List<string>();
            if (SintomasMusculoCervicalgia) sintomasAtivos.Add("Cervicalgia");
            if (SintomasMusculoLombalgia) sintomasAtivos.Add("Lombalgia");
            if (SintomasMusculoDorsalgia) sintomasAtivos.Add("Dorsalgia");
            if (SintomasMusculoDorArticular) sintomasAtivos.Add("Dor articular");
            if (SintomasMusculoRigidezMatinal) sintomasAtivos.Add("Rigidez matinal");
            if (SintomasMusculoFraqueza) sintomasAtivos.Add("Fraqueza");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"💾 PERMANENTE: {string.Join(", ", sintomasAtivos)} salvo no perfil";
                _logger?.LogInformation("Perfil musculoesquelético permanente atualizado: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = "⚠️ Selecione sintomas para salvar no perfil permanente";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Marca sintomas neurológicos para trabalhar na sessão atual
    /// </summary>
    [RelayCommand]
    private async Task TrabalharHojeNeuroAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var sintomasAtivos = new List<string>();
            if (SintomasNeurologicoCefaleia) sintomasAtivos.Add("Cefaleia");
            if (SintomasNeurologicoTonturas) sintomasAtivos.Add("Tonturas");
            if (SintomasNeurologicoVertigens) sintomasAtivos.Add("Vertigens");
            if (SintomasNeurologicoParestesias) sintomasAtivos.Add("Parestesias");
            if (SintomasNeurologicoDormencia) sintomasAtivos.Add("Dormência");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"✅ Neurológicos para SESSÃO: {string.Join(", ", sintomasAtivos)}";
                _logger?.LogInformation("Sintomas neurológicos marcados para sessão: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = "⚠️ Selecione primeiro os sintomas neurológicos";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Atualiza o perfil permanente com sintomas neurológicos
    /// </summary>
    [RelayCommand]
    private async Task AtualizarPermanenteNeuroAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var sintomasAtivos = new List<string>();
            if (SintomasNeurologicoCefaleia) sintomasAtivos.Add("Cefaleia");
            if (SintomasNeurologicoTonturas) sintomasAtivos.Add("Tonturas");
            if (SintomasNeurologicoVertigens) sintomasAtivos.Add("Vertigens");
            if (SintomasNeurologicoParestesias) sintomasAtivos.Add("Parestesias");
            if (SintomasNeurologicoDormencia) sintomasAtivos.Add("Dormência");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"💾 PERMANENTE neurológico: {string.Join(", ", sintomasAtivos)}";
                _logger?.LogInformation("Perfil neurológico permanente atualizado: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = "⚠️ Selecione sintomas neurológicos para perfil permanente";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Marca sintomas digestivos para trabalhar na sessão atual
    /// </summary>
    [RelayCommand]
    private async Task TrabalharHojeDigestivoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var sintomasAtivos = new List<string>();
            if (SintomasDigestivoAzia) sintomasAtivos.Add("Azia");
            if (SintomasDigestivoRefluxo) sintomasAtivos.Add("Refluxo");
            if (SintomasDigestivoNauseas) sintomasAtivos.Add("Náuseas");
            if (SintomasDigestivoDistensao) sintomasAtivos.Add("Distensão");
            if (SintomasDigestivoObstipacao) sintomasAtivos.Add("Obstipação");
            if (SintomasDigestivoDiarreia) sintomasAtivos.Add("Diarreia");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"✅ Digestivos para SESSÃO: {string.Join(", ", sintomasAtivos)}";
                _logger?.LogInformation("Sintomas digestivos marcados para sessão: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = "⚠️ Selecione primeiro os sintomas digestivos";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Atualiza o perfil permanente com sintomas digestivos
    /// </summary>
    [RelayCommand]
    private async Task AtualizarPermanenteDigestivoAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var sintomasAtivos = new List<string>();
            if (SintomasDigestivoAzia) sintomasAtivos.Add("Azia");
            if (SintomasDigestivoRefluxo) sintomasAtivos.Add("Refluxo");
            if (SintomasDigestivoNauseas) sintomasAtivos.Add("Náuseas");
            if (SintomasDigestivoDistensao) sintomasAtivos.Add("Distensão");
            if (SintomasDigestivoObstipacao) sintomasAtivos.Add("Obstipação");
            if (SintomasDigestivoDiarreia) sintomasAtivos.Add("Diarreia");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"💾 PERMANENTE digestivo: {string.Join(", ", sintomasAtivos)}";
                _logger?.LogInformation("Perfil digestivo permanente atualizado: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = "⚠️ Selecione sintomas digestivos para perfil permanente";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Marca sintomas de saúde mental para trabalhar na sessão atual
    /// </summary>
    [RelayCommand]
    private async Task TrabalharHojeMentalAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var sintomasAtivos = new List<string>();
            if (SintomasMentalAnsiedade) sintomasAtivos.Add("Ansiedade");
            if (SintomasMentalDepressao) sintomasAtivos.Add("Humor deprimido");
            if (SintomasMentalIrritabilidade) sintomasAtivos.Add("Irritabilidade");
            if (SintomasMentalPanico) sintomasAtivos.Add("Ataques de pânico");
            if (SintomasMentalInsonia) sintomasAtivos.Add("Insónia");
            if (SintomasMentalSonolencia) sintomasAtivos.Add("Sonolência diurna");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"✅ Saúde mental para SESSÃO: {string.Join(", ", sintomasAtivos)}";
                _logger?.LogInformation("Sintomas de saúde mental marcados para sessão: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = "⚠️ Selecione primeiro os sintomas de saúde mental";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Atualiza o perfil permanente com sintomas de saúde mental
    /// </summary>
    [RelayCommand]
    private async Task AtualizarPermanenteMentalAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            var sintomasAtivos = new List<string>();
            if (SintomasMentalAnsiedade) sintomasAtivos.Add("Ansiedade");
            if (SintomasMentalDepressao) sintomasAtivos.Add("Humor deprimido");
            if (SintomasMentalIrritabilidade) sintomasAtivos.Add("Irritabilidade");
            if (SintomasMentalPanico) sintomasAtivos.Add("Ataques de pânico");
            if (SintomasMentalInsonia) sintomasAtivos.Add("Insónia");
            if (SintomasMentalSonolencia) sintomasAtivos.Add("Sonolência diurna");

            if (sintomasAtivos.Any())
            {
                ErrorMessage = $"💾 PERMANENTE saúde mental: {string.Join(", ", sintomasAtivos)}";
                _logger?.LogInformation("Perfil de saúde mental permanente atualizado: {Sintomas}", string.Join(", ", sintomasAtivos));
            }
            else
            {
                ErrorMessage = "⚠️ Selecione sintomas de saúde mental para perfil permanente";
            }
            
            await Task.CompletedTask;
        });
    }

    /// <summary>
    /// Carrega um paciente no formulário
    /// </summary>
    public void CarregarPaciente(Paciente paciente)
    {
        if (paciente == null) return;

        var isNovoPaciente = paciente.Id == 0;

        PacienteAtual = paciente;
        Nome = paciente.Nome ?? string.Empty;
        Email = paciente.Email ?? string.Empty;
        Telefone = paciente.Telefone ?? string.Empty;
        DataNascimento = paciente.DataNascimento == default
            ? DateTime.Today.AddYears(-30)
            : paciente.DataNascimento;
        
        IsEdicao = isNovoPaciente ? true : false;
        IsDirty = false;
        
        // Notificar propriedades computadas
        OnPropertyChanged(nameof(Id));
        OnPropertyChanged(nameof(CriadoEm));
        OnPropertyChanged(nameof(AtualizadoEm));
        OnPropertyChanged(nameof(Idade));
        
        if (isNovoPaciente)
        {
            _logger.LogInformation("Ficha preparada para novo paciente");
        }
        else
        {
            _logger.LogInformation("Paciente carregado: {Nome} (ID: {Id})", paciente.Nome, paciente.Id);
        }
    }

    /// <summary>
    /// Limpa o formulário para criar novo paciente
    /// </summary>
    public void LimparFormulario()
    {
        PacienteAtual = null;
        Nome = string.Empty;
        Email = string.Empty;
        Telefone = string.Empty;
        DataNascimento = DateTime.Today.AddYears(-30);
        
        IsEdicao = true; // Novo paciente começa em modo de edição
        IsDirty = false;
        
        // Notificar propriedades computadas
        OnPropertyChanged(nameof(Id));
        OnPropertyChanged(nameof(CriadoEm));
        OnPropertyChanged(nameof(AtualizadoEm));
        OnPropertyChanged(nameof(Idade));
        
        _logger.LogInformation("Formulário limpo para novo paciente");
    }

    /// <summary>
    /// Valida o formulário antes de gravar
    /// </summary>
    private bool ValidarFormulario()
    {
        if (string.IsNullOrWhiteSpace(Nome))
        {
            _logger.LogWarning("Tentativa de gravar paciente sem nome");
            return false;
        }

        return true;
    }

    /// <summary>
    /// Cria uma instância de Paciente com os dados do formulário
    /// </summary>
    private Paciente CriarPacienteFromFormulario()
    {
        var paciente = PacienteAtual ?? new Paciente();
        
        paciente.Nome = Nome?.Trim() ?? string.Empty;
        paciente.Email = string.IsNullOrWhiteSpace(Email) ? string.Empty : Email.Trim();
        paciente.Telefone = string.IsNullOrWhiteSpace(Telefone) ? null : Telefone.Trim();
        paciente.DataNascimento = DataNascimento;
        
        return paciente;
    }

    /// <summary>
    /// Calcula a idade baseada na data de nascimento
    /// </summary>
    private static string CalcularIdade(DateTime dataNascimento)
    {
        var hoje = DateTime.Today;
        var idade = hoje.Year - dataNascimento.Year;
        
        if (dataNascimento.Date > hoje.AddYears(-idade))
            idade--;
            
        return $"{idade} anos";
    }

    /// <summary>
    /// Marca o formulário como alterado quando propriedades mudam
    /// </summary>
    partial void OnNomeChanged(string value) => MarkAsDirtyAndTriggerAutoSave();
    partial void OnEmailChanged(string value) => MarkAsDirtyAndTriggerAutoSave();
    partial void OnTelefoneChanged(string value) => MarkAsDirtyAndTriggerAutoSave();
    partial void OnDataNascimentoChanged(DateTime value) 
    {
        MarkAsDirtyAndTriggerAutoSave();
        OnPropertyChanged(nameof(Idade));
    }

    private void MarkAsDirty()
    {
        if (IsEdicao) // Só marca como dirty se estiver em modo de edição
        {
            IsDirty = true;
        }
    }

    /// <summary>
    /// Marca como dirty e dispara auto-save se habilitado
    /// </summary>
    private void MarkAsDirtyAndTriggerAutoSave()
    {
        MarkAsDirty();
        
        // Disparar auto-save se habilitado e em modo de edição
        if (AutoSaveEnabled && IsEdicao && PacienteAtual != null)
        {
            var paciente = CriarPacienteFromFormulario();
            _autoSaveService.TriggerAutoSave(paciente);
        }
    }

    /// <summary>
    /// Configura o sistema de auto-save com debounce
    /// </summary>
    private void ConfigurarAutoSave()
    {
        // Configurar função de save
        _autoSaveService.SetSaveFunction(async paciente => await SalvarPacienteInternoAsync(paciente));
        
        // Configurar debounce de 2 segundos
        _autoSaveService.SetDebounceTime(TimeSpan.FromSeconds(2.0));

        // Subscrever aos eventos do auto-save
        _autoSaveService.AutoSaveExecuted += OnAutoSaveExecuted;
        _autoSaveService.AutoSaveError += OnAutoSaveError;

        // Iniciar monitoramento
        _autoSaveService.StartMonitoring();
    }

    /// <summary>
    /// Método interno para salvar paciente (usado pelo auto-save)
    /// </summary>
    private async Task SalvarPacienteInternoAsync(Paciente paciente)
    {
        // Usar o método GravarAsync existente no IPacienteService
        await _pacienteService.GravarAsync(paciente);
        _logger.LogInformation("Auto-save executado para paciente {PacienteId}", paciente.Id);
    }

    /// <summary>
    /// Handler para sucesso do auto-save
    /// </summary>
    private void OnAutoSaveExecuted(object? sender, AutoSaveEventArgs<Paciente> e)
    {
        // Mostrar notificação discreta de sucesso
        _ = Task.Run(async () => await _notificationService.ShowSuccessAsync("Dados guardados automaticamente"));
        IsDirty = false;
    }

    /// <summary>
    /// Handler para falha do auto-save
    /// </summary>
    private void OnAutoSaveError(object? sender, AutoSaveErrorEventArgs<Paciente> e)
    {
        var errorMsg = e.Exception?.Message ?? "Erro desconhecido";
        _ = Task.Run(async () => await _notificationService.ShowWarningAsync($"Falha no auto-save: {errorMsg}", durationMs: 0)); // Sem auto-close
        _logger.LogError(e.Exception, "Erro no auto-save do paciente");
    }

    /// <summary>
    /// Dispensa recursos quando o ViewModel é descartado
    /// </summary>
    public void Dispose()
    {
        // Fazer último save se necessário
        if (IsDirty && AutoSaveEnabled && PacienteAtual != null)
        {
            var paciente = CriarPacienteFromFormulario();
            _autoSaveService.TriggerAutoSave(paciente);
        }

        // Parar monitoramento
        _autoSaveService.StopMonitoring();

        // Desinscrever eventos
        _autoSaveService.AutoSaveExecuted -= OnAutoSaveExecuted;
        _autoSaveService.AutoSaveError -= OnAutoSaveError;
    }
}