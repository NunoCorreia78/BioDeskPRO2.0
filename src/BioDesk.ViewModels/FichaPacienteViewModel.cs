using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Navigation;
using BioDesk.Services.AutoSave;
using BioDesk.Services.Notifications;
using BioDesk.Services.Settings;
using BioDesk.Services.Consultas;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para a ficha básica do paciente
/// Permite visualizar e editar dados básicos do paciente
/// Com auto-save integrado usando debounce
/// </summary>
public partial class FichaPacienteViewModel : NavigationViewModelBase, IDisposable
{
    private readonly IPacienteService _pacienteService;
    private readonly INavigationService _navigationService;
    private readonly INotificationService _notificationService;
    private readonly ILogger<FichaPacienteViewModel> _logger;
    private readonly IAutoSaveService<Paciente> _autoSaveService;
    private readonly ISettingsService _settingsService;
    private readonly IConsultaService _consultaService;

    /// <summary>
    /// Auto-save controlado pelas configurações globais
    /// </summary>
    public bool AutoSaveEnabled 
    { 
        get => _settingsService.AutoSaveEnabled;
        set 
        {
            _settingsService.AutoSaveEnabled = value;
            _settingsService.SaveSettings();
            OnPropertyChanged();
            
            // Reconfigurar auto-save se necessário
            if (value && _autoSaveService != null)
            {
                ConfigurarAutoSave();
            }
            else if (!value && _autoSaveService != null)
            {
                _autoSaveService.StopMonitoring();
            }
        }
    }

    [ObservableProperty]
    private DateTime? _lastAutoSave;

    [ObservableProperty]
    private bool _isAutoSaving = false;
    
    [ObservableProperty]
    private Paciente? _pacienteAtual;
    
    [ObservableProperty]
    private PacienteViewModel? _pacienteWrapper;
    
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
    private DateTime? _dataNascimento;
    
    [ObservableProperty]
    private string _genero = string.Empty;
    
    [ObservableProperty]
    private string _estadoCivil = string.Empty;
    
    [ObservableProperty]
    private string _profissao = string.Empty;
    
    [ObservableProperty]
    private string _nif = string.Empty;
    
    [ObservableProperty]
    private string _morada = string.Empty;

    // Propriedades para gestão de consultas
    [ObservableProperty]
    private List<Consulta> _consultasPaciente = new();

    [ObservableProperty]
    private bool _hasConsultas = false;

    // Novas propriedades para o layout moderno
    [ObservableProperty]
    private Consulta? _consultaSelecionada;

    [ObservableProperty]
    private string _resumoAnamnese = string.Empty;

    [ObservableProperty]
    private string _buscaTemplate = string.Empty;

    [ObservableProperty]
    private List<TemplatePrescricao> _templatesSugeridos = new();

    // 🆕 Propriedades para Modal Nova Consulta
    [ObservableProperty]
    private bool _mostrarModalNovaConsulta = false;

    [ObservableProperty]
    private string _novaConsultaTipo = "Naturopatia";

    [ObservableProperty]
    private DateTime _novaConsultaData = DateTime.Today.AddDays(1);

    [ObservableProperty]
    private string _novaConsultaHora = "09:00";

    [ObservableProperty]
    private int _novaConsultaDuracao = 60;

    [ObservableProperty]
    private decimal _novaConsultaValor = 50.00m;

    [ObservableProperty]
    private string _novaConsultaStatus = "Agendada";

    [ObservableProperty]
    private string _novaConsultaNotas = string.Empty;

    // Listas para dropdowns do modal
    public List<string> TiposConsultaDisponiveis => new() { "Naturopatia", "Osteopatia", "Medicina Quântica", "Iridologia", "Seguimento" };
    
    public List<string> HorariosDisponiveis => GenerateTimeSlots();
    
    public List<int> DuracoesDisponiveis => new() { 30, 45, 60, 90, 120 };
    
    public List<string> StatusDisponiveis => new() { "Agendada", "Confirmada", "Realizada" };

    public bool PodeConfirmarNovaConsulta => !string.IsNullOrEmpty(NovaConsultaTipo) && NovaConsultaData > DateTime.Today;

    /// <summary>
    /// Gera slots de horário de 30 em 30 minutos das 8h às 19h
    /// </summary>
    private static List<string> GenerateTimeSlots()
    {
        var slots = new List<string>();
        for (int hour = 8; hour <= 19; hour++)
        {
            slots.Add($"{hour:D2}:00");
            if (hour < 19) slots.Add($"{hour:D2}:30");
        }
        return slots;
    }

    public FichaPacienteViewModel(
        IPacienteService pacienteService,
        INavigationService navigationService,
        INotificationService notificationService,
        IAutoSaveService<Paciente> autoSaveService,
        ISettingsService settingsService,
        IConsultaService consultaService,
        ILogger<FichaPacienteViewModel> logger) : base(navigationService, pacienteService)
    {
        try
        {
            _logger = logger;
            _logger.LogError("🚨🚨🚨 FichaPacienteViewModel: CONSTRUTOR INICIADO!");

            _logger.LogInformation("🚀 FichaPacienteViewModel: Iniciando construção...");

            _pacienteService = pacienteService;
            _logger.LogInformation("✓ PacienteService definido");

            _navigationService = navigationService;
            _logger.LogInformation("✓ NavigationService definido");

            _notificationService = notificationService;
            _logger.LogInformation("✓ NotificationService definido");

            _autoSaveService = autoSaveService;
            _logger.LogInformation("✓ AutoSaveService definido");

            _settingsService = settingsService;
            _logger.LogInformation("✓ SettingsService definido");

            _consultaService = consultaService;
            _logger.LogInformation("✓ ConsultaService definido");

            // Configurar auto-save
            _logger.LogInformation("🔧 Configurando auto-save...");
            ConfigurarAutoSave();
            _logger.LogInformation("✓ Auto-save configurado");

            // Subscrever ao evento PacienteAtivoChanged
            _logger.LogInformation("🔗 Configurando event handler...");
            _pacienteService.PacienteAtivoChanged += OnPacienteAtivoChanged;
            _logger.LogInformation("✓ Event handler configurado");
        
            // Inicializar com paciente ativo se existir
            _logger.LogWarning("� VERIFICANDO PACIENTE ATIVO NO CONSTRUTOR...");
            var pacienteAtivo = _pacienteService.GetPacienteAtivo();
            
            if (pacienteAtivo != null)
            {
                _logger.LogWarning($"👤 PACIENTE ATIVO ENCONTRADO: {pacienteAtivo.Nome} (ID: {pacienteAtivo.Id})");
                _logger.LogWarning($"📧 Email do BD: {pacienteAtivo.Email}");
                _logger.LogWarning($"📞 Telefone do BD: {pacienteAtivo.Telefone}");
                _logger.LogWarning($"👔 Profissão do BD: {pacienteAtivo.Profissao}");
                CarregarPaciente(pacienteAtivo);
                _logger.LogWarning("✓ PACIENTE CARREGADO NO CONSTRUTOR");
            }
            else
            {
                _logger.LogWarning("👤 NENHUM PACIENTE ATIVO - formulário limpo");
                LimparFormulario();
                _logger.LogWarning("✓ FORMULÁRIO LIMPO");
            }

            _logger.LogInformation("🎉 FichaPacienteViewModel: Construção concluída com sucesso!");
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "💥 CRASH no construtor FichaPacienteViewModel: {Message}", ex.Message);
            throw; // Re-throw para manter o crash visível
        }
    }

    /// <summary>
    /// Propriedades de idade e data de nascimento removidas conforme solicitado
    /// </summary>

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
    /// Idade calculada automaticamente a partir da data de nascimento
    /// </summary>
    public string IdadeCalculada
    {
        get
        {
            if (DataNascimento == null) return string.Empty;
            var nascimento = DataNascimento.Value.Date;
            var hoje = DateTime.Today;
            var anos = hoje.Year - nascimento.Year;
            if (nascimento > hoje.AddYears(-anos)) anos--;
            if (anos < 0) return string.Empty;
            return anos == 1 ? "1 ano" : $"{anos} anos";
        }
    }

    [RelayCommand]
    private void Editar()
    {
        IsEdicao = true;
        _logger.LogInformation("Modo de edição ativado para paciente ID: {Id}", Id);
    }

    [RelayCommand]
    private async Task GravarAsync()
    {
        if (!await ValidarFormularioAsync())
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
            
            await _notificationService.ShowSuccessAsync("Paciente gravado com sucesso!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gravar paciente");
            await _notificationService.ShowErrorAsync($"Erro ao gravar paciente: {ex.Message}");
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
    /// Comando para abrir modal de nova consulta
    /// </summary>
    [RelayCommand]
    private void NovaConsulta()
    {
        if (PacienteAtual == null)
        {
            _ = _notificationService.ShowErrorAsync("Nenhum paciente selecionado para criar consulta.");
            return;
        }

        // Resetar dados do modal
        NovaConsultaTipo = "Naturopatia";
        NovaConsultaData = DateTime.Today.AddDays(1);
        NovaConsultaHora = "09:00";
        NovaConsultaDuracao = 60;
        NovaConsultaValor = 50.00m;
        NovaConsultaStatus = "Agendada";
        NovaConsultaNotas = string.Empty;

        MostrarModalNovaConsulta = true;
        _logger.LogInformation("Modal nova consulta aberto para paciente {Nome}", PacienteAtual.Nome);
    }

    /// <summary>
    /// Comando para fechar o modal
    /// </summary>
    [RelayCommand]
    private void FecharModal()
    {
        MostrarModalNovaConsulta = false;
    }

    /// <summary>
    /// Comando para criar nova consulta com dados do modal
    /// </summary>
    [RelayCommand]
    private async Task CriarNovaConsulta()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (PacienteAtual == null || !PodeConfirmarNovaConsulta)
            {
                await _notificationService.ShowWarningAsync("Dados inválidos para criar consulta.");
                return;
            }

            // Se é um paciente novo (ID = 0), precisa de ser gravado primeiro
            if (PacienteAtual.Id == 0)
            {
                await _notificationService.ShowWarningAsync("Precisa de gravar o paciente antes de criar uma consulta.");
                return;
            }

            // Combinar data e hora
            var horaPartes = NovaConsultaHora.Split(':');
            var dataHoraCompleta = NovaConsultaData
                .AddHours(int.Parse(horaPartes[0]))
                .AddMinutes(int.Parse(horaPartes[1]));

            var novaConsulta = new Consulta
            {
                PacienteId = PacienteAtual.Id,
                DataConsulta = dataHoraCompleta,
                Status = NovaConsultaStatus,
                TipoConsulta = NovaConsultaTipo,
                Valor = NovaConsultaValor,
                Notas = $"{NovaConsultaNotas}\n\n[Duração prevista: {NovaConsultaDuracao} minutos]"
            };

            var consultaCriada = await _consultaService.CriarConsultaAsync(novaConsulta);
            if (consultaCriada != null)
            {
                await CarregarConsultasPaciente();
                MostrarModalNovaConsulta = false;
                
                // Selecionar a nova consulta criada
                ConsultaSelecionada = consultaCriada;
                
                await _notificationService.ShowSuccessAsync($"Nova consulta de {NovaConsultaTipo} agendada para {NovaConsultaData:dd/MM/yyyy} às {NovaConsultaHora}!");
                _logger.LogInformation($"Nova consulta criada: {consultaCriada.TipoConsulta} - {consultaCriada.DataConsulta:dd/MM/yyyy HH:mm}");
            }
        });
    }

    /// <summary>
    /// Comando para editar uma consulta existente
    /// </summary>
    [RelayCommand]
    private async Task EditarConsulta(Consulta consulta)
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (consulta == null) return;

            // Por agora, permite alterar status e notas da consulta
            // Futuramente pode abrir um dialog de edição
            if (consulta.Status == "Agendada")
            {
                consulta.Status = "Realizada";
                consulta.Notas += $" [Realizada em {DateTime.Now:dd/MM/yyyy HH:mm}]";
            }

            await _consultaService.AtualizarConsultaAsync(consulta);
            await CarregarConsultasPaciente();
            await _notificationService.ShowSuccessAsync("Consulta atualizada!");
        });
    }

    /// <summary>
    /// Comando para ver detalhes de uma consulta
    /// </summary>
    [RelayCommand]
    private void VerDetalhesConsulta(Consulta consulta)
    {
        if (consulta == null) return;

        var detalhes = $"Consulta: {consulta.TipoConsulta}\n" +
                      $"Data: {consulta.DataConsulta:dd/MM/yyyy HH:mm}\n" +
                      $"Status: {consulta.Status}\n" +
                      $"Valor: {consulta.Valor:C}\n" +
                      $"Notas: {consulta.Notas}";

        _ = _notificationService.ShowInfoAsync($"Detalhes da Consulta\n\n{detalhes}");
    }

    /// <summary>
    /// Comando para selecionar uma consulta e mostrar painel de detalhes
    /// </summary>
    [RelayCommand]
    private void SelecionarConsulta(Consulta consulta)
    {
        if (consulta == null) return;
        
        ConsultaSelecionada = consulta;
        GerarResumoAnamnese();
        CarregarTemplatesSugeridos();
        
        _logger.LogInformation($"Consulta selecionada: {consulta.TipoConsulta} - {consulta.DataConsulta:dd/MM/yyyy}");
    }

    /// <summary>
    /// Comando para fechar o painel de detalhes
    /// </summary>
    [RelayCommand]
    private void FecharDetalhes()
    {
        ConsultaSelecionada = null;
        ResumoAnamnese = string.Empty;
        TemplatesSugeridos.Clear();
    }

    /// <summary>
    /// Comando para repetir a última consulta
    /// </summary>
    [RelayCommand]
    private async Task RepetirConsulta()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (PacienteAtual?.Id == null || !ConsultasPaciente.Any())
            {
                await _notificationService.ShowWarningAsync("Não há consultas anteriores para repetir.");
                return;
            }

            var ultimaConsulta = ConsultasPaciente.OrderByDescending(c => c.DataConsulta).First();
            
            var novaConsulta = new Consulta
            {
                PacienteId = PacienteAtual.Id,
                DataConsulta = DateTime.Now.AddDays(7), // Agendar para a próxima semana
                Status = "Agendada",
                TipoConsulta = ultimaConsulta.TipoConsulta,
                Valor = ultimaConsulta.Valor,
                Notas = $"Repetição de consulta anterior ({ultimaConsulta.DataConsulta:dd/MM/yyyy})"
            };

            var consultaCriada = await _consultaService.CriarConsultaAsync(novaConsulta);
            if (consultaCriada != null)
            {
                await CarregarConsultasPaciente();
                await _notificationService.ShowSuccessAsync("Consulta repetida e agendada!");
            }
        });
    }

    /// <summary>
    /// Comando para selecionar template de prescrição
    /// </summary>
    [RelayCommand]
    private void SelecionarTemplate(TemplatePrescricao template)
    {
        if (template == null || ConsultaSelecionada == null) return;
        
        ConsultaSelecionada.Prescricao = template.Conteudo;
        OnPropertyChanged(nameof(ConsultaSelecionada));
    }

    /// <summary>
    /// Comando para guardar alterações na consulta
    /// </summary>
    [RelayCommand]
    private async Task GuardarConsulta()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (ConsultaSelecionada == null) return;

            await _consultaService.AtualizarConsultaAsync(ConsultaSelecionada);
            await CarregarConsultasPaciente();
            await _notificationService.ShowSuccessAsync("Consulta atualizada com sucesso!");
        });
    }

    /// <summary>
    /// Comando para gerar PDF da consulta
    /// </summary>
    [RelayCommand]
    private async Task GerarPdfConsulta()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (ConsultaSelecionada == null || PacienteAtual == null) return;

            // Funcionalidade de geração de PDF planejada para próximas versões
            await _notificationService.ShowInfoAsync("Funcionalidade de geração de PDF será implementada em breve!");
            
            _logger.LogInformation($"PDF solicitado para consulta {ConsultaSelecionada.Id} - Paciente: {PacienteAtual.Nome}");
        });
    }

    /// <summary>
    /// Gera um resumo automático da anamnese do paciente
    /// </summary>
    private void GerarResumoAnamnese()
    {
        if (PacienteAtual == null)
        {
            ResumoAnamnese = string.Empty;
            return;
        }

        var resumo = $"Paciente: {PacienteAtual.Nome}\n"; // Idade removida conforme solicitado
        resumo += $"Contacto: {PacienteAtual.Email}";
        
        if (!string.IsNullOrEmpty(PacienteAtual.Telefone))
        {
            resumo += $" | {PacienteAtual.Telefone}";
        }

        // Dados adicionais da anamnese serão incluídos em futuras versões
        resumo += "\n\n[Resumo completo da anamnese será implementado quando os dados estiverem disponíveis]";

        ResumoAnamnese = resumo;
    }

    /// <summary>
    /// Carrega templates sugeridos baseado na busca
    /// </summary>
    private void CarregarTemplatesSugeridos()
    {
        TemplatesSugeridos.Clear();

        // Templates mockados para demonstração
        var templates = new List<TemplatePrescricao>
        {
            new() { Id = 1, Nome = "Lombalgia Aguda", Categoria = "Osteopatia", 
                   Conteudo = "1. Repouso relativo\n2. Aplicação de calor local\n3. Exercícios suaves de mobilização" },
            new() { Id = 2, Nome = "Ansiedade", Categoria = "Naturopatia", 
                   Conteudo = "1. Chá de camomila 2x/dia\n2. Técnicas de respiração\n3. Suplemento de magnésio" },
            new() { Id = 3, Nome = "Digestão", Categoria = "Naturopatia", 
                   Conteudo = "1. Enzimas digestivas antes das refeições\n2. Probióticos\n3. Evitar alimentos processados" }
        };

        // Filtrar por busca se houver texto
        if (!string.IsNullOrEmpty(BuscaTemplate))
        {
            templates = templates.Where(t => 
                t.Nome.Contains(BuscaTemplate, StringComparison.OrdinalIgnoreCase) ||
                t.Categoria.Contains(BuscaTemplate, StringComparison.OrdinalIgnoreCase)
            ).ToList();
        }

        foreach (var template in templates)
        {
            TemplatesSugeridos.Add(template);
        }
    }

    /// <summary>
    /// Atualizar templates quando busca muda
    /// </summary>
    partial void OnBuscaTemplateChanged(string value)
    {
        if (ConsultaSelecionada != null)
        {
            CarregarTemplatesSugeridos();
        }
    }

    /// <summary>
    /// Triggers para atualizar propriedades computadas do modal
    /// </summary>
    partial void OnNovaConsultaTipoChanged(string value) => OnPropertyChanged(nameof(PodeConfirmarNovaConsulta));
    partial void OnNovaConsultaDataChanged(DateTime value) => OnPropertyChanged(nameof(PodeConfirmarNovaConsulta));

    /// <summary>
    /// Carrega as consultas do paciente atual
    /// </summary>
    private async Task CarregarConsultasPaciente()
    {
        if (PacienteAtual?.Id == null || PacienteAtual.Id == 0)
        {
            ConsultasPaciente.Clear();
            HasConsultas = false;
            return;
        }

        try
        {
            var consultas = await _consultaService.ObterConsultasPorPacienteAsync(PacienteAtual.Id);
            
            ConsultasPaciente.Clear();
            foreach (var consulta in consultas.OrderByDescending(c => c.DataConsulta))
            {
                ConsultasPaciente.Add(consulta);
            }
            
            HasConsultas = ConsultasPaciente.Count > 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, $"Erro ao carregar consultas do paciente {PacienteAtual.Nome}");
            ConsultasPaciente.Clear();
            HasConsultas = false;
        }
    }

    /// <summary>
    /// Carrega um paciente no formulário
    /// </summary>
    public async Task CarregarPacienteAsync(Paciente paciente)
    {
        if (paciente == null)
            return;

        paciente = await GarantirPacienteDetalhadoAsync(paciente);

        _logger.LogInformation("📂 (Async) Carregando paciente: {Nome} (ID: {Id})", paciente.Nome, paciente.Id);

        LogDadosPaciente(paciente);

        PreencherFormularioPaciente(paciente);
    }

    /// <summary>
    /// Método síncrono mantido para compatibilidade
    /// </summary>
    public void CarregarPaciente(Paciente paciente)
    {
        try
        {
            if (paciente == null)
            {
                _logger.LogWarning("CarregarPaciente chamado com paciente null");
                LimparFormulario();
                return;
            }

            paciente = GarantirPacienteDetalhado(paciente);

            _logger.LogInformation($"📂 Carregando paciente: {paciente.Nome}");

            LogDadosPaciente(paciente);

            PreencherFormularioPaciente(paciente);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar paciente no método síncrono");
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
        DataNascimento = null;
        
        IsEdicao = true; // Novo paciente começa em modo de edição
        IsDirty = false;
        
        // Notificar propriedades computadas
        OnPropertyChanged(nameof(Id));
        OnPropertyChanged(nameof(CriadoEm));
        OnPropertyChanged(nameof(AtualizadoEm));
        OnPropertyChanged(nameof(IdadeCalculada));
        
        _logger.LogInformation("Formulário limpo para novo paciente");
    }

    private void PreencherFormularioPaciente(Paciente paciente)
    {
        var isNovoPaciente = paciente.Id == 0;

        PacienteAtual = paciente;
        PacienteWrapper = new PacienteViewModel(paciente);

        Nome = paciente.Nome ?? string.Empty;
        Email = paciente.Email ?? string.Empty;
        Telefone = paciente.Telefone ?? string.Empty;
        DataNascimento = paciente.DataNascimento;
        Genero = paciente.Genero ?? string.Empty;
        EstadoCivil = paciente.EstadoCivil ?? string.Empty;
        Profissao = paciente.Profissao ?? string.Empty;
        Nif = paciente.NIF ?? string.Empty;
        Morada = paciente.Morada ?? string.Empty;

        _logger.LogWarning("🚨 DEPOIS DE ATRIBUIR ÀS PROPRIEDADES:");
        _logger.LogWarning("📋 Nome: '{Nome}'", Nome);
        _logger.LogWarning("📧 Email: '{Email}'", Email);
        _logger.LogWarning("📞 Telefone: '{Telefone}'", Telefone);
        _logger.LogWarning("📅 DataNascimento: {DataNascimento}", DataNascimento?.ToString("dd/MM/yyyy") ?? "NULL");
        _logger.LogWarning("👔 Profissao: '{Profissao}'", Profissao);
        _logger.LogWarning("🆔 Genero: '{Genero}'", Genero);
        _logger.LogWarning("💍 EstadoCivil: '{EstadoCivil}'", EstadoCivil);
        _logger.LogWarning("🏠 Morada: '{Morada}'", Morada);
        _logger.LogWarning("🔢 NIF: '{Nif}'", Nif);

        _logger.LogWarning("⚙️ FORÇANDO NOTIFICAÇÃO DE PROPRIEDADES...");
        OnPropertyChanged(nameof(Nome));
        OnPropertyChanged(nameof(Email));
        OnPropertyChanged(nameof(Telefone));
        OnPropertyChanged(nameof(DataNascimento));
        OnPropertyChanged(nameof(Genero));
        OnPropertyChanged(nameof(EstadoCivil));
        OnPropertyChanged(nameof(Profissao));
        OnPropertyChanged(nameof(Nif));
        OnPropertyChanged(nameof(Morada));

        IsEdicao = isNovoPaciente;
        IsDirty = false;

        if (isNovoPaciente)
        {
            ConsultasPaciente = new List<Consulta>();
            HasConsultas = false;
        }
        else
        {
            _ = CarregarConsultasPaciente();
        }

        OnPropertyChanged(nameof(Id));
        OnPropertyChanged(nameof(CriadoEm));
        OnPropertyChanged(nameof(AtualizadoEm));
        OnPropertyChanged(nameof(IdadeCalculada));

        if (isNovoPaciente)
        {
            _logger.LogInformation("Ficha preparada para novo paciente");
        }
        else
        {
            _logger.LogInformation("Paciente carregado: {Nome} (ID: {Id})", paciente.Nome, paciente.Id);
        }
    }

    private Paciente GarantirPacienteDetalhado(Paciente paciente)
    {
        ArgumentNullException.ThrowIfNull(paciente);

        if (paciente.Id <= 0)
            return paciente;

        try
        {
            var pacienteCompleto = _pacienteService.GetByIdAsync(paciente.Id)
                .ConfigureAwait(false).GetAwaiter().GetResult();

            if (pacienteCompleto == null)
            {
                _logger.LogWarning("Não foi possível obter dados completos para o paciente ID {Id}", paciente.Id);
                return paciente;
            }

            if (!ReferenceEquals(paciente, pacienteCompleto))
            {
                CopiarPropriedadesPaciente(paciente, pacienteCompleto);
                _logger.LogInformation("Paciente ID {Id} sincronizado com dados completos do repositório", paciente.Id);
            }

            return paciente;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao obter dados completos do paciente ID {Id}", paciente.Id);
            return paciente;
        }
    }

    private async Task<Paciente> GarantirPacienteDetalhadoAsync(Paciente paciente)
    {
        ArgumentNullException.ThrowIfNull(paciente);

        if (paciente.Id <= 0)
            return paciente;

        try
        {
            var pacienteCompleto = await _pacienteService.GetByIdAsync(paciente.Id);

            if (pacienteCompleto == null)
            {
                _logger.LogWarning("[Async] Não foi possível obter dados completos para o paciente ID {Id}", paciente.Id);
                return paciente;
            }

            if (!ReferenceEquals(paciente, pacienteCompleto))
            {
                CopiarPropriedadesPaciente(paciente, pacienteCompleto);
                _logger.LogInformation("[Async] Paciente ID {Id} sincronizado com dados completos do repositório", paciente.Id);
            }

            return paciente;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro async ao obter dados completos do paciente ID {Id}", paciente.Id);
            return paciente;
        }
    }

    private static void CopiarPropriedadesPaciente(Paciente destino, Paciente origem)
    {
        var propriedades = typeof(Paciente)
            .GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.CanWrite);

        foreach (var propriedade in propriedades)
        {
            try
            {
                var valor = propriedade.GetValue(origem);
                propriedade.SetValue(destino, valor);
            }
            catch
            {
                // Ignorar propriedades que não podem ser copiadas (ex: somente leitura ou proxy EF)
            }
        }
    }

    private void LogDadosPaciente(Paciente paciente)
    {
        _logger.LogWarning("🔍 DADOS RECEBIDOS DA BASE DE DADOS:");
        _logger.LogWarning("ID: {Id}", paciente.Id);
        _logger.LogWarning("Nome: '{Nome}'", paciente.Nome ?? "NULL");
        _logger.LogWarning("Email: '{Email}'", paciente.Email ?? "NULL");
        _logger.LogWarning("Telefone: '{Telefone}'", paciente.Telefone ?? "NULL");
        _logger.LogWarning("DataNascimento: {DataNascimento}", paciente.DataNascimento?.ToString("dd/MM/yyyy") ?? "NULL");
        _logger.LogWarning("Genero: '{Genero}'", paciente.Genero ?? "NULL");
        _logger.LogWarning("EstadoCivil: '{EstadoCivil}'", paciente.EstadoCivil ?? "NULL");
        _logger.LogWarning("Profissao: '{Profissao}'", paciente.Profissao ?? "NULL");
        _logger.LogWarning("NIF: '{NIF}'", paciente.NIF ?? "NULL");
        _logger.LogWarning("Morada: '{Morada}'", paciente.Morada ?? "NULL");
    }

    /// <summary>
    /// Valida o formulário antes de gravar usando FluentValidation
    /// </summary>
    private async Task<bool> ValidarFormularioAsync()
    {
        if (string.IsNullOrWhiteSpace(Nome))
        {
            await _notificationService.ShowWarningAsync("Nome é obrigatório");
            _logger.LogWarning("Tentativa de gravar paciente sem nome");
            return false;
        }

        if (DataNascimento == null)
        {
            await _notificationService.ShowWarningAsync("Data de nascimento é obrigatória");
            _logger.LogWarning("Tentativa de gravar paciente sem data de nascimento");
            return false;
        }

        if (DataNascimento >= DateTime.Today)
        {
            await _notificationService.ShowWarningAsync("Data de nascimento não pode ser futura");
            _logger.LogWarning("Tentativa de gravar paciente com data de nascimento futura");
            return false;
        }

        if (DataNascimento < DateTime.Today.AddYears(-120))
        {
            await _notificationService.ShowWarningAsync("Data de nascimento não pode ser superior a 120 anos");
            _logger.LogWarning("Tentativa de gravar paciente com idade superior a 120 anos");
            return false;
        }

        return true;
    }

    /// <summary>
    /// Método de validação simples mantido para compatibilidade
    /// </summary>
    private bool ValidarFormulario()
    {
        if (string.IsNullOrWhiteSpace(Nome))
        {
            _logger.LogWarning("Tentativa de gravar paciente sem nome");
            return false;
        }

        if (DataNascimento == null)
        {
            _logger.LogWarning("Tentativa de gravar paciente sem data de nascimento");
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
    /// Métodos de cálculo de idade removidos conforme solicitado
    /// </summary>

    /// <summary>
    /// Marca o formulário como alterado quando propriedades mudam
    /// </summary>
    partial void OnNomeChanged(string value) => MarkAsDirtyAndTriggerAutoSave();
    partial void OnEmailChanged(string value) => MarkAsDirtyAndTriggerAutoSave();
    partial void OnTelefoneChanged(string value) => MarkAsDirtyAndTriggerAutoSave();
    
    /// <summary>
    /// Handler chamado quando a data de nascimento muda
    /// </summary>
    partial void OnDataNascimentoChanged(DateTime? value)
    {
        MarkAsDirtyAndTriggerAutoSave();
        OnPropertyChanged(nameof(IdadeCalculada));
    }

    partial void OnPacienteAtualChanged(Paciente? value)
    {
        // Propriedades de idade removidas conforme solicitado
        
        // Se temos um paciente ativo, marcar como edição
        IsEdicao = value != null;
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
        // Verificar se auto-save está habilitado nas configurações (sem usar o setter para evitar recursão)
        var autoSaveEnabled = _settingsService.AutoSaveEnabled;
        
        if (!autoSaveEnabled)
        {
            _logger.LogInformation("Auto-save desabilitado nas configurações");
            return;
        }

        // Configurar função de save
        _autoSaveService.SetSaveFunction(async paciente => await SalvarPacienteInternoAsync(paciente));
        
        // Configurar debounce usando as configurações
        var intervalSeconds = _settingsService.AutoSaveIntervalSeconds;
        _autoSaveService.SetDebounceTime(TimeSpan.FromSeconds(intervalSeconds));

        // Subscrever aos eventos do auto-save
        _autoSaveService.AutoSaveExecuted += OnAutoSaveExecuted;
        _autoSaveService.AutoSaveError += OnAutoSaveError;

        // Iniciar monitoramento
        _autoSaveService.StartMonitoring();
        
        _logger.LogInformation("Auto-save configurado: intervalo {Interval}s", intervalSeconds);
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
        // CORREÇÃO: Usar padrão fire-and-forget mais seguro
        _ = ExecuteWithErrorHandlingAsync(async () => 
            await _notificationService.ShowSuccessAsync("Dados guardados automaticamente")
        );
        IsDirty = false;
    }

    /// <summary>
    /// Handler para falha do auto-save
    /// </summary>
    private void OnAutoSaveError(object? sender, AutoSaveErrorEventArgs<Paciente> e)
    {
        var errorMsg = e.Exception?.Message ?? "Erro desconhecido";
        // CORREÇÃO: Usar padrão fire-and-forget mais seguro
        _ = ExecuteWithErrorHandlingAsync(async () => 
            await _notificationService.ShowWarningAsync($"Falha no auto-save: {errorMsg}", durationMs: 0)
        );
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

        // Desinscrever eventos do auto-save
        _autoSaveService.AutoSaveExecuted -= OnAutoSaveExecuted;
        _autoSaveService.AutoSaveError -= OnAutoSaveError;

        // Desinscrever evento do PacienteService
        _pacienteService.PacienteAtivoChanged -= OnPacienteAtivoChanged;

        _logger.LogInformation("FichaPacienteViewModel recursos liberados");
    }

    private void OnPacienteAtivoChanged(object? sender, Paciente? paciente)
    {
        try
        {
            _logger.LogInformation("🔄 Evento PacienteAtivoChanged recebido");
            
            if (paciente != null)
            {
                _logger.LogInformation($"📋 Novo paciente ativo: {paciente.Nome} (ID: {paciente.Id})");
                CarregarPaciente(paciente);
            }
            else
            {
                _logger.LogInformation("📋 Limpando formulário");
                LimparFormulario();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro no handler PacienteAtivoChanged");
            // Não re-throw - evita crash
        }
    }
}