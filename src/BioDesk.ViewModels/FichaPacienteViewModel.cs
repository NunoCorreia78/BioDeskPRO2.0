using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.ViewModels.Base;
using BioDesk.Services.Navigation;
using BioDesk.Domain.Entities;
using System.Linq;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para ficha completa de paciente com navegação por separadores
/// Implementa sistema de 6 abas com validação progressiva
/// </summary>
public partial class FichaPacienteViewModel : NavigationViewModelBase, IDisposable
{
    private readonly ILogger<FichaPacienteViewModel> _logger;
    private bool _disposed = false;

    public FichaPacienteViewModel(
        INavigationService navigationService,
        ILogger<FichaPacienteViewModel> logger)
        : base(navigationService)
    {
        _logger = logger;

        _logger.LogInformation("🔍 FichaPacienteViewModel - INICIANDO construtor...");

        try
        {
            _logger.LogInformation("🔍 FichaPacienteViewModel - Inicializando dados de exemplo...");
            // Inicializar dados de exemplo
            InicializarDadosExemplo();

            _logger.LogInformation("🔍 FichaPacienteViewModel - Configurando auto-save...");
            // Configurar auto-save
            ConfigurarAutoSave();

            _logger.LogInformation("🔍 FichaPacienteViewModel - Atualizando progresso...");
            // Inicializar estado das abas
            AtualizarProgresso();

            _logger.LogInformation("✅ FichaPacienteViewModel - Construtor concluído com sucesso!");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "💥 ERRO no construtor FichaPacienteViewModel: {Message}", ex.Message);
            throw;
        }
    }

    #region Propriedades do Paciente

    [ObservableProperty]
    private string _nomePaciente = string.Empty;

    [ObservableProperty]
    private string _numeroProcesso = string.Empty;

    [ObservableProperty]
    private string _idadePaciente = string.Empty;

    [ObservableProperty]
    private string _estadoRegisto = "Incompleto";

    [ObservableProperty]
    private DateTime _dataCriacao = DateTime.Now;

    [ObservableProperty]
    private string _estadoCorHex = "#9CAF97"; // Cor como string para binding

    #endregion

    #region Auto-Save System - RESTAURADO

    [ObservableProperty]
    private bool _isDirty = false;

    [ObservableProperty]
    private DateTime? _ultimoSave;

    [ObservableProperty]
    private bool _autoSaveHabilitado = true;

    [ObservableProperty]
    private string _statusAutoSave = "Pronto";

    private System.Timers.Timer? _autoSaveTimer;
    private const int AUTO_SAVE_INTERVAL_MS = 30000; // 30 segundos

    #endregion

    #region Navegação entre Abas

    [ObservableProperty]
    private int _abaAtiva = 1;

    [ObservableProperty]
    private string _percentagemProgresso = "1/6 etapas completas (17%)";

    [ObservableProperty]
    private double _progressoNumerico = 17.0;

    [ObservableProperty]
    private bool _podeAvancarAba = true;

    [ObservableProperty]
    private object? _conteudoAbaAtiva;

    #endregion

    #region Estados

    [ObservableProperty]
    private bool _isLoading = false;

    #endregion

    #region Dados do Paciente

    [ObservableProperty]
    private BioDesk.Domain.Entities.Paciente _pacienteAtual = new();

    [ObservableProperty]
    private BioDesk.Domain.Entities.Contacto _contactoAtual = new();

    #endregion

    #region Controlo de Progresso das Abas

    /// <summary>
    /// Controla quais abas foram completadas
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<bool> _abasCompletadas = new() { false, false, false, false, false, false };

    #endregion

    #region Commands - Auto-Save

    [RelayCommand]
    private async Task GuardarRascunho()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            StatusAutoSave = "Guardando rascunho...";

            await GuardarAutoSave();

            StatusAutoSave = "Rascunho guardado";
            MostrarNotificacaoAutoSave("💾 Rascunho guardado com sucesso!");

            await Task.Delay(2000);
            StatusAutoSave = "Pronto";
        });
    }

    #endregion

    #region Commands - Navegação de Abas

    [RelayCommand]
    private void NavegarParaAba(object parameter)
    {
        if (parameter is string abaStr && int.TryParse(abaStr, out int numeroAba))
        {
            if (numeroAba >= 1 && numeroAba <= 6)
            {
                AbaAtiva = numeroAba;
                AtualizarProgresso();
                _logger.LogInformation("Navegação para aba {NumeroAba}", numeroAba);
            }
        }
    }

    [RelayCommand]
    private void ProximaAba()
    {
        if (AbaAtiva < 6)
        {
            // Marcar aba atual como completada
            AbasCompletadas[AbaAtiva - 1] = true;

            AbaAtiva++;
            AtualizarProgresso();
            AtualizarCorEstado();

            _logger.LogInformation("Avançou para aba {NumeroAba}", AbaAtiva);
        }
    }

    [RelayCommand]
    private void AbaAnterior()
    {
        if (AbaAtiva > 1)
        {
            AbaAtiva--;
            AtualizarProgresso();
            _logger.LogInformation("Retrocedeu para aba {NumeroAba}", AbaAtiva);
        }
        else
        {
            // Se estiver na primeira aba, volta ao Dashboard
            _logger.LogInformation("Voltando ao Dashboard da primeira aba");
            NavigationService.NavigateTo("Dashboard");
        }
    }

    #endregion

    #region Commands - Navegação Principal

    [RelayCommand]
    private async Task VoltarDashboard()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (IsDirty)
            {
                // Aqui iria mostrar diálogo de confirmação
                await GuardarAutoSave();
            }

            NavigationService.NavigateTo("Dashboard");
        });
    }

    [RelayCommand]
    private async Task GuardarCompleto()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;

            // Simular guardar completo
            await Task.Delay(1500);

            // Marcar todas as abas como completadas
            for (int i = 0; i < AbasCompletadas.Count; i++)
            {
                AbasCompletadas[i] = true;
            }

            EstadoRegisto = "Completo";
            EstadoCorHex = "#4CAF50"; // Verde para completo
            UltimoSave = DateTime.Now;
            IsDirty = false;

            AtualizarProgresso();
            MostrarNotificacaoAutoSave("✅ Ficha guardada com sucesso!");

            _logger.LogInformation("Ficha de paciente guardada completamente");
        });
    }

    #endregion

    #region Métodos Auto-Save

    private void ConfigurarAutoSave()
    {
        if (AutoSaveHabilitado)
        {
            _autoSaveTimer = new System.Timers.Timer(AUTO_SAVE_INTERVAL_MS);
            _autoSaveTimer.Elapsed += async (sender, e) => await GuardarAutoSave();
            _autoSaveTimer.AutoReset = true;
            _autoSaveTimer.Start();

            _logger.LogInformation("Auto-save configurado com intervalo de {Intervalo}ms", AUTO_SAVE_INTERVAL_MS);
        }
    }

    private async Task GuardarAutoSave()
    {
        if (!IsDirty || !AutoSaveHabilitado) return;

        try
        {
            StatusAutoSave = "Guardando automaticamente...";

            // Simular gravação
            await Task.Delay(500);

            UltimoSave = DateTime.Now;
            IsDirty = false;
            StatusAutoSave = "Gravação automática concluída";

            // Resetar status após 3 segundos
            await Task.Delay(3000);
            if (StatusAutoSave == "Gravação automática concluída")
            {
                StatusAutoSave = "Pronto";
            }

            _logger.LogDebug("Auto-save executado com sucesso");
        }
        catch (Exception ex)
        {
            StatusAutoSave = "Erro na gravação automática";
            _logger.LogError(ex, "Erro durante auto-save");
        }
    }

    private void MostrarNotificacaoAutoSave(string mensagem)
    {
        // Em implementação futura: mostrar toast notification
        _logger.LogInformation("Notificação: {Mensagem}", mensagem);
    }

    #endregion

    #region Métodos de Progresso

    private void AtualizarProgresso()
    {
        int abasCompletas = AbasCompletadas.Count(c => c);
        double percentagem = (double)abasCompletas / 6 * 100;

        PercentagemProgresso = $"{abasCompletas}/6 etapas completas ({percentagem:F0}%)";
        ProgressoNumerico = percentagem;

        // Controlar navegação
        PodeAvancarAba = AbaAtiva < 6;
    }

    private void AtualizarCorEstado()
    {
        EstadoCorHex = EstadoRegisto switch
        {
            "Completo" => "#4CAF50",    // Verde
            "Em Progresso" => "#FF9800", // Laranja
            _ => "#9CAF97"               // Verde pastel padrão
        };
    }

    #endregion

    #region Inicialização

    private void InicializarDadosExemplo()
    {
        // ✅ Inicializar PacienteAtual com dados de exemplo
        PacienteAtual = new BioDesk.Domain.Entities.Paciente
        {
            Id = 1,
            NumeroProcesso = "P2024001",
            NomeCompleto = "João Silva Santos",
            DataNascimento = new DateTime(1985, 3, 15),
            Genero = "Masculino",
            NIF = "123456789",
            Nacionalidade = "Portuguesa",
            EstadoCivil = "Casado(a)",
            Profissao = "Engenheiro",
            DataCriacao = DateTime.Now.AddDays(-15),
            EstadoRegisto = "Em Progresso"
        };

        // ✅ Inicializar ContactoAtual com dados de exemplo
        ContactoAtual = new BioDesk.Domain.Entities.Contacto
        {
            Id = 1,
            PacienteId = 1,
            RuaAvenida = "Rua das Flores",
            Numero = "123",
            CodigoPostal = "1000-001",
            Localidade = "Lisboa",
            TelefonePrincipal = "912345678",
            EmailPrincipal = "joao.santos@email.com"
        };

        // Simular algumas abas já completadas
        AbasCompletadas[0] = true; // Aba 1 - Dados Biográficos
        AbasCompletadas[1] = true; // Aba 2 - Declaração

        AtualizarCorEstado();
        AtualizarProgresso();

        _logger.LogInformation("Dados de exemplo inicializados: PacienteAtual e ContactoAtual");
    }

    #endregion

    #region Dispose Pattern

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _autoSaveTimer?.Stop();
            _autoSaveTimer?.Dispose();
            _autoSaveTimer = null;

            _logger.LogInformation("FichaPacienteViewModel disposed");
        }
        _disposed = true;
    }

    #endregion
}
