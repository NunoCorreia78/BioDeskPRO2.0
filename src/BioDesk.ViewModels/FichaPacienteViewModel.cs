using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.ViewModels.Base;
using BioDesk.Services.Navigation;
using BioDesk.Services.Cache;
using BioDesk.Data.Repositories;
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
    private readonly IUnitOfWork _unitOfWork;
    private readonly ICacheService _cache;
    private bool _disposed = false;

    /// <summary>
    /// ⭐ Flag para evitar marcar IsDirty durante carregamento de dados da BD
    /// </summary>
    private bool _isLoadingData = false;

    public FichaPacienteViewModel(
        INavigationService navigationService,
        ILogger<FichaPacienteViewModel> logger,
        IUnitOfWork unitOfWork,
        ICacheService cache)
        : base(navigationService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));

        _logger.LogInformation("🔍 FichaPacienteViewModel - INICIANDO construtor...");

        try
        {
            // ✅ VERIFICAR SE HÁ PACIENTE ATIVO (vindo da Lista de Pacientes)
            var pacienteAtivo = PacienteService.Instance.GetPacienteAtivo();

            if (pacienteAtivo != null)
            {
                _logger.LogInformation("� Carregando paciente existente: {Nome} (ID {Id})",
                    pacienteAtivo.NomeCompleto, pacienteAtivo.Id);

                _ = CarregarPacienteAsync(pacienteAtivo.Id);
            }
            else
            {
                _logger.LogInformation("🔍 FichaPacienteViewModel - Inicializando NOVO paciente...");
                InicializarDadosExemplo();
            }

            _logger.LogInformation("🔍 FichaPacienteViewModel - Atualizando progresso...");
            // Inicializar estado das abas
            AtualizarProgresso();

            _logger.LogInformation("🔍 VALOR INICIAL: AbaAtiva = {AbaAtiva}", AbaAtiva);

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

    #region Sistema de Gravação Manual

    [ObservableProperty]
    private bool _isDirty = false;

    [ObservableProperty]
    private DateTime? _ultimoSave;

    [ObservableProperty]
    private string _statusSave = "Pronto";

    // Auto-save DESABILITADO - usar botão manual
    // private System.Timers.Timer? _autoSaveTimer;

    #endregion

    #region Navegação entre Abas

    [ObservableProperty]
    private int _abaAtiva = 1;

    partial void OnAbaAtivaChanged(int value)
    {
        _logger.LogInformation("🔄 ABA MUDOU: Aba ativa agora é {NovaAba}", value);
        AtualizarProgresso();
    }

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

    /// <summary>
    /// ⭐ CORREÇÃO CRÍTICA: Tracking automático de mudanças em PacienteAtual
    /// Subscrevemos ao PropertyChanged do paciente para marcar IsDirty
    /// </summary>
    partial void OnPacienteAtualChanged(BioDesk.Domain.Entities.Paciente? oldValue, BioDesk.Domain.Entities.Paciente newValue)
    {
        // Unsubscribe do paciente anterior (se existir)
        if (oldValue != null && oldValue is INotifyPropertyChanged oldNotify)
        {
            oldNotify.PropertyChanged -= OnPacientePropertyChanged;
        }

        // Subscribe ao novo paciente para detectar mudanças
        if (newValue != null && newValue is INotifyPropertyChanged newNotify)
        {
            newNotify.PropertyChanged += OnPacientePropertyChanged;
            _logger.LogDebug("🔔 Tracking ativado para PropertyChanged de PacienteAtual");
        }
    }

    /// <summary>
    /// ⭐ CORREÇÃO CRÍTICA: Tracking automático de mudanças em ContactoAtual
    /// </summary>
    partial void OnContactoAtualChanged(BioDesk.Domain.Entities.Contacto? oldValue, BioDesk.Domain.Entities.Contacto newValue)
    {
        // Unsubscribe do contacto anterior (se existir)
        if (oldValue != null && oldValue is INotifyPropertyChanged oldNotify)
        {
            oldNotify.PropertyChanged -= OnContactoPropertyChanged;
        }

        // Subscribe ao novo contacto para detectar mudanças
        if (newValue != null && newValue is INotifyPropertyChanged newNotify)
        {
            newNotify.PropertyChanged += OnContactoPropertyChanged;
            _logger.LogDebug("🔔 Tracking ativado para PropertyChanged de ContactoAtual");
        }
    }

    /// <summary>
    /// ⭐ Handler para mudanças nas propriedades do Paciente
    /// </summary>
    private void OnPacientePropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // ⚠️ Ignorar mudanças durante carregamento de dados da BD
        if (_isLoadingData) return;

        if (!IsDirty)
        {
            IsDirty = true;
            _logger.LogInformation("✏️ IsDirty ativado: Propriedade '{Property}' do Paciente foi alterada", e.PropertyName);
        }
    }

    /// <summary>
    /// ⭐ Handler para mudanças nas propriedades do Contacto
    /// </summary>
    private void OnContactoPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        // ⚠️ Ignorar mudanças durante carregamento de dados da BD
        if (_isLoadingData) return;

        if (!IsDirty)
        {
            IsDirty = true;
            _logger.LogInformation("✏️ IsDirty ativado: Propriedade '{Property}' do Contacto foi alterada", e.PropertyName);
        }
    }

    /// <summary>
    /// Método auxiliar para marcar formulário como alterado (dirty)
    /// Chamar sempre que o utilizador edita um campo
    /// </summary>
    public void MarcarComoAlterado()
    {
        IsDirty = true;
        _logger.LogDebug("Formulário marcado como alterado (IsDirty = true)");
    }

    #endregion

    #region Controlo de Progresso das Abas

    /// <summary>
    /// Controla quais abas foram completadas
    /// </summary>
    [ObservableProperty]
    private ObservableCollection<bool> _abasCompletadas = new() { false, false, false, false, false, false };

    #endregion

    #region Commands - Gravação Manual

    /// <summary>
    /// 💾 BOTÃO UNIVERSAL DE GRAVAÇÃO
    ///
    /// ESTADO ATUAL:
    /// ✅ Grava: Paciente (Aba 1) + Contacto (Aba 1)
    ///
    /// ROADMAP (Futuro):
    /// ⏳ Declaração Saúde (Aba 2) - Histórico médico, alergias, medicação
    /// ⏳ Consentimentos (Aba 3) - Assinaturas digitais, consentimentos
    /// ⏳ Registo Consultas (Aba 4) - Sessões, prescrições
    /// ⏳ Comunicação (Aba 5) - Histórico de e-mails, SMS
    ///
    /// NOTA: Os ViewModels das abas já capturam os dados via IsDirty.
    ///       A gravação será implementada quando tivermos as entidades
    ///       HistoricoMedico, Consentimento, Sessao, Comunicacao no banco.
    /// </summary>
    [RelayCommand]
    private async Task GuardarRascunho()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (PacienteAtual == null)
            {
                ErrorMessage = "❌ Nenhum paciente para guardar";
                return;
            }

            IsLoading = true;
            StatusSave = "Guardando...";
            _logger.LogInformation("💾 Guardando manualmente...");

            try
            {
                // ✅ GRAVAR PACIENTE
                if (PacienteAtual.Id == 0)
                {
                    await _unitOfWork.Pacientes.AddAsync(PacienteAtual);
                    await _unitOfWork.SaveChangesAsync(); // Obter ID
                    _logger.LogInformation("✅ Paciente novo ID {Id}", PacienteAtual.Id);
                }
                else
                {
                    PacienteAtual.DataUltimaAtualizacao = DateTime.Now;
                    _unitOfWork.Pacientes.Update(PacienteAtual);
                }

                // ✅ GRAVAR CONTACTO
                if (ContactoAtual != null)
                {
                    ContactoAtual.PacienteId = PacienteAtual.Id;
                    if (ContactoAtual.Id == 0)
                        await _unitOfWork.Contactos.AddAsync(ContactoAtual);
                    else
                        _unitOfWork.Contactos.Update(ContactoAtual);
                }

                // ✅ COMMIT FINAL
                await _unitOfWork.SaveChangesAsync();

                // ✅ INVALIDAR CACHE
                _cache.RemoveByPrefix(CacheKeys.PrefixDashboard);
                _cache.Remove("Dashboard:PacientesRecentes");

                UltimoSave = DateTime.Now;
                IsDirty = false;
                StatusSave = "Guardado com sucesso!";
                _logger.LogInformation("✅ Guardado com sucesso!");

                // Limpar status após 3s
                await Task.Delay(3000);
                StatusSave = "Pronto";
            }
            catch (Exception ex)
            {
                StatusSave = "Erro ao guardar";
                _logger.LogError(ex, "❌ Erro ao guardar: {Message}", ex.Message);
                ErrorMessage = $"Erro: {ex.Message}";
            }
            finally
            {
                IsLoading = false;
            }
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
                // 💬 DIÁLOGO DE CONFIRMAÇÃO
                var resultado = MessageBox.Show(
                    "Tem alterações não gravadas na ficha do paciente.\n\n" +
                    "Deseja guardar antes de sair?",
                    "⚠️ Alterações Pendentes",
                    MessageBoxButton.YesNoCancel,
                    MessageBoxImage.Question);

                if (resultado == MessageBoxResult.Yes)
                {
                    // Gravar e depois sair
                    await GuardarRascunho();
                }
                else if (resultado == MessageBoxResult.Cancel)
                {
                    // Não sair - cancelar navegação
                    return;
                }
                // Se for "Não" → continua e descarta alterações
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
            StatusSave = "Guardando na base de dados...";

            _logger.LogInformation("💾 Iniciando gravação de paciente na BD...");

            // ✅ GRAVAÇÃO REAL NA BD
            if (PacienteAtual != null)
            {
                try
                {
                    // Atualizar timestamps e estado
                    PacienteAtual.DataUltimaAtualizacao = DateTime.Now;
                    PacienteAtual.EstadoRegisto = "Completo";

                    if (PacienteAtual.Id == 0)
                    {
                        // ✅ NOVO PACIENTE - INSERT + SaveChanges para obter ID
                        _logger.LogInformation("📝 Criando novo paciente: {Nome}", PacienteAtual.NomeCompleto);
                        await _unitOfWork.Pacientes.AddAsync(PacienteAtual);
                        await _unitOfWork.SaveChangesAsync(); // ⭐ COMMIT PARA OBTER ID GERADO
                        _logger.LogInformation("✅ Paciente novo criado com ID {Id}", PacienteAtual.Id);
                    }
                    else
                    {
                        // ✅ ATUALIZAR EXISTENTE - UPDATE
                        _logger.LogInformation("✏️ Atualizando paciente ID {Id}: {Nome}", PacienteAtual.Id, PacienteAtual.NomeCompleto);
                        _unitOfWork.Pacientes.Update(PacienteAtual);
                    }

                    // Gravar contacto se existir (agora PacienteAtual.Id já está definido)
                    if (ContactoAtual != null)
                    {
                        ContactoAtual.PacienteId = PacienteAtual.Id;

                        if (ContactoAtual.Id == 0)
                        {
                            await _unitOfWork.Contactos.AddAsync(ContactoAtual);
                        }
                        else
                        {
                            _unitOfWork.Contactos.Update(ContactoAtual);
                        }
                    }

                    // ✅ COMMIT TRANSACTION
                    await _unitOfWork.SaveChangesAsync();

                    // ✅ INVALIDAR CACHE DO DASHBOARD
                    _cache.RemoveByPrefix(CacheKeys.PrefixDashboard);
                    _cache.Remove("Dashboard:PacientesRecentes");

                    _logger.LogInformation("✅ Paciente ID {Id} gravado com sucesso na BD!", PacienteAtual.Id);

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
                    MostrarNotificacaoAutoSave("✅ Ficha gravada na base de dados com sucesso!");
                    StatusSave = "Gravação concluída";

                    // Voltar imediatamente ao dashboard após gravação
                    NavigationService.NavigateTo("Dashboard");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "❌ Erro ao gravar paciente na BD");
                    StatusSave = "Erro na gravação";
                    throw;
                }
            }
            else
            {
                _logger.LogWarning("⚠️ PacienteAtual é null - não é possível gravar");
                StatusSave = "Erro: dados inválidos";
            }
        });
    }

    #endregion

    private void MostrarNotificacaoAutoSave(string mensagem)
    {
        // Em implementação futura: mostrar toast notification
        _logger.LogInformation("Notificação: {Mensagem}", mensagem);
    }

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

    /// <summary>
    /// Carregar paciente existente da BD para edição
    /// </summary>
    private async Task CarregarPacienteAsync(int pacienteId)
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            _isLoadingData = true; // ⭐ Ativar flag para evitar IsDirty durante carregamento
            StatusSave = "Carregando dados...";

            _logger.LogInformation("📂 Carregando paciente ID {Id} da BD...", pacienteId);

            // Carregar paciente completo com relacionamentos
            var paciente = await _unitOfWork.Pacientes.GetCompleteByIdAsync(pacienteId);

            if (paciente == null)
            {
                _logger.LogWarning("⚠️ Paciente ID {Id} não encontrado!", pacienteId);
                ErrorMessage = "Paciente não encontrado";
                InicializarDadosExemplo(); // Fallback para novo
                _isLoadingData = false; // ⭐ Desativar flag
                return;
            }

            // Definir paciente atual
            PacienteAtual = paciente;

            // Carregar contacto (se existir)
            ContactoAtual = paciente.Contacto ?? new BioDesk.Domain.Entities.Contacto
            {
                Id = 0,
                PacienteId = paciente.Id
            };

            // Atualizar propriedades da UI
            NomePaciente = paciente.NomeCompleto;
            NumeroProcesso = paciente.NumeroProcesso;
            IdadePaciente = $"{paciente.Idade} anos";
            EstadoRegisto = paciente.EstadoRegisto;

            // TODO: Carregar estado das abas se estiver salvo em ProgressoAbas (JSON)
            AtualizarCorEstado();
            AtualizarProgresso();

            StatusSave = "Paciente carregado";
            _isLoadingData = false; // ⭐ Desativar flag após carregamento completo
            IsLoading = false;

            _logger.LogInformation("✅ Paciente {Nome} carregado com sucesso!", paciente.NomeCompleto);
        });
    }

    private void InicializarDadosExemplo()
    {
        _isLoadingData = true; // ⭐ Ativar flag para evitar IsDirty durante inicialização

        // ✅ CRIAR NOVO PACIENTE (Id = 0 para INSERT na BD)
        PacienteAtual = new BioDesk.Domain.Entities.Paciente
        {
            Id = 0, // ⭐ 0 = NOVO (será auto-incrementado pela BD)
            NumeroProcesso = $"P{DateTime.Now:yyyyMMddHHmmss}", // Gerar número único
            NomeCompleto = "", // Vazio para preenchimento
            DataNascimento = DateTime.Today.AddYears(-30), // Default 30 anos
            Genero = "", // ⭐ VAZIO por defeito (utilizador escolhe)
            NIF = "",
            Nacionalidade = "Portuguesa",
            EstadoCivil = "Solteiro(a)",
            Profissao = "",
            DataCriacao = DateTime.Now,
            EstadoRegisto = "Em Progresso"
        };

        // ✅ Inicializar ContactoAtual (Id = 0 para INSERT)
        ContactoAtual = new BioDesk.Domain.Entities.Contacto
        {
            Id = 0, // ⭐ 0 = NOVO
            PacienteId = 0, // Será definido após gravar paciente
            RuaAvenida = "",
            Numero = "",
            CodigoPostal = "",
            Localidade = "",
            TelefonePrincipal = "",
            EmailPrincipal = ""
        };

        // Nenhuma aba completada (paciente novo)
        for (int i = 0; i < AbasCompletadas.Count; i++)
        {
            AbasCompletadas[i] = false;
        }

        AtualizarCorEstado();
        AtualizarProgresso();

        _isLoadingData = false; // ⭐ Desativar flag - agora mudanças serão detectadas!
        _logger.LogInformation("📝 Inicializado NOVO PACIENTE para criação (Id = 0) - Tracking ativado!");
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
            _unitOfWork?.Dispose();
            _logger.LogInformation("FichaPacienteViewModel disposed");
        }
        _disposed = true;
    }

    #endregion
}
