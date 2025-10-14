using System;
using System.Collections.Generic;
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
using BioDesk.ViewModels.Documentos;
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
    /// ViewModel para gestão de documentos externos do paciente.
    /// </summary>
    public DocumentosExternosViewModel DocumentosExternosViewModel { get; }

    /// <summary>
    /// ⭐ Flag para evitar marcar IsDirty durante carregamento de dados da BD
    /// </summary>
    private bool _isLoadingData = false;

    public FichaPacienteViewModel(
        INavigationService navigationService,
        ILogger<FichaPacienteViewModel> logger,
        IUnitOfWork unitOfWork,
        ICacheService cache,
        DocumentosExternosViewModel documentosExternosViewModel)
        : base(navigationService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
        DocumentosExternosViewModel = documentosExternosViewModel ?? throw new ArgumentNullException(nameof(documentosExternosViewModel));

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
                InicializarNovoPaciente();
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

    /// <summary>
    /// Aba ativa (1-8). Auto-save quando muda para restaurar ao reabrir paciente.
    /// </summary>
    [ObservableProperty]
    private int _abaAtiva = 1;

    partial void OnAbaAtivaChanged(int value)
    {
        _logger.LogInformation("🔄 ABA MUDOU: Aba ativa agora é {NovaAba}", value);
        AtualizarProgresso();

        // ✅ Persistir última aba ativa automaticamente (só se paciente já foi salvo)
        if (!_isLoadingData && PacienteAtual != null && PacienteAtual.Id > 0)
        {
            Task.Run(async () =>
            {
                try
                {
                    var paciente = await _unitOfWork.Pacientes.GetCompleteByIdAsync(PacienteAtual.Id);
                    if (paciente != null)
                    {
                        paciente.LastActiveTab = value;
                        _unitOfWork.Pacientes.Update(paciente);
                        await _unitOfWork.SaveChangesAsync();
                        _logger.LogDebug("💾 Aba {Aba} salva para paciente {Id}", value, PacienteAtual.Id);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "⚠️ Erro ao salvar LastActiveTab");
                }
            });
        }
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
        // ✅ VALIDAÇÃO EM TEMPO REAL (sempre, mesmo durante loading)
        if (e.PropertyName == nameof(Paciente.NomeCompleto) && PacienteAtual != null)
        {
            ValidarNomeCompleto(PacienteAtual.NomeCompleto);
        }
        else if (e.PropertyName == nameof(Paciente.DataNascimento) && PacienteAtual != null)
        {
            ValidarDataNascimento(PacienteAtual.DataNascimento);
        }
        else if (e.PropertyName == nameof(Paciente.NIF) && PacienteAtual != null)
        {
            ValidarNIF(PacienteAtual.NIF);
        }

        // ⚠️ Ignorar mudanças de IsDirty durante carregamento de dados da BD
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
        // ✅ VALIDAÇÃO EM TEMPO REAL (sempre, mesmo durante loading)
        if (e.PropertyName == nameof(Contacto.EmailPrincipal) && ContactoAtual != null)
        {
            ValidarEmail(ContactoAtual.EmailPrincipal);
        }
        else if (e.PropertyName == nameof(Contacto.TelefonePrincipal) && ContactoAtual != null)
        {
            ValidarTelefone(ContactoAtual.TelefonePrincipal);
        }

        // ⚠️ Ignorar mudanças de IsDirty durante carregamento de dados da BD
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

    #region Validação em Tempo Real

    // ===== PROPRIEDADES DE ERRO =====

    [ObservableProperty]
    private string? _erroEmail;

    [ObservableProperty]
    private string? _erroTelefonePrincipal;

    [ObservableProperty]
    private string? _erroNIF;

    [ObservableProperty]
    private string? _erroDataNascimento;

    [ObservableProperty]
    private string? _erroNomeCompleto;

    // ===== MÉTODOS DE VALIDAÇÃO =====

    /// <summary>
    /// Valida email em tempo real
    /// </summary>
    private void ValidarEmail(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            ErroEmail = null; // Campo vazio não é erro
            return;
        }

        // Validações progressivas
        if (!email.Contains("@"))
        {
            ErroEmail = "⚠️ Email deve conter @";
            return;
        }

        var parts = email.Split('@');
        if (parts.Length != 2 || string.IsNullOrWhiteSpace(parts[0]) || string.IsNullOrWhiteSpace(parts[1]))
        {
            ErroEmail = "⚠️ Email incompleto";
            return;
        }

        if (!parts[1].Contains("."))
        {
            ErroEmail = "⚠️ Domínio do email inválido";
            return;
        }

        // Email válido
        ErroEmail = null;
    }

    /// <summary>
    /// Valida telefone português (9 dígitos)
    /// </summary>
    private void ValidarTelefone(string? telefone)
    {
        if (string.IsNullOrWhiteSpace(telefone))
        {
            ErroTelefonePrincipal = null; // Campo vazio não é erro
            return;
        }

        // Remover espaços e caracteres especiais
        var digits = new string(telefone.Where(char.IsDigit).ToArray());

        if (digits.Length < 9)
        {
            ErroTelefonePrincipal = $"⚠️ Telefone deve ter 9 dígitos ({digits.Length}/9)";
            return;
        }

        if (digits.Length > 9)
        {
            ErroTelefonePrincipal = "⚠️ Telefone tem dígitos a mais";
            return;
        }

        // Validar prefixos válidos portugueses
        if (!digits.StartsWith("2") && !digits.StartsWith("9"))
        {
            ErroTelefonePrincipal = "⚠️ Número português deve começar por 2 ou 9";
            return;
        }

        // Telefone válido
        ErroTelefonePrincipal = null;
    }

    /// <summary>
    /// Valida NIF português (9 dígitos + algoritmo de verificação)
    /// </summary>
    private void ValidarNIF(string? nif)
    {
        if (string.IsNullOrWhiteSpace(nif))
        {
            ErroNIF = null; // Campo vazio não é erro
            return;
        }

        // Remover espaços
        nif = nif.Trim();

        // Validar comprimento
        if (nif.Length != 9)
        {
            ErroNIF = $"⚠️ NIF deve ter 9 dígitos ({nif.Length}/9)";
            return;
        }

        // Validar se são todos dígitos
        if (!nif.All(char.IsDigit))
        {
            ErroNIF = "⚠️ NIF deve conter apenas números";
            return;
        }

        // Algoritmo de validação do NIF português
        int checkDigit = int.Parse(nif[8].ToString());
        int sum = 0;

        for (int i = 0; i < 8; i++)
        {
            sum += int.Parse(nif[i].ToString()) * (9 - i);
        }

        int mod = sum % 11;
        int expectedCheckDigit = mod < 2 ? 0 : 11 - mod;

        if (checkDigit != expectedCheckDigit)
        {
            ErroNIF = "⚠️ NIF inválido (dígito de controlo incorreto)";
            return;
        }

        // NIF válido
        ErroNIF = null;
    }

    /// <summary>
    /// Valida data de nascimento (não pode ser futura nem ter mais de 120 anos)
    /// </summary>
    private void ValidarDataNascimento(DateTime? dataNascimento)
    {
        if (dataNascimento == null)
        {
            ErroDataNascimento = null;
            return;
        }

        var hoje = DateTime.Now;

        // Data no futuro
        if (dataNascimento > hoje)
        {
            ErroDataNascimento = "⚠️ Data não pode ser no futuro";
            return;
        }

        // Idade maior que 120 anos
        var idade = hoje.Year - dataNascimento.Value.Year;
        if (idade > 120)
        {
            ErroDataNascimento = "⚠️ Data muito antiga (idade > 120 anos)";
            return;
        }

        // Data válida
        ErroDataNascimento = null;
    }

    /// <summary>
    /// Valida nome completo (mínimo 3 caracteres)
    /// </summary>
    private void ValidarNomeCompleto(string? nome)
    {
        if (string.IsNullOrWhiteSpace(nome))
        {
            ErroNomeCompleto = "⚠️ Nome é obrigatório";
            return;
        }

        if (nome.Length < 3)
        {
            ErroNomeCompleto = $"⚠️ Nome muito curto ({nome.Length}/3 caracteres)";
            return;
        }

        // Nome válido
        ErroNomeCompleto = null;
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

            // ⭐ VALIDAÇÃO OBRIGATÓRIA ANTES DE GUARDAR
            var erros = new List<string>();

            if (string.IsNullOrWhiteSpace(PacienteAtual.NomeCompleto) || PacienteAtual.NomeCompleto.Trim().Length < 3)
                erros.Add("• Nome Completo (mínimo 3 caracteres)");

            if (!PacienteAtual.DataNascimento.HasValue || PacienteAtual.DataNascimento == DateTime.MinValue)
                erros.Add("• Data de Nascimento");

            if (!string.IsNullOrEmpty(ErroNIF))
                erros.Add("• NIF inválido");

            if (!string.IsNullOrEmpty(ErroTelefonePrincipal))
                erros.Add("• Telefone inválido");

            if (!string.IsNullOrEmpty(ErroEmail))
                erros.Add("• Email inválido");

            if (erros.Any())
            {
                ErrorMessage = "❌ Corrija os seguintes campos obrigatórios:\n" + string.Join("\n", erros);
                _logger.LogWarning("⚠️ Tentativa de guardar com {Count} erros de validação", erros.Count);
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
            if (numeroAba >= 1 && numeroAba <= 8)
            {
                // Inicializar DocumentosExternosViewModel quando navegar para aba 7
                if (numeroAba == 7 && PacienteAtual != null && PacienteAtual.Id > 0)
                {
                    _ = DocumentosExternosViewModel.InicializarParaPacienteAsync(PacienteAtual.Id);
                }

                AbaAtiva = numeroAba;
                AtualizarProgresso();
                _logger.LogInformation("📋 Navegação para aba {NumeroAba}", numeroAba);
            }
        }
    }

    [RelayCommand]
    private void ProximaAba()
    {
        if (AbaAtiva < 7)
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
                InicializarNovoPaciente(); // Fallback para novo
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

            // ✅ Restaurar última aba ativa (1-8, default = 1)
            AbaAtiva = paciente.LastActiveTab > 0 && paciente.LastActiveTab <= 8 ? paciente.LastActiveTab : 1;

            // TODO: Carregar estado das abas se estiver salvo em ProgressoAbas (JSON)
            AtualizarCorEstado();
            AtualizarProgresso();

            StatusSave = "Paciente carregado";
            _isLoadingData = false; // ⭐ Desativar flag após carregamento completo
            IsLoading = false;

            _logger.LogInformation("✅ Paciente {Nome} carregado com sucesso!", paciente.NomeCompleto);
        });
    }

    /// <summary>
    /// Inicializa estrutura para criação de NOVO paciente (Id = 0 para INSERT).
    /// NÃO é sample data - é inicialização legítima de novo registo vazio.
    /// </summary>
    private void InicializarNovoPaciente()
    {
        _isLoadingData = true; // ⭐ Ativar flag para evitar IsDirty durante inicialização

        // ✅ CRIAR NOVO PACIENTE (Id = 0 para INSERT na BD)
        PacienteAtual = new BioDesk.Domain.Entities.Paciente
        {
            Id = 0, // ⭐ 0 = NOVO (será auto-incrementado pela BD)
            NumeroProcesso = $"P{DateTime.Now:yyyyMMddHHmmss}", // Gerar número único
            NomeCompleto = "", // Vazio para preenchimento
            DataNascimento = null, // ⭐ NULL - Campo fica vazio até utilizador preencher
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
