using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ConfiguracaoClinicaViewModel - ViewModel para configuração da clínica
/// Permite editar: Nome, Morada, Telefone, Email, NIPC, Logo
/// Singleton pattern: sempre carrega/salva ConfiguracaoClinica com Id=1
/// </summary>
public partial class ConfiguracaoClinicaViewModel : ViewModelBase
{
    private readonly ILogger<ConfiguracaoClinicaViewModel> _logger;
    private readonly IUnitOfWork _unitOfWork;

    #region === PROPRIEDADES ===

    [ObservableProperty]
    private string _nomeClinica = "Minha Clínica";

    [ObservableProperty]
    private string? _morada;

    [ObservableProperty]
    private string? _telefone;

    [ObservableProperty]
    private string? _email;

    [ObservableProperty]
    private string? _nipc;

    [ObservableProperty]
    private string? _logoPath;

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string? _errorMessage;

    #endregion

    #region === EVENTOS ===

    /// <summary>
    /// Evento disparado quando a configuração é salva com sucesso
    /// </summary>
    public event EventHandler? ConfiguracaoSalvaComSucesso;

    #endregion

    public ConfiguracaoClinicaViewModel(
        IUnitOfWork unitOfWork,
        ILogger<ConfiguracaoClinicaViewModel> logger)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        _logger.LogInformation("📋 ConfiguracaoClinicaViewModel inicializado");

        // Carregar configuração existente
        _ = CarregarConfiguracaoAsync();
    }

    #region === COMANDOS ===

    [RelayCommand]
    private async Task Guardar()
    {
        await GuardarAsync();
    }

    [RelayCommand]
    private async Task SelecionarLogo()
    {
        await SelecionarLogoAsync();
    }

    #endregion

    #region === MÉTODOS PRIVADOS ===

    /// <summary>
    /// Carrega a configuração da clínica (Id=1)
    /// Se não existir, cria com valores padrão
    /// </summary>
    private async Task CarregarConfiguracaoAsync()
    {
        try
        {
            _logger.LogInformation("📂 Carregando configuração da clínica...");

            var config = await _unitOfWork.ConfiguracaoClinica.GetByIdAsync(1);

            if (config == null)
            {
                _logger.LogWarning("⚠️ Configuração não encontrada, usando valores padrão");
                NomeClinica = "Minha Clínica";
                Morada = null;
                Telefone = null;
                Email = null;
                Nipc = null;
                LogoPath = null;
            }
            else
            {
                NomeClinica = config.NomeClinica;
                Morada = config.Morada;
                Telefone = config.Telefone;
                Email = config.Email;
                Nipc = config.NIPC;
                LogoPath = config.LogoPath;

                _logger.LogInformation("✅ Configuração carregada: {Nome}", config.NomeClinica);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao carregar configuração");
            ErrorMessage = $"Erro ao carregar configuração: {ex.Message}";
        }
    }

    /// <summary>
    /// Salva a configuração da clínica
    /// </summary>
    private async Task GuardarAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            ErrorMessage = null;

            _logger.LogInformation("💾 Guardando configuração da clínica...");

            // Validação básica
            if (string.IsNullOrWhiteSpace(NomeClinica))
            {
                ErrorMessage = "Nome da clínica é obrigatório";
                _logger.LogWarning("⚠️ Validação falhou: Nome da clínica vazio");
                return;
            }

            // Validação de email (se preenchido)
            if (!string.IsNullOrWhiteSpace(Email) && !IsValidEmail(Email))
            {
                ErrorMessage = "Email inválido";
                _logger.LogWarning("⚠️ Validação falhou: Email inválido");
                return;
            }

            // Buscar configuração existente ou criar nova
            var config = await _unitOfWork.ConfiguracaoClinica.GetByIdAsync(1);

            if (config == null)
            {
                // Criar nova configuração
                config = new ConfiguracaoClinica
                {
                    Id = 1,
                    NomeClinica = NomeClinica,
                    Morada = Morada,
                    Telefone = Telefone,
                    Email = Email,
                    NIPC = Nipc,
                    LogoPath = LogoPath,
                    DataAtualizacao = DateTime.UtcNow
                };

                await _unitOfWork.ConfiguracaoClinica.AddAsync(config);
                _logger.LogInformation("➕ Nova configuração criada");
            }
            else
            {
                // Atualizar configuração existente
                config.NomeClinica = NomeClinica;
                config.Morada = Morada;
                config.Telefone = Telefone;
                config.Email = Email;
                config.NIPC = Nipc;
                config.LogoPath = LogoPath;
                config.DataAtualizacao = DateTime.UtcNow;

                _unitOfWork.ConfiguracaoClinica.Update(config);
                _logger.LogInformation("🔄 Configuração existente atualizada");
            }

            // Salvar no banco de dados
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("✅ Configuração guardada com sucesso: {Nome}", NomeClinica);

            // Disparar evento de sucesso
            ConfiguracaoSalvaComSucesso?.Invoke(this, EventArgs.Empty);

        }, "Guardar configuração", _logger);

        IsLoading = false;
    }

    /// <summary>
    /// Abre diálogo para selecionar logo
    /// </summary>
    private async Task SelecionarLogoAsync()
    {
        await Task.Run(() =>
        {
            try
            {
                _logger.LogInformation("🖼️ Abrindo diálogo para selecionar logo...");

                // Criar OpenFileDialog
                var dialog = new Microsoft.Win32.OpenFileDialog
                {
                    Title = "Selecionar Logo da Clínica",
                    Filter = "Imagens (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg|Todos os ficheiros (*.*)|*.*",
                    FilterIndex = 1,
                    Multiselect = false
                };

                if (dialog.ShowDialog() == true)
                {
                    var filePath = dialog.FileName;
                    _logger.LogInformation("📁 Ficheiro selecionado: {Path}", filePath);

                    // Validar tamanho do ficheiro (máx 2MB)
                    var fileInfo = new FileInfo(filePath);
                    if (fileInfo.Length > 2 * 1024 * 1024)
                    {
                        ErrorMessage = "Ficheiro muito grande. Máximo: 2MB";
                        _logger.LogWarning("⚠️ Ficheiro muito grande: {Size} bytes", fileInfo.Length);
                        return;
                    }

                    // TODO: Copiar para pasta Templates/ usando PathService
                    // Por agora, usar o caminho original
                    LogoPath = filePath;

                    _logger.LogInformation("✅ Logo selecionado: {Path}", LogoPath);
                    ErrorMessage = null;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao selecionar logo");
                ErrorMessage = $"Erro ao selecionar logo: {ex.Message}";
            }
        });
    }

    /// <summary>
    /// Valida formato de email
    /// </summary>
    private bool IsValidEmail(string email)
    {
        try
        {
            var addr = new System.Net.Mail.MailAddress(email);
            return addr.Address == email;
        }
        catch
        {
            return false;
        }
    }

    #endregion
}
