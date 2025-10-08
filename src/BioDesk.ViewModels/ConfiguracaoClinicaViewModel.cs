using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.ViewModels.Base;
using BioDesk.ViewModels.Validators;

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
    private readonly IConfiguration _configuration;
    private ConfiguracaoClinica? _configuracaoOriginal; // Para guardar logo antigo

    #region === PROPRIEDADES - DADOS DA CLÍNICA ===

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

    #endregion

    #region === PROPRIEDADES - CONFIGURAÇÕES SMTP ===

    [ObservableProperty]
    private string _smtpHost = "smtp.gmail.com";

    [ObservableProperty]
    private int _smtpPort = 587;

    [ObservableProperty]
    private string? _smtpFromEmail;

    [ObservableProperty]
    private string? _smtpPassword;

    [ObservableProperty]
    private string? _smtpFromName;

    [ObservableProperty]
    private string? _testeSucessoMessage;

    #endregion

    #region === PROPRIEDADES - UI STATE ===

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
        IConfiguration configuration,
        ILogger<ConfiguracaoClinicaViewModel> logger)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
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

    [RelayCommand]
    private async Task TestarConexao()
    {
        await TestarConexaoSmtpAsync();
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
                _configuracaoOriginal = null;
            }
            else
            {
                NomeClinica = config.NomeClinica;
                Morada = config.Morada;
                Telefone = config.Telefone;
                Email = config.Email;
                Nipc = config.NIPC;
                LogoPath = config.LogoPath;

                // ✅ GUARDAR REFERÊNCIA para apagar logo antigo
                _configuracaoOriginal = config;

                _logger.LogInformation("✅ Configuração carregada: {Nome}", config.NomeClinica);
            }

            // ✅ CARREGAR CONFIGURAÇÕES SMTP do appsettings.json
            SmtpHost = _configuration["Email:SmtpHost"] ?? "smtp.gmail.com";
            SmtpPort = int.TryParse(_configuration["Email:SmtpPort"], out var port) ? port : 587;
            SmtpFromEmail = _configuration["Email:FromEmail"];
            SmtpFromName = _configuration["Email:FromName"] ?? "BioDeskPro - Clínica";
            // Nota: Password não é carregado por segurança (apenas gravado)

            _logger.LogInformation("✅ Configurações SMTP carregadas");
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

            // 🔍 CONSTRUIR ENTIDADE para validação
            var configuracaoParaValidar = new ConfiguracaoClinica
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

            // ✅ VALIDAR COM FLUENTVALIDATION
            var validator = new ConfiguracaoClinicaValidator();
            var resultado = await validator.ValidateAsync(configuracaoParaValidar);

            if (!resultado.IsValid)
            {
                ErrorMessage = string.Join("\n", resultado.Errors.Select(e => e.ErrorMessage));
                _logger.LogWarning("⚠️ Validação falhou: {Erros}", ErrorMessage);
                return;
            }

            // Buscar configuração existente ou criar nova
            var config = await _unitOfWork.ConfiguracaoClinica.GetByIdAsync(1);

            if (config == null)
            {
                // Criar nova configuração
                await _unitOfWork.ConfiguracaoClinica.AddAsync(configuracaoParaValidar);
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

            // ✅ SALVAR CONFIGURAÇÕES SMTP no appsettings.json
            await SalvarConfiguracoesSmtpAsync();

            // Disparar evento de sucesso
            ConfiguracaoSalvaComSucesso?.Invoke(this, EventArgs.Empty);

        }, "Guardar configuração", _logger);

        IsLoading = false;
    }

    /// <summary>
    /// Abre diálogo para selecionar logo e copiar para Templates/
    /// </summary>
    private async Task SelecionarLogoAsync()
    {
        try
        {
            _logger.LogInformation("🖼️ Abrindo diálogo para selecionar logo...");

            // Criar OpenFileDialog
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Selecionar Logo da Clínica",
                Filter = "Imagens (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp|Todos os ficheiros (*.*)|*.*",
                FilterIndex = 1,
                Multiselect = false
            };

            if (dialog.ShowDialog() == true)
            {
                var filePath = dialog.FileName;
                _logger.LogInformation("📁 Ficheiro selecionado: {Path}", filePath);

                // 1️⃣ VALIDAR TAMANHO (máx 2MB)
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 2 * 1024 * 1024)
                {
                    ErrorMessage = "❌ Ficheiro muito grande! Tamanho máximo: 2MB";
                    _logger.LogWarning("⚠️ Ficheiro muito grande: {Size} KB", fileInfo.Length / 1024);
                    return;
                }

                _logger.LogInformation("✅ Tamanho válido: {Size} KB", fileInfo.Length / 1024);

                // 2️⃣ COPIAR para Templates/ com nome único
                var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
                var extension = fileInfo.Extension;
                var novoNome = $"logo_{timestamp}{extension}";
                var templatesPath = Path.Combine(
                    BioDesk.Services.PathService.AppDataPath,
                    "Templates"
                );
                var destinoPath = Path.Combine(templatesPath, novoNome);

                // Garantir que pasta Templates/ existe
                Directory.CreateDirectory(templatesPath);

                // Copiar ficheiro
                await Task.Run(() => File.Copy(filePath, destinoPath, overwrite: true));

                _logger.LogInformation("📂 Logo copiado para: {Destino}", destinoPath);

                // 3️⃣ ATUALIZAR LogoPath (caminho relativo para BD)
                LogoPath = $"Templates/{novoNome}";

                // 4️⃣ APAGAR logo antigo (se existir e for diferente do novo)
                if (!string.IsNullOrEmpty(_configuracaoOriginal?.LogoPath) &&
                    _configuracaoOriginal.LogoPath != LogoPath)
                {
                    try
                    {
                        var logoAntigoPath = Path.Combine(
                            BioDesk.Services.PathService.AppDataPath,
                            _configuracaoOriginal.LogoPath
                        );

                        if (File.Exists(logoAntigoPath))
                        {
                            File.Delete(logoAntigoPath);
                            _logger.LogInformation("🗑️ Logo antigo apagado: {Path}", logoAntigoPath);
                        }
                    }
                    catch (Exception exDelete)
                    {
                        _logger.LogWarning(exDelete, "⚠️ Não foi possível apagar logo antigo");
                        // Não bloquear operação se não conseguir apagar
                    }
                }

                _logger.LogInformation("✅ Logo selecionado com sucesso: {Path}", LogoPath);
                ErrorMessage = "✅ Logo carregado com sucesso!";
            }
            else
            {
                _logger.LogInformation("ℹ️ Seleção de logo cancelada pelo utilizador");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao selecionar logo");
            ErrorMessage = $"❌ Erro ao copiar logo: {ex.Message}";
        }
    }

    /// <summary>
    /// Salva as configurações SMTP no appsettings.json
    /// </summary>
    private async Task SalvarConfiguracoesSmtpAsync()
    {
        try
        {
            _logger.LogInformation("💾 Salvando configurações SMTP no appsettings.json...");

            var appSettingsPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");

            if (!File.Exists(appSettingsPath))
            {
                _logger.LogWarning("⚠️ Arquivo appsettings.json não encontrado em: {Path}", appSettingsPath);
                return;
            }

            // Ler conteúdo atual
            var json = await File.ReadAllTextAsync(appSettingsPath);
            var settings = System.Text.Json.JsonDocument.Parse(json);

            // Criar dicionário mutável para manter todas as secções existentes
            var settingsDict = new Dictionary<string, object>();

            // Copiar todas as secções existentes (Logging, etc.)
            foreach (var property in settings.RootElement.EnumerateObject())
            {
                if (property.Name != "Email") // Vamos substituir Email
                {
                    settingsDict[property.Name] = System.Text.Json.JsonSerializer.Deserialize<object>(property.Value.GetRawText());
                }
            }

            // Adicionar/atualizar secção Email com novos valores
            settingsDict["Email"] = new Dictionary<string, object>
            {
                ["SmtpHost"] = SmtpHost,
                ["SmtpPort"] = SmtpPort,
                ["Sender"] = SmtpFromEmail ?? "",
                ["Password"] = SmtpPassword ?? "",
                ["FromEmail"] = SmtpFromEmail ?? "",
                ["FromName"] = SmtpFromName ?? "BioDeskPro - Clínica"
            };

            // Serializar de volta para JSON
            var options = new System.Text.Json.JsonSerializerOptions
            {
                WriteIndented = true
            };
            var updatedJson = System.Text.Json.JsonSerializer.Serialize(settingsDict, options);

            // Salvar arquivo
            await File.WriteAllTextAsync(appSettingsPath, updatedJson);

            _logger.LogInformation("✅ Configurações SMTP salvas com sucesso");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao salvar configurações SMTP");
            ErrorMessage = $"Erro ao salvar configurações de email: {ex.Message}";
        }
    }

    /// <summary>
    /// Testa a conexão SMTP enviando um email de teste
    /// </summary>
    private async Task TestarConexaoSmtpAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            ErrorMessage = null;
            TesteSucessoMessage = null;

            _logger.LogInformation("🔌 Testando conexão SMTP...");

            // Validar campos obrigatórios
            if (string.IsNullOrWhiteSpace(SmtpHost))
            {
                ErrorMessage = "❌ Servidor SMTP é obrigatório";
                return;
            }

            if (string.IsNullOrWhiteSpace(SmtpFromEmail))
            {
                ErrorMessage = "❌ Email de envio é obrigatório";
                return;
            }

            if (string.IsNullOrWhiteSpace(SmtpPassword))
            {
                ErrorMessage = "❌ Senha é obrigatória";
                return;
            }

            // Salvar temporariamente as configurações para teste
            await SalvarConfiguracoesSmtpAsync();

            // Tentar enviar email de teste usando System.Net.Mail
            try
            {
                using var smtpClient = new System.Net.Mail.SmtpClient(SmtpHost, SmtpPort)
                {
                    Credentials = new System.Net.NetworkCredential(SmtpFromEmail, SmtpPassword),
                    EnableSsl = true
                };

                var mailMessage = new System.Net.Mail.MailMessage
                {
                    From = new System.Net.Mail.MailAddress(SmtpFromEmail ?? "", SmtpFromName ?? "BioDeskPro"),
                    Subject = "🔌 Teste de Conexão SMTP - BioDeskPro",
                    Body = $"Este é um email de teste enviado em {DateTime.Now:dd/MM/yyyy HH:mm:ss}.\n\n✅ Se recebeu este email, a configuração SMTP está correta!",
                    IsBodyHtml = false
                };

                mailMessage.To.Add(SmtpFromEmail ?? ""); // Enviar para si próprio

                await smtpClient.SendMailAsync(mailMessage);

                TesteSucessoMessage = "✅ Email de teste enviado com sucesso! Verifique a sua caixa de entrada.";
                _logger.LogInformation("✅ Conexão SMTP testada com sucesso");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Erro ao testar conexão SMTP");
                ErrorMessage = $"❌ Falha no teste: {ex.Message}";
            }

        }, "Testar conexão SMTP", _logger);

        IsLoading = false;
    }

    #endregion
}
