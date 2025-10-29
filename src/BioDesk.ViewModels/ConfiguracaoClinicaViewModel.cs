using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Windows;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.Win32;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Services;
using BioDesk.Services.Backup;
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
    private readonly IBackupService? _backupService;
    private readonly BioDesk.Services.Templates.ITemplatesPdfService? _templatesPdfService;
    private ConfiguracaoClinica? _configuracaoOriginal; // Para guardar logo antigo

    #region === PROPRIEDADES - DADOS DA CLÃNICA ===

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

    #region === PROPRIEDADES - CONFIGURAÃ‡Ã•ES SMTP ===

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

    [ObservableProperty]
    private ObservableCollection<BackupMetadata> _backupsDisponiveis = new();

    [ObservableProperty]
    private string _ultimoBackupInfo = string.Empty;

    [ObservableProperty]
    private bool _temBackups = false;

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
        ILogger<ConfiguracaoClinicaViewModel> logger,
        IBackupService backupService,
        BioDesk.Services.Templates.ITemplatesPdfService? templatesPdfService = null)
    {
        _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _backupService = backupService ?? throw new ArgumentNullException(nameof(backupService));
        _templatesPdfService = templatesPdfService; // opcional (para retrocompatibilidade)

        _logger.LogInformation("ðŸ“‹ ConfiguracaoClinicaViewModel inicializado");

        // Carregar configuração existente
        _ = CarregarConfiguracaoAsync();

        // Carregar lista de backups disponíveis
        _ = AtualizarListaBackupsAsync();
        // Carregar lista de templates PDF (se serviço disponível)
        if (_templatesPdfService != null)
        {
            _ = AtualizarListaTemplatesAsync();
        }
    }

    // Lista de templates PDF encontrados (para mostrar na UI de Configurações)
    [ObservableProperty]
    private System.Collections.ObjectModel.ObservableCollection<BioDesk.Services.Templates.TemplatePdf> _templatesPdf = new();

    private async Task AtualizarListaTemplatesAsync()
    {
        try
        {
            if (_templatesPdfService == null) return;
            var lista = await _templatesPdfService.ListarTemplatesAsync();
            TemplatesPdf.Clear();
            foreach (var t in lista) TemplatesPdf.Add(t);
            _logger.LogInformation("Templates PDF encontrados: {Count}", TemplatesPdf.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar templates PDF");
        }
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

    #region === MÃ‰TODOS PRIVADOS ===

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
                NomeClinica = "Minha ClÃ­nica";
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

                // âœ… GUARDAR REFERÃŠNCIA para apagar logo antigo
                _configuracaoOriginal = config;

                _logger.LogInformation("âœ… ConfiguraÃ§Ã£o carregada: {Nome}", config.NomeClinica);
            }

            // âœ… CARREGAR CONFIGURAÃ‡Ã•ES SMTP do appsettings.json
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
    /// Salva a configuraÃ§Ã£o da clÃ­nica
    /// </summary>
    private async Task GuardarAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;
            ErrorMessage = null;

            _logger.LogInformation("ðŸ’¾ Guardando configuraÃ§Ã£o da clÃ­nica...");

            // ðŸ” CONSTRUIR ENTIDADE para validaÃ§Ã£o
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

            // âœ… VALIDAR COM FLUENTVALIDATION
            var validator = new ConfiguracaoClinicaValidator();
            var resultado = await validator.ValidateAsync(configuracaoParaValidar);

            if (!resultado.IsValid)
            {
                ErrorMessage = string.Join("\n", resultado.Errors.Select(e => e.ErrorMessage));
                _logger.LogWarning("âš ï¸ ValidaÃ§Ã£o falhou: {Erros}", ErrorMessage);
                return;
            }

            // Buscar configuraÃ§Ã£o existente ou criar nova
            var config = await _unitOfWork.ConfiguracaoClinica.GetByIdAsync(1);

            if (config == null)
            {
                // Criar nova configuraÃ§Ã£o
                await _unitOfWork.ConfiguracaoClinica.AddAsync(configuracaoParaValidar);
                _logger.LogInformation("âž• Nova configuraÃ§Ã£o criada");
            }
            else
            {
                // Atualizar configuraÃ§Ã£o existente
                config.NomeClinica = NomeClinica;
                config.Morada = Morada;
                config.Telefone = Telefone;
                config.Email = Email;
                config.NIPC = Nipc;
                config.LogoPath = LogoPath;
                config.DataAtualizacao = DateTime.UtcNow;

                _unitOfWork.ConfiguracaoClinica.Update(config);
                _logger.LogInformation("ðŸ”„ ConfiguraÃ§Ã£o existente atualizada");
            }

            // Salvar no banco de dados
            await _unitOfWork.SaveChangesAsync();

            _logger.LogInformation("âœ… ConfiguraÃ§Ã£o guardada com sucesso: {Nome}", NomeClinica);

            // âœ… SALVAR CONFIGURAÃ‡Ã•ES SMTP no appsettings.json
            await SalvarConfiguracoesSmtpAsync();

            // Disparar evento de sucesso
            ConfiguracaoSalvaComSucesso?.Invoke(this, EventArgs.Empty);

        }, "Guardar configuraÃ§Ã£o", _logger);

        IsLoading = false;
    }

    /// <summary>
    /// Abre diÃ¡logo para selecionar logo e copiar para Templates/
    /// </summary>
    private async Task SelecionarLogoAsync()
    {
        try
        {
            _logger.LogInformation("ðŸ–¼ï¸ Abrindo diÃ¡logo para selecionar logo...");

            // Criar OpenFileDialog
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Selecionar Logo da ClÃ­nica",
                Filter = "Imagens (*.png;*.jpg;*.jpeg;*.bmp)|*.png;*.jpg;*.jpeg;*.bmp|Todos os ficheiros (*.*)|*.*",
                FilterIndex = 1,
                Multiselect = false
            };

            if (dialog.ShowDialog() == true)
            {
                var filePath = dialog.FileName;
                _logger.LogInformation("ðŸ“ Ficheiro selecionado: {Path}", filePath);

                // 1ï¸âƒ£ VALIDAR TAMANHO (mÃ¡x 2MB)
                var fileInfo = new FileInfo(filePath);
                if (fileInfo.Length > 2 * 1024 * 1024)
                {
                    ErrorMessage = "âŒ Ficheiro muito grande! Tamanho mÃ¡ximo: 2MB";
                    _logger.LogWarning("âš ï¸ Ficheiro muito grande: {Size} KB", fileInfo.Length / 1024);
                    return;
                }

                _logger.LogInformation("âœ… Tamanho vÃ¡lido: {Size} KB", fileInfo.Length / 1024);

                // 2ï¸âƒ£ COPIAR para Templates/ com nome Ãºnico
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

                _logger.LogInformation("ðŸ“‚ Logo copiado para: {Destino}", destinoPath);

                // 3ï¸âƒ£ ATUALIZAR LogoPath (caminho relativo para BD)
                LogoPath = $"Templates/{novoNome}";

                // 4ï¸âƒ£ APAGAR logo antigo (se existir e for diferente do novo)
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
                            _logger.LogInformation("ðŸ—‘ï¸ Logo antigo apagado: {Path}", logoAntigoPath);
                        }
                    }
                    catch (Exception exDelete)
                    {
                        _logger.LogWarning(exDelete, "âš ï¸ NÃ£o foi possÃ­vel apagar logo antigo");
                        // NÃ£o bloquear operaÃ§Ã£o se nÃ£o conseguir apagar
                    }
                }

                _logger.LogInformation("âœ… Logo selecionado com sucesso: {Path}", LogoPath);
                ErrorMessage = "âœ… Logo carregado com sucesso!";
            }
            else
            {
                _logger.LogInformation("â„¹ï¸ SeleÃ§Ã£o de logo cancelada pelo utilizador");
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "âŒ Erro ao selecionar logo");
            ErrorMessage = $"âŒ Erro ao copiar logo: {ex.Message}";
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
                _logger.LogWarning("âš ï¸ Arquivo appsettings.json nÃ£o encontrado em: {Path}", appSettingsPath);
                return;
            }

            // Ler conteÃºdo atual
            var json = await File.ReadAllTextAsync(appSettingsPath);
            using var settings = System.Text.Json.JsonDocument.Parse(json);

            // Criar dicionÃ¡rio mutÃ¡vel para manter todas as secÃ§Ãµes existentes
            var settingsDict = new Dictionary<string, object>();

            // Copiar todas as secÃ§Ãµes existentes (Logging, etc.)
            foreach (var property in settings.RootElement.EnumerateObject())
            {
                if (property.Name != "Email") // Vamos substituir Email
                {
                    settingsDict[property.Name] = property.Value.Clone();
                }
            }

            // Adicionar/atualizar secÃ§Ã£o Email com novos valores
            settingsDict["Email"] = new Dictionary<string, object>
            {
                ["SmtpHost"] = SmtpHost,
                ["SmtpPort"] = SmtpPort,
                ["Sender"] = SmtpFromEmail ?? "",
                ["Password"] = SmtpPassword ?? "",
                ["FromEmail"] = SmtpFromEmail ?? "",
                ["FromName"] = SmtpFromName ?? "BioDeskPro - ClÃ­nica"
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

            _logger.LogInformation("ðŸ”Œ Testando conexÃ£o SMTP...");

            // Validar campos obrigatÃ³rios
            if (string.IsNullOrWhiteSpace(SmtpHost))
            {
                ErrorMessage = "âŒ Servidor SMTP Ã© obrigatÃ³rio";
                return;
            }

            if (string.IsNullOrWhiteSpace(SmtpFromEmail))
            {
                ErrorMessage = "âŒ Email de envio Ã© obrigatÃ³rio";
                return;
            }

            if (string.IsNullOrWhiteSpace(SmtpPassword))
            {
                ErrorMessage = "âŒ Senha Ã© obrigatÃ³ria";
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
                    Subject = "ðŸ”Œ Teste de ConexÃ£o SMTP - BioDeskPro",
                    Body = $"Este Ã© um email de teste enviado em {DateTime.Now:dd/MM/yyyy HH:mm:ss}.\n\nâœ… Se recebeu este email, a configuraÃ§Ã£o SMTP estÃ¡ correta!",
                    IsBodyHtml = false
                };

                mailMessage.To.Add(SmtpFromEmail ?? ""); // Enviar para si prÃ³prio

                await smtpClient.SendMailAsync(mailMessage);

                TesteSucessoMessage = "âœ… Email de teste enviado com sucesso! Verifique a sua caixa de entrada.";
                _logger.LogInformation("âœ… ConexÃ£o SMTP testada com sucesso");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "âŒ Erro ao testar conexÃ£o SMTP");
                ErrorMessage = $"âŒ Falha no teste: {ex.Message}";
            }

        }, "Testar conexÃ£o SMTP", _logger);

        IsLoading = false;
    }

    #endregion

    #region === COMANDO: ADICIONAR TEMPLATE PDF ===

    /// <summary>
    /// Comando para adicionar novo template PDF para prescriÃ§Ãµes
    /// </summary>
    [RelayCommand]
    private void AdicionarTemplatePdf()
    {
        try
        {
            var dialog = new OpenFileDialog
            {
                Title = "Selecionar Template(s) PDF",
                Filter = "Ficheiros PDF (*.pdf)|*.pdf",
                Multiselect = true
            };

            var resultado = dialog.ShowDialog();
            if (resultado is not true)
            {
                _logger.LogInformation("ImportaÃ§Ã£o de template PDF cancelada pelo utilizador.");
                return;
            }

            var templatesDirectory = System.IO.Path.Combine(PathService.TemplatesPath, "PDFs");
            Directory.CreateDirectory(templatesDirectory);

            int adicionados = 0;
            int atualizados = 0;
            var ficheirosSelecionados = dialog.FileNames != null && dialog.FileNames.Length > 0
                ? dialog.FileNames
                : new[] { dialog.FileName };

            foreach (var ficheiroOrigem in ficheirosSelecionados)
            {
                var nomeFicheiro = Path.GetFileName(ficheiroOrigem);
                if (string.IsNullOrWhiteSpace(nomeFicheiro))
                {
                    _logger.LogWarning("Nome de ficheiro invÃ¡lido ao importar template PDF.");
                    continue;
                }

                var destino = Path.Combine(templatesDirectory, nomeFicheiro);
                var substituido = File.Exists(destino);

                File.Copy(ficheiroOrigem, destino, overwrite: true);

                if (substituido)
                    atualizados++;
                else
                    adicionados++;

                _logger.LogInformation("Template PDF importado para {Destino}", destino);
            }

            var mensagemSucesso = $"{adicionados} adicionado(s), {atualizados} atualizado(s).";
            TesteSucessoMessage = mensagemSucesso;
            MessageBox.Show(mensagemSucesso + "\n\nPasta: " + templatesDirectory, "Templates PDF", MessageBoxButton.OK, MessageBoxImage.Information);

            if (_templatesPdfService != null)
            {
                _ = AtualizarListaTemplatesAsync();
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao adicionar template PDF");
            ErrorMessage = $"Erro ao adicionar template: {ex.Message}";
            MessageBox.Show($"Erro ao adicionar template: {ex.Message}", "Templates PDF", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    #endregion

    #region === COMANDOS: BACKUP & RESTORE ===

    [RelayCommand]
    private async Task CriarBackupAsync()
    {
        if (_backupService == null)
        {
            MessageBox.Show("âš ï¸ ServiÃ§o de backup nÃ£o disponÃ­vel.", "Backup", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            IsLoading = true;
            var resultado = await _backupService.CreateBackupAsync(incluirDocumentos: true, incluirTemplates: true);

            if (resultado.Sucesso)
            {
                TesteSucessoMessage = $"Backup criado! {resultado.TamanhoFormatado}";
                MessageBox.Show(
                    $"Backup criado com sucesso!\n\nFicheiro: {Path.GetFileName(resultado.CaminhoZip)}\nTamanho: {resultado.TamanhoFormatado}\nTotal ficheiros: {resultado.NumeroFicheiros}",
                    "Backup", MessageBoxButton.OK, MessageBoxImage.Information);
                await AtualizarListaBackupsAsync();
            }
            else
            {
                ErrorMessage = $"âŒ Erro: {resultado.Erro}";
                MessageBox.Show($"âŒ Erro ao criar backup:\n\n{resultado.Erro}", "Backup", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao criar backup");
            ErrorMessage = $"âŒ Erro: {ex.Message}";
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private async Task RestaurarBackupAsync()
    {
        if (_backupService == null) return;

        var confirmacao = MessageBox.Show(
            "âš ï¸ ATENÃ‡ÃƒO!\n\nRestaurar um backup irÃ¡ SUBSTITUIR todos os dados atuais.\nUm backup de seguranÃ§a serÃ¡ criado antes.\n\nContinuar?",
            "Restaurar Backup", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);

        if (confirmacao != MessageBoxResult.Yes) return;

        try
        {
            var dialog = new OpenFileDialog
            {
                Title = "Selecionar Backup",
                Filter = "Ficheiros ZIP (*.zip)|*.zip",
                InitialDirectory = PathService.BackupsPath
            };

            if (dialog.ShowDialog() != true) return;

            IsLoading = true;
            var resultado = await _backupService.RestoreBackupAsync(dialog.FileName, validarIntegridade: true);

            if (resultado.Sucesso)
            {
                var mensagem = $"âœ… Backup restaurado com sucesso!\n\n" +
                               $"ðŸ“‚ Ficheiros restaurados: {resultado.FicheirosRestaurados}\n" +
                               $"â±ï¸ DuraÃ§Ã£o: {resultado.Duracao.TotalSeconds:N1}s\n\n" +
                               $"âš ï¸ IMPORTANTE:\n" +
                               $"A aplicaÃ§Ã£o PRECISA ser reiniciada agora!\n\n" +
                               $"Clique OK para fechar a aplicaÃ§Ã£o.";

                MessageBox.Show(mensagem, "Backup Restaurado", MessageBoxButton.OK, MessageBoxImage.Warning);

                // Fechar aplicaÃ§Ã£o apÃ³s restore
                System.Windows.Application.Current.Shutdown();
            }
            else
            {
                MessageBox.Show($"âŒ Erro ao restaurar backup:\n\n{resultado.Erro}",
                    "Restaurar Backup", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao restaurar backup");
            MessageBox.Show($"âŒ Erro: {ex.Message}", "Restaurar Backup", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }

    [RelayCommand]
    private void AbrirPastaBackups()
    {
        try
        {
            var pasta = PathService.BackupsPath;
            if (!Directory.Exists(pasta)) Directory.CreateDirectory(pasta);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = pasta,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao abrir pasta de backups");
            MessageBox.Show($"Erro: {ex.Message}", "Backups", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task AtualizarListaBackupsAsync()
    {
        if (_backupService == null) return;

        try
        {
            var backups = await _backupService.ListBackupsAsync();
            BackupsDisponiveis.Clear();
            foreach (var backup in backups) BackupsDisponiveis.Add(backup);
            TemBackups = BackupsDisponiveis.Count > 0;
            if (TemBackups)
            {
                var ultimo = BackupsDisponiveis.First();
                UltimoBackupInfo = $"Ãšltimo: {ultimo.DataFormatada} ({ultimo.TamanhoFormatado})";
            }
            else
            {
                UltimoBackupInfo = "Nenhum backup disponÃ­vel";
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao listar backups");
        }
    }

    #endregion
}
