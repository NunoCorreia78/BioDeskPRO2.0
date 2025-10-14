using System;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using BioDesk.Services;
using BioDesk.Services.Backup;
using BioDesk.Services.Email;
using BioDesk.ViewModels.Templates;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace BioDesk.ViewModels;

public partial class ConfiguracoesViewModel : ObservableObject
{
    private readonly IConfiguration _configuration;
    private readonly IEmailService _emailService;
    private readonly ILogger<ConfiguracoesViewModel> _logger;

    [ObservableProperty]
    private string _emailRemetente = string.Empty;

    [ObservableProperty]
    private string _emailPassword = string.Empty;

    [ObservableProperty]
    private string _nomeRemetente = "BioDeskPro - Terapias Naturais";

    [ObservableProperty]
    private bool _mostrarStatus = false;

    [ObservableProperty]
    private string _statusMensagem = string.Empty;

    [ObservableProperty]
    private string _statusIcon = string.Empty;

    [ObservableProperty]
    private Brush _statusBackground = Brushes.Transparent;

    [ObservableProperty]
    private Brush _statusBorder = Brushes.Transparent;

    [ObservableProperty]
    private Brush _statusForeground = Brushes.Black;

    // === BACKUPS ===
    [ObservableProperty]
    private ObservableCollection<BackupMetadata> _backupsDisponiveis = new();

    [ObservableProperty]
    private string _ultimoBackupInfo = string.Empty;

    [ObservableProperty]
    private bool _temBackups = false;

    private readonly IBackupService? _backupService;

    /// <summary>
    /// ViewModel para gestão de templates globais (usado no Tab "Templates & Documentos")
    /// </summary>
    public TemplatesGlobalViewModel TemplatesGlobalViewModel { get; }

    public ConfiguracoesViewModel(
        IConfiguration configuration,
        IEmailService emailService,
        TemplatesGlobalViewModel templatesGlobalViewModel,
        ILogger<ConfiguracoesViewModel> logger,
        IBackupService? backupService = null) // Opcional para não quebrar DI existente
    {
        _configuration = configuration;
        _emailService = emailService;
        TemplatesGlobalViewModel = templatesGlobalViewModel;
        _logger = logger;
        _backupService = backupService;
    }

    public async Task CarregarConfiguracoesAsync()
    {
        try
        {
            // Carregar configurações existentes
            EmailRemetente = _configuration["Email:Sender"] ?? string.Empty;
            EmailPassword = _configuration["Email:Password"] ?? string.Empty;
            NomeRemetente = _configuration["Email:SenderName"] ?? "BioDeskPro - Terapias Naturais";

            // Carregar lista de backups
            await AtualizarListaBackupsAsync();

            _logger.LogInformation("Configurações carregadas com sucesso");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar configurações");
            MostrarStatus = false;
        }
    }

    [RelayCommand]
    private async Task GuardarConfiguracoesAsync()
    {
        try
        {
            // Validação
            if (string.IsNullOrWhiteSpace(EmailRemetente))
            {
                MostrarErro("Por favor, insira o email de envio");
                return;
            }

            if (string.IsNullOrWhiteSpace(EmailPassword))
            {
                MostrarErro("Por favor, insira a App Password do Gmail");
                return;
            }

            if (!EmailRemetente.Contains("@"))
            {
                MostrarErro("Email inválido. Use o formato: exemplo@gmail.com");
                return;
            }

            // Guardar usando User Secrets do .NET
            await GuardarUserSecretsAsync();

            MostrarSucesso("✅ Configurações guardadas com segurança!");
            _logger.LogInformation("Configurações de email guardadas com sucesso");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao guardar configurações");
            MostrarErro($"Erro ao guardar: {ex.Message}");
        }
    }

    [RelayCommand]
    private async Task TestarConexaoAsync()
    {
        try
        {
            if (string.IsNullOrWhiteSpace(EmailRemetente) || string.IsNullOrWhiteSpace(EmailPassword))
            {
                MostrarErro("Por favor, preencha email e password antes de testar");
                return;
            }

            MostrarInfo("🔄 A enviar email de teste para " + EmailRemetente + "...");

            // TESTAR DIRETAMENTE SEM GRAVAR (TestarConexaoAsync passa credenciais ao EmailService)
            var resultado = await _emailService.TestarConexaoAsync(
                smtpUsername: EmailRemetente,
                smtpPassword: EmailPassword,
                fromEmail: EmailRemetente,
                fromName: NomeRemetente ?? "BioDeskPro"
            );

            if (resultado.Sucesso)
            {
                MostrarSucesso($"✅ Email de teste enviado com sucesso para {EmailRemetente}! Verifique a sua caixa de entrada.");
                _logger.LogInformation("✅ Teste de conexão de email bem-sucedido");
            }
            else
            {
                MostrarErro(resultado.Mensagem ?? "Erro desconhecido ao enviar email");
                _logger.LogError("❌ Teste de email falhou: {Mensagem}", resultado.Mensagem);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao testar conexão de email");
            MostrarErro($"❌ Erro ao testar: {ex.Message}\n\nVerifique se:\n• App Password está correto\n• Email é Gmail\n• Tem conexão à internet");
        }
    }

    private async Task GuardarUserSecretsAsync()
    {
        // Guardar diretamente no IConfiguration (usado pelo EmailService)
        // NOTA: User Secrets são lidos automaticamente em Development
        // Para produção, usar variáveis de ambiente ou cofre seguro

        try
        {
            // Obter caminho do projeto BioDesk.App corretamente
            // AppDomain.BaseDirectory aponta para bin/Debug/net8.0-windows/
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var appProjectPath = System.IO.Path.GetFullPath(System.IO.Path.Combine(baseDir, "..", "..", ".."));

            _logger.LogInformation($"🔍 Tentando gravar User Secrets no projeto: {appProjectPath}");

            var secretsCommands = new[]
            {
                ("Email:Sender", EmailRemetente),
                ("Email:Password", EmailPassword),
                ("Email:SenderName", NomeRemetente)
            };

            foreach (var (key, value) in secretsCommands)
            {
                var processInfo = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = "dotnet",
                    Arguments = $"user-secrets set \"{key}\" \"{value}\" --project \"{appProjectPath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = appProjectPath // ✅ CRITICAL: Define working directory
                };

                _logger.LogInformation($"🔧 Executando: dotnet user-secrets set \"{key}\" \"***\" --project \"{appProjectPath}\"");

                using var process = System.Diagnostics.Process.Start(processInfo);
                if (process != null)
                {
                    await process.WaitForExitAsync();

                    var output = await process.StandardOutput.ReadToEndAsync();
                    var error = await process.StandardError.ReadToEndAsync();

                    if (process.ExitCode != 0)
                    {
                        _logger.LogError($"❌ Erro ao guardar {key}. Exit code: {process.ExitCode}\nStdErr: {error}\nStdOut: {output}");
                        throw new Exception($"Erro ao guardar {key}: {error}");
                    }
                    else
                    {
                        _logger.LogInformation($"✅ {key} guardado com sucesso");
                    }
                }
            }

            _logger.LogInformation("✅ User secrets guardados com sucesso via dotnet CLI");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao executar dotnet user-secrets");
            throw;
        }
    }

    private void MostrarSucesso(string mensagem)
    {
        StatusMensagem = mensagem;
        StatusIcon = "✅";
        StatusBackground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#D1FAE5"));
        StatusBorder = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#6EE7B7"));
        StatusForeground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#065F46"));
        MostrarStatus = true;
    }

    private void MostrarErro(string mensagem)
    {
        StatusMensagem = mensagem;
        StatusIcon = "❌";
        StatusBackground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FEE2E2"));
        StatusBorder = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FCA5A5"));
        StatusForeground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#991B1B"));
        MostrarStatus = true;
    }

    private void MostrarInfo(string mensagem)
    {
        StatusMensagem = mensagem;
        StatusIcon = "ℹ️";
        StatusBackground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#DBEAFE"));
        StatusBorder = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#93C5FD"));
        StatusForeground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1E40AF"));
        MostrarStatus = true;
    }

    [RelayCommand]
    private void AdicionarNovoTemplatePdf()
    {
        try
        {
            var dialog = new OpenFileDialog
            {
                Title = "Selecionar Template PDF",
                Filter = "Ficheiros PDF (*.pdf)|*.pdf",
                Multiselect = false
            };

            var resultado = dialog.ShowDialog();
            if (resultado is not true)
            {
                _logger.LogInformation("Importação de template PDF cancelada pelo utilizador.");
                return;
            }

            // ✅ USAR PathService.TemplatesPath (funciona em qualquer PC/instalação)
            var templatesDirectory = PathService.TemplatesPath;
            Directory.CreateDirectory(templatesDirectory);

            var ficheiroOrigem = dialog.FileName;
            var nomeFicheiro = Path.GetFileName(ficheiroOrigem);
            if (string.IsNullOrWhiteSpace(nomeFicheiro))
            {
                _logger.LogWarning("Nome de ficheiro inválido ao importar template PDF.");
                MostrarErro("Não foi possível determinar o nome do ficheiro selecionado.");
                return;
            }

            var destino = Path.Combine(templatesDirectory, nomeFicheiro);
            var substituido = File.Exists(destino);

            File.Copy(ficheiroOrigem, destino, overwrite: true);

            var mensagemSucesso = substituido
                ? $"✅ Template '{nomeFicheiro}' atualizado com sucesso!\n📂 Localização: {destino}"
                : $"✅ Template '{nomeFicheiro}' adicionado com sucesso!\n📂 Localização: {destino}";

            MostrarSucesso(mensagemSucesso);
            MessageBox.Show(mensagemSucesso, "Templates PDF", MessageBoxButton.OK, MessageBoxImage.Information);
            _logger.LogInformation("Template PDF importado para {Destino}", destino);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao adicionar template PDF");
            MostrarErro($"Erro ao adicionar template: {ex.Message}");
            MessageBox.Show($"Erro ao adicionar template: {ex.Message}", "Templates PDF", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    #region Backup Commands

    [RelayCommand]
    private async Task CriarBackupAsync()
    {
        if (_backupService == null)
        {
            MessageBox.Show("⚠️ Serviço de backup não disponível.", "Backup", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            MostrarInfo("💾 Criando backup...");

            var result = await _backupService.CreateBackupAsync(
                incluirDocumentos: true,
                incluirTemplates: true);

            if (result.Sucesso)
            {
                MostrarSucesso($"✅ Backup criado com sucesso!\n📦 {result.NumeroFicheiros} ficheiros | {result.TamanhoFormatado}");
                MessageBox.Show(
                    $"✅ Backup criado com sucesso!\n\n" +
                    $"📂 Ficheiro: {Path.GetFileName(result.CaminhoZip)}\n" +
                    $"💾 Tamanho: {result.TamanhoFormatado}\n" +
                    $"📦 Ficheiros: {result.NumeroFicheiros}\n" +
                    $"⏱️ Duração: {result.Duracao.TotalSeconds:N2}s",
                    "Backup Criado",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                await AtualizarListaBackupsAsync();
            }
            else
            {
                MostrarErro($"❌ Erro ao criar backup: {result.Erro}");
                MessageBox.Show($"❌ Erro ao criar backup:\n\n{result.Erro}", "Backup", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao criar backup");
            MostrarErro($"❌ Erro inesperado: {ex.Message}");
            MessageBox.Show($"❌ Erro ao criar backup:\n\n{ex.Message}", "Backup", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task RestaurarBackupAsync()
    {
        if (_backupService == null)
        {
            MessageBox.Show("⚠️ Serviço de backup não disponível.", "Restaurar Backup", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Aviso crítico
        var confirmacao = MessageBox.Show(
            "⚠️ ATENÇÃO!\n\n" +
            "Restaurar um backup irá SUBSTITUIR todos os dados atuais da base de dados.\n" +
            "Esta operação NÃO PODE SER DESFEITA!\n\n" +
            "Um backup de segurança será criado automaticamente antes do restore.\n\n" +
            "Tem a certeza que deseja continuar?",
            "⚠️ Restaurar Backup - Confirmação",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);

        if (confirmacao != MessageBoxResult.Yes)
        {
            _logger.LogInformation("Restauração de backup cancelada pelo utilizador");
            return;
        }

        try
        {
            // Selecionar ficheiro ZIP
            var dialog = new OpenFileDialog
            {
                Title = "Selecionar Backup para Restaurar",
                Filter = "Ficheiros ZIP (*.zip)|*.zip|Todos os ficheiros (*.*)|*.*",
                InitialDirectory = PathService.BackupsPath,
                Multiselect = false
            };

            if (dialog.ShowDialog() != true)
            {
                _logger.LogInformation("Seleção de backup cancelada");
                return;
            }

            var backupPath = dialog.FileName;
            MostrarInfo($"📥 Restaurando backup: {Path.GetFileName(backupPath)}...");

            var result = await _backupService.RestoreBackupAsync(backupPath, validarIntegridade: true);

            if (result.Sucesso)
            {
                MostrarSucesso($"✅ Backup restaurado com sucesso! {result.FicheirosRestaurados} ficheiros restaurados.");

                var resposta = MessageBox.Show(
                    $"✅ Backup restaurado com sucesso!\n\n" +
                    $"📂 Ficheiros restaurados: {result.FicheirosRestaurados}\n" +
                    $"⏱️ Duração: {result.Duracao.TotalSeconds:N2}s\n\n" +
                    $"⚠️ É ALTAMENTE RECOMENDADO reiniciar a aplicação agora.\n\n" +
                    $"Deseja reiniciar agora?",
                    "Backup Restaurado",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Question);

                if (resposta == MessageBoxResult.Yes)
                {
                    Application.Current.Shutdown();
                    // TODO: Reiniciar aplicação (System.Diagnostics.Process.Start)
                }
            }
            else
            {
                MostrarErro($"❌ Erro ao restaurar backup: {result.Erro}");
                MessageBox.Show($"❌ Erro ao restaurar backup:\n\n{result.Erro}", "Restaurar Backup", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao restaurar backup");
            MostrarErro($"❌ Erro inesperado: {ex.Message}");
            MessageBox.Show($"❌ Erro ao restaurar backup:\n\n{ex.Message}", "Restaurar Backup", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    [RelayCommand]
    private async Task AtualizarListaBackupsAsync()
    {
        if (_backupService == null)
            return;

        try
        {
            var backups = await _backupService.ListBackupsAsync();

            BackupsDisponiveis.Clear();
            foreach (var backup in backups)
            {
                BackupsDisponiveis.Add(backup);
            }

            TemBackups = BackupsDisponiveis.Count > 0;

            if (TemBackups)
            {
                var maisRecente = BackupsDisponiveis.First();
                UltimoBackupInfo = $"Último backup: {maisRecente.DataFormatada} ({maisRecente.TamanhoFormatado})";
            }
            else
            {
                UltimoBackupInfo = "Nenhum backup disponível";
            }

            _logger.LogInformation("Lista de backups atualizada: {Count} encontrados", backups.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao listar backups");
            UltimoBackupInfo = "Erro ao carregar backups";
        }
    }

    #endregion
    [RelayCommand]
    private void AbrirPastaBackups()
    {
        try
        {
            var pasta = BioDesk.Services.PathService.BackupsPath;
            if (!Directory.Exists(pasta))
            {
                Directory.CreateDirectory(pasta);
            }
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo()
            {
                FileName = pasta,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao abrir pasta de backups");
            MessageBox.Show($"Erro ao abrir pasta de backups:\n\n{ex.Message}", "Backups", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }
}
