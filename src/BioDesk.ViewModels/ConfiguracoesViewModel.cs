using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using BioDesk.Services.Email;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

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

    public ConfiguracoesViewModel(
        IConfiguration configuration,
        IEmailService emailService,
        ILogger<ConfiguracoesViewModel> logger)
    {
        _configuration = configuration;
        _emailService = emailService;
        _logger = logger;
    }

    public async Task CarregarConfiguracoesAsync()
    {
        try
        {
            // Carregar configurações existentes
            EmailRemetente = _configuration["Email:Sender"] ?? string.Empty;
            EmailPassword = _configuration["Email:Password"] ?? string.Empty;
            NomeRemetente = _configuration["Email:SenderName"] ?? "BioDeskPro - Terapias Naturais";

            _logger.LogInformation("Configurações carregadas com sucesso");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao carregar configurações");
            MostrarStatus = false;
        }

        await Task.CompletedTask;
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

    /// <summary>
    /// Adicionar novo template PDF para prescrições
    /// </summary>
    [RelayCommand]
    private async Task AdicionarNovoTemplatePdf()
    {
        try
        {
            // OpenFileDialog para selecionar PDF
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = "Selecionar Template PDF",
                Filter = "Ficheiros PDF (*.pdf)|*.pdf",
                Multiselect = false
            };

            if (dialog.ShowDialog() == true)
            {
                // Copiar para pasta Templates
                var templatesFolder = Path.Combine(
                    AppDomain.CurrentDomain.BaseDirectory, 
                    "Templates");
                
                Directory.CreateDirectory(templatesFolder);
                
                var fileName = Path.GetFileName(dialog.FileName);
                var destinationPath = Path.Combine(templatesFolder, fileName);
                
                // Verificar se já existe
                if (File.Exists(destinationPath))
                {
                    var result = MessageBox.Show(
                        $"Já existe um template com o nome '{fileName}'.\n\nDeseja substituir?",
                        "Template Existente",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Question);
                    
                    if (result != MessageBoxResult.Yes)
                    {
                        _logger.LogInformation("ℹ️ Utilizador cancelou substituição de template");
                        return;
                    }
                }
                
                File.Copy(dialog.FileName, destinationPath, overwrite: true);
                
                _logger.LogInformation("✅ Template PDF copiado: {FileName}", fileName);
                
                MessageBox.Show(
                    $"Template '{fileName}' adicionado com sucesso!\n\nPasta: {templatesFolder}",
                    "✅ Template Adicionado",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao adicionar template PDF");
            MessageBox.Show(
                $"Erro ao adicionar template:\n\n{ex.Message}",
                "❌ Erro",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        
        await Task.CompletedTask;
    }
}
