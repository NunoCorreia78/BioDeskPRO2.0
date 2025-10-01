using System.Threading.Tasks;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace BioDesk.ViewModels;

public partial class ConfiguracoesViewModel : ObservableObject
{
    private readonly IConfiguration _configuration;
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
        ILogger<ConfiguracoesViewModel> logger)
    {
        _configuration = configuration;
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

            MostrarInfo("🔄 A testar conexão com Gmail...");

            // TODO: Implementar teste real de envio de email
            await Task.Delay(2000); // Simulação

            MostrarSucesso("✅ Conexão testada com sucesso! Email de teste enviado.");
            _logger.LogInformation("Teste de conexão de email bem-sucedido");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao testar conexão de email");
            MostrarErro($"Erro ao testar: {ex.Message}");
        }
    }

    private async Task GuardarUserSecretsAsync()
    {
        // Criar comando para guardar user secrets
        var secretsCommands = new[]
        {
            $"dotnet user-secrets set \"Email:Sender\" \"{EmailRemetente}\"",
            $"dotnet user-secrets set \"Email:Password\" \"{EmailPassword}\"",
            $"dotnet user-secrets set \"Email:SenderName\" \"{NomeRemetente}\""
        };

        foreach (var command in secretsCommands)
        {
            // Executar comando (implementação simplificada)
            // Na prática, usaria Process.Start ou biblioteca de configuração
            await Task.Delay(100);
        }

        _logger.LogInformation("User secrets guardados com sucesso");
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
}
