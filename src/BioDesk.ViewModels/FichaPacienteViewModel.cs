using System;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.Domain.Entities;
using BioDesk.Services.Pacientes;
using BioDesk.Services.Navigation;
using BioDesk.ViewModels.Base;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para a ficha básica do paciente
/// Permite visualizar e editar dados básicos do paciente
/// </summary>
public partial class FichaPacienteViewModel : ViewModelBase
{
    private readonly IPacienteService _pacienteService;
    private readonly INavigationService _navigationService;
    private readonly ILogger<FichaPacienteViewModel> _logger;
    
    [ObservableProperty]
    private Paciente? _pacienteAtual;
    
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
    private DateTime _dataNascimento = DateTime.Today.AddYears(-30);

    public FichaPacienteViewModel(
        IPacienteService pacienteService,
        INavigationService navigationService,
        ILogger<FichaPacienteViewModel> logger)
    {
        _pacienteService = pacienteService;
        _navigationService = navigationService;
        _logger = logger;
        
        // Inicializar com paciente ativo se existir
        var pacienteAtivo = _pacienteService.GetPacienteAtivo();
        if (pacienteAtivo != null)
        {
            CarregarPaciente(pacienteAtivo);
        }
        else
        {
            LimparFormulario();
        }
    }

    /// <summary>
    /// Propriedade computada para mostrar a idade do paciente
    /// </summary>
    public string Idade => CalcularIdade(DataNascimento);

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
    /// Serviço de navegação (para uso nos bindings)
    /// </summary>
    public INavigationService NavigationService => _navigationService;

    [RelayCommand]
    private void Editar()
    {
        IsEdicao = true;
        _logger.LogInformation("Modo de edição ativado para paciente ID: {Id}", Id);
    }

    [RelayCommand]
    private async Task GravarAsync()
    {
        if (!ValidarFormulario())
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
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Erro ao gravar paciente");
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

    [RelayCommand]
    private void VoltarDashboard()
    {
        _navigationService.NavigateTo("Dashboard");
    }

    [RelayCommand]
    private void VoltarLista()
    {
        _navigationService.NavigateTo("ListaPacientes");
    }

    /// <summary>
    /// Carrega um paciente no formulário
    /// </summary>
    public void CarregarPaciente(Paciente paciente)
    {
        if (paciente == null) return;

        var isNovoPaciente = paciente.Id == 0;

        PacienteAtual = paciente;
        Nome = paciente.Nome ?? string.Empty;
        Email = paciente.Email ?? string.Empty;
        Telefone = paciente.Telefone ?? string.Empty;
        DataNascimento = paciente.DataNascimento == default
            ? DateTime.Today.AddYears(-30)
            : paciente.DataNascimento;
        
        IsEdicao = isNovoPaciente ? true : false;
        IsDirty = false;
        
        // Notificar propriedades computadas
        OnPropertyChanged(nameof(Id));
        OnPropertyChanged(nameof(CriadoEm));
        OnPropertyChanged(nameof(AtualizadoEm));
        OnPropertyChanged(nameof(Idade));
        
        if (isNovoPaciente)
        {
            _logger.LogInformation("Ficha preparada para novo paciente");
        }
        else
        {
            _logger.LogInformation("Paciente carregado: {Nome} (ID: {Id})", paciente.Nome, paciente.Id);
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
        DataNascimento = DateTime.Today.AddYears(-30);
        
        IsEdicao = true; // Novo paciente começa em modo de edição
        IsDirty = false;
        
        // Notificar propriedades computadas
        OnPropertyChanged(nameof(Id));
        OnPropertyChanged(nameof(CriadoEm));
        OnPropertyChanged(nameof(AtualizadoEm));
        OnPropertyChanged(nameof(Idade));
        
        _logger.LogInformation("Formulário limpo para novo paciente");
    }

    /// <summary>
    /// Valida o formulário antes de gravar
    /// </summary>
    private bool ValidarFormulario()
    {
        if (string.IsNullOrWhiteSpace(Nome))
        {
            _logger.LogWarning("Tentativa de gravar paciente sem nome");
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
    /// Calcula a idade baseada na data de nascimento
    /// </summary>
    private static string CalcularIdade(DateTime dataNascimento)
    {
        var hoje = DateTime.Today;
        var idade = hoje.Year - dataNascimento.Year;
        
        if (dataNascimento.Date > hoje.AddYears(-idade))
            idade--;
            
        return $"{idade} anos";
    }

    /// <summary>
    /// Marca o formulário como alterado quando propriedades mudam
    /// </summary>
    partial void OnNomeChanged(string value) => MarkAsDirty();
    partial void OnEmailChanged(string value) => MarkAsDirty();
    partial void OnTelefoneChanged(string value) => MarkAsDirty();
    partial void OnDataNascimentoChanged(DateTime value) 
    {
        MarkAsDirty();
        OnPropertyChanged(nameof(Idade));
    }

    private void MarkAsDirty()
    {
        if (IsEdicao) // Só marca como dirty se estiver em modo de edição
        {
            IsDirty = true;
        }
    }
}