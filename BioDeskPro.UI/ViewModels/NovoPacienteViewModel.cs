using System.ComponentModel.DataAnnotations;
using System.Windows.Input;
using BioDeskPro.UI.Services;
using BioDeskPro.UI.ViewModels;
using BioDeskPro.Core.Entities;
using BioDeskPro.Data.Contexts;
using BioDeskPro.Core.Interfaces;
using Microsoft.EntityFrameworkCore;
using static BioDeskPro.Core.Interfaces.IDialogService;

namespace BioDeskPro.UI.ViewModels;

public class NovoPacienteViewModel : BaseViewModel
{
    private readonly INavigationService _navigationService;
    private readonly IDialogService _dialogService;
    private readonly BioDeskContext _context;
    private readonly IPacienteContext _pacienteContext;

    private string _nome = string.Empty;
    private DateTime _dataNascimento = DateTime.Today.AddYears(-30);
    private string _genero = "Masculino";
    private string _nif = string.Empty;
    private string _email = string.Empty;
    private string _telefone = string.Empty;
    private string _morada = string.Empty;
    private string _observacoes = string.Empty;
    private bool _isGuardando = false;

    public NovoPacienteViewModel(
        INavigationService navigationService,
        IDialogService dialogService,
        BioDeskContext context,
        IPacienteContext pacienteContext)
    {
        _navigationService = navigationService;
        _dialogService = dialogService;
        _context = context;
        _pacienteContext = pacienteContext;

        InitializeCommands();
        InitializeData();
    }

    #region Properties

    [Required(ErrorMessage = "Nome é obrigatório")]
    [StringLength(100, ErrorMessage = "Nome deve ter no máximo 100 caracteres")]
    public string Nome
    {
        get => _nome;
        set
        {
            SetProperty(ref _nome, value);
            OnPropertyChanged(nameof(CanSalvar));
        }
    }

    public DateTime DataNascimento
    {
        get => _dataNascimento;
        set
        {
            SetProperty(ref _dataNascimento, value);
            OnPropertyChanged(nameof(Idade));
            OnPropertyChanged(nameof(CanSalvar));
        }
    }

    public int Idade => DateTime.Today.Year - DataNascimento.Year - 
                       (DateTime.Today.DayOfYear < DataNascimento.DayOfYear ? 1 : 0);

    public string Genero
    {
        get => _genero;
        set => SetProperty(ref _genero, value);
    }

    public string Nif
    {
        get => _nif;
        set => SetProperty(ref _nif, value);
    }

    public string Email
    {
        get => _email;
        set => SetProperty(ref _email, value);
    }

    public string Telefone
    {
        get => _telefone;
        set => SetProperty(ref _telefone, value);
    }

    public string Morada
    {
        get => _morada;
        set => SetProperty(ref _morada, value);
    }

    public string Observacoes
    {
        get => _observacoes;
        set => SetProperty(ref _observacoes, value);
    }

    public bool IsGuardando
    {
        get => _isGuardando;
        set
        {
            SetProperty(ref _isGuardando, value);
            OnPropertyChanged(nameof(CanSalvar));
            OnPropertyChanged(nameof(CanCancelar));
        }
    }

    public bool CanSalvar => !IsGuardando && !string.IsNullOrWhiteSpace(Nome) && 
                            DataNascimento <= DateTime.Today;

    public bool CanCancelar => !IsGuardando;

    public string[] GenerosDisponiveis { get; } = { "Masculino", "Feminino", "Outro" };

    #endregion

    #region Commands

    public ICommand SalvarCommand { get; private set; } = null!;
    public ICommand CancelarCommand { get; private set; } = null!;
    public ICommand LimparCommand { get; private set; } = null!;

    #endregion

    #region Methods

    private void InitializeCommands()
    {
        SalvarCommand = new RelayCommand(ExecuteSalvar, CanExecuteSalvar);
        CancelarCommand = new RelayCommand(ExecuteCancelar, CanExecuteCancelar);
        LimparCommand = new RelayCommand(ExecuteLimpar);
    }
    
    private bool CanExecuteSalvar() => CanSalvar;
    private bool CanExecuteCancelar() => CanCancelar;

    private void InitializeData()
    {
        // Valores padrão já definidos nos campos privados
    }

    private async void ExecuteSalvar()
    {
        if (!CanSalvar) return;

        IsGuardando = true;

        try
        {
            // Validação básica
            if (string.IsNullOrWhiteSpace(Nome))
            {
                _dialogService.ShowWarning("Nome é obrigatório.", "Validação");
                return;
            }

            // Verificar se documento de identidade já existe (se fornecido)
            if (!string.IsNullOrWhiteSpace(Nif))
            {
                var existingPaciente = await _context.Pacientes
                    .FirstOrDefaultAsync(p => p.DocumentoIdentidade == Nif);
                if (existingPaciente != null)
                {
                    _dialogService.ShowWarning("Já existe um paciente com este NIF.", "NIF Duplicado");
                    return;
                }
            }

            // Criar novo paciente
            var novoPaciente = new Paciente
            {
                Nome = Nome.Trim(),
                DataNascimento = DataNascimento,
                Sexo = Genero,
                DocumentoIdentidade = string.IsNullOrWhiteSpace(Nif) ? null : Nif.Trim(),
                Email = string.IsNullOrWhiteSpace(Email) ? null : Email.Trim(),
                Telemovel = string.IsNullOrWhiteSpace(Telefone) ? null : Telefone.Trim(),
                Morada = string.IsNullOrWhiteSpace(Morada) ? null : Morada.Trim(),
                Observacoes = string.IsNullOrWhiteSpace(Observacoes) ? null : Observacoes.Trim()
            };

            // Salvar na base de dados
            _context.Pacientes.Add(novoPaciente);
            await _context.SaveChangesAsync();

            // Sucesso
            _dialogService.ShowInfo($"Paciente '{Nome}' foi criado com sucesso!", "Paciente Criado");

            // Navegar para a ficha do novo paciente
            _pacienteContext.SetPacienteAtivo(novoPaciente);
            _navigationService.NavigateTo("FichaPaciente");
        }
        catch (Exception ex)
        {
            _dialogService.ShowError($"Erro ao criar paciente: {ex.Message}", "Erro");
        }
        finally
        {
            IsGuardando = false;
        }
    }

    private void ExecuteCancelar()
    {
        if (!CanCancelar) return;

        // Verificar se há alterações não salvas
        if (HasUnsavedChanges())
        {
            var result = _dialogService.ShowConfirmation(
                "Tem alterações não guardadas. Pretende sair sem guardar?",
                "Confirmar Cancelamento");

            if (result != DialogResult.Yes) return;
        }

        // Voltar à página anterior
        _navigationService.GoBack();
    }

    private void ExecuteLimpar()
    {
        Nome = string.Empty;
        DataNascimento = DateTime.Today.AddYears(-30);
        Genero = "Masculino";
        Nif = string.Empty;
        Email = string.Empty;
        Telefone = string.Empty;
        Morada = string.Empty;
        Observacoes = string.Empty;
    }

    private bool HasUnsavedChanges()
    {
        return !string.IsNullOrWhiteSpace(Nome) ||
               DataNascimento != DateTime.Today.AddYears(-30) ||
               Genero != "Masculino" ||
               !string.IsNullOrWhiteSpace(Nif) ||
               !string.IsNullOrWhiteSpace(Email) ||
               !string.IsNullOrWhiteSpace(Telefone) ||
               !string.IsNullOrWhiteSpace(Morada) ||
               !string.IsNullOrWhiteSpace(Observacoes);
    }

    #endregion
}