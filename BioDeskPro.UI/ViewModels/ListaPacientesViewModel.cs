using BioDeskPro.Core.Entities;
using BioDeskPro.Core.Interfaces;
using BioDeskPro.Data.Services;
using System.Collections.ObjectModel;
using System.Windows.Input;

namespace BioDeskPro.UI.ViewModels;

public class ListaPacientesViewModel : BaseViewModel
{
    private readonly IPacienteService _pacienteService;
    private readonly IPacienteContext _pacienteContext;
    private readonly INavigationService _navigationService;
    private readonly IChangeTracker _changeTracker;

    private string _searchText = string.Empty;
    private Paciente? _selectedPaciente;
    private bool _isLoading;
    private string _statusText = string.Empty;

    public ListaPacientesViewModel(
        IPacienteService pacienteService,
        IPacienteContext pacienteContext,
        INavigationService navigationService,
        IChangeTracker changeTracker)
    {
        _pacienteService = pacienteService;
        _pacienteContext = pacienteContext;
        _navigationService = navigationService;
        _changeTracker = changeTracker;

        Pacientes = new ObservableCollection<Paciente>();
        StatusText = "Carregando pacientes...";
        
        InitializeCommands();
        _ = LoadPacientesAsync(); // Fire and forget
    }

    #region Properties

    public ObservableCollection<Paciente> Pacientes { get; }

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (SetProperty(ref _searchText, value))
            {
                SearchCommand.Execute(null);
            }
        }
    }

    public Paciente? SelectedPaciente
    {
        get => _selectedPaciente;
        set
        {
            if (SetProperty(ref _selectedPaciente, value))
            {
                OnPropertyChanged(nameof(HasSelectedPaciente));
            }
        }
    }

    public bool HasSelectedPaciente => SelectedPaciente != null;

    public bool IsLoading
    {
        get => _isLoading;
        set => SetProperty(ref _isLoading, value);
    }

    public string StatusText 
    { 
        get => _statusText; 
        private set => SetProperty(ref _statusText, value); 
    }

    #endregion

    #region Commands

    public ICommand SearchCommand { get; private set; } = null!;
    public ICommand NovoPacienteCommand { get; private set; } = null!;
    public ICommand EditarPacienteCommand { get; private set; } = null!;
    public ICommand SelecionarPacienteCommand { get; private set; } = null!;
    public ICommand EliminarPacienteCommand { get; private set; } = null!;
    public ICommand RefreshCommand { get; private set; } = null!;

    #endregion

    private void InitializeCommands()
    {
        SearchCommand = new RelayCommand(ExecuteSearch);
        NovoPacienteCommand = new RelayCommand(ExecuteNovoPaciente);
        EditarPacienteCommand = new RelayCommand(ExecuteEditarPaciente, CanExecuteEditarPaciente);
        SelecionarPacienteCommand = new RelayCommand<Paciente>(ExecuteSelecionarPaciente);
        EliminarPacienteCommand = new RelayCommand(ExecuteEliminarPaciente, CanExecuteEliminarPaciente);
        RefreshCommand = new RelayCommand(ExecuteRefresh);
    }

    private async void ExecuteSearch()
    {
        IsLoading = true;
        try
        {
            var pacientes = await _pacienteService.SearchAsync(SearchText);
            
            Pacientes.Clear();
            foreach (var paciente in pacientes)
            {
                Pacientes.Add(paciente);
            }
        }
        catch (Exception ex)
        {
            // TODO: Log error and show user message
            System.Diagnostics.Debug.WriteLine($"Erro na pesquisa: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
            OnPropertyChanged(nameof(StatusText));
        }
    }

    private void ExecuteNovoPaciente()
    {
        _navigationService.NavigateTo("NovoPaciente");
    }

    private void ExecuteEditarPaciente()
    {
        if (SelectedPaciente != null)
        {
            // TODO: Implementar navegação para edição
            System.Diagnostics.Debug.WriteLine($"Editar paciente: {SelectedPaciente.NomeCompleto}");
        }
    }

    private bool CanExecuteEditarPaciente()
    {
        return HasSelectedPaciente;
    }

    private void ExecuteSelecionarPaciente(Paciente? paciente)
    {
        if (paciente != null)
        {
            SelectedPaciente = paciente;
            _pacienteContext.SetPacienteAtivo(paciente);
            
            // Navegar para a ficha do paciente
            _navigationService.NavigateTo("FichaPaciente");
            
            StatusText = $"Paciente {paciente.Nome} selecionado";
        }
    }

    private async void ExecuteEliminarPaciente()
    {
        if (SelectedPaciente != null)
        {
            // TODO: Mostrar confirmação
            try
            {
                await _pacienteService.DeleteAsync(SelectedPaciente.Id);
                Pacientes.Remove(SelectedPaciente);
                SelectedPaciente = null;
                OnPropertyChanged(nameof(StatusText));
            }
            catch (Exception ex)
            {
                // TODO: Show error message
                System.Diagnostics.Debug.WriteLine($"Erro ao eliminar: {ex.Message}");
            }
        }
    }

    private bool CanExecuteEliminarPaciente()
    {
        return HasSelectedPaciente;
    }

    private async void ExecuteRefresh()
    {
        SearchText = string.Empty;
        await LoadPacientesAsync();
    }

    private async Task LoadPacientesAsync()
    {
        IsLoading = true;
        try
        {
            var pacientes = await _pacienteService.GetAllAsync();
            
            Pacientes.Clear();
            foreach (var paciente in pacientes)
            {
                Pacientes.Add(paciente);
            }
            
            StatusText = $"Total: {Pacientes.Count} pacientes";
        }
        catch (Exception ex)
        {
            StatusText = "Erro ao carregar pacientes";
            // TODO: Log error and show user message
            System.Diagnostics.Debug.WriteLine($"Erro ao carregar pacientes: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }
}