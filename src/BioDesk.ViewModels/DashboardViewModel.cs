using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.Extensions.Logging;
using BioDesk.ViewModels.Base;
using BioDesk.Services.Navigation;
using BioDesk.Services.Pacientes;
using BioDesk.Domain.Entities;

namespace BioDesk.ViewModels;

/// <summary>
/// ViewModel para o Dashboard (ecrã inicial)
/// Caminho de ouro: Dashboard → NovoPaciente(Salvar) → Ficha OU Dashboard → Pesquisa → Lista → SelecionarPaciente → Ficha
/// Comportamentos: SetPacienteAtivo + NavigateTo("FichaPaciente") sempre que confirma seleção/criação
/// </summary>
public partial class DashboardViewModel : NavigationViewModelBase
{
    private readonly ILogger<DashboardViewModel> _logger;

    [ObservableProperty]
    private string _pesquisarTexto = string.Empty;

    [ObservableProperty]
    private List<Paciente> _pacientesRecentes = new();

    [ObservableProperty]
    private string _statusConexao = "Online";

    [ObservableProperty]
    private string _statusIridoscopio = "Não detectado";

    [ObservableProperty]
    private string _statusOsciloscopio = "Não detectado";

    [ObservableProperty]
    private DateTime _horaAtual = DateTime.Now;

    /// <summary>
    /// Data formatada em português europeu
    /// </summary>
    public string DataFormatadaPT => HoraAtual.ToString("dddd, dd/MM/yyyy", new CultureInfo("pt-PT"));

    public DashboardViewModel(
        INavigationService navigationService,
        IPacienteService pacienteService,
        ILogger<DashboardViewModel> logger)
        : base(navigationService, pacienteService)
    {
        _logger = logger;

        // Inicia o relógio
        IniciarRelogio();
    }

    /// <summary>
    /// Comando para navegar para criação de novo paciente
    /// </summary>
    [RelayCommand]
    private void NovoPaciente()
    {
        _logger.LogInformation("Preparando criação de novo paciente na ficha");

        var novoPaciente = new Paciente
        {
            Nome = string.Empty,
            Email = string.Empty,
            Telefone = string.Empty,
            DataNascimento = DateTime.Today.AddYears(-30)
        };

        PacienteService.SetPacienteAtivo(novoPaciente);
        NavigationService.NavigateTo("FichaPaciente");
    }

    /// <summary>
    /// Comando para navegar para lista de pacientes
    /// </summary>
    [RelayCommand]
    private void AbrirListaPacientes()
    {
        _logger.LogInformation("Navegando para lista de pacientes");
        NavigationService.NavigateTo("ListaPacientes");
    }

    /// <summary>
    /// Comando para pesquisar pacientes
    /// Enter/clicar → SearchAsync e navega para Lista com filtro aplicado
    /// </summary>
    [RelayCommand]
    private async Task PesquisarAsync()
    {
        if (string.IsNullOrWhiteSpace(PesquisarTexto))
        {
            AbrirListaPacientes();
            return;
        }

        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Pesquisando pacientes com termo: {Termo}", PesquisarTexto);
            
            var resultados = await PacienteService.SearchAsync(PesquisarTexto);
            
            if (resultados.Count == 1)
            {
                // Se só há um resultado, navegar diretamente para a ficha
                var paciente = resultados.First();
                PacienteService.SetPacienteAtivo(paciente);
                NavigationService.NavigateTo("FichaPaciente");
            }
            else
            {
                // Múltiplos resultados ou nenhum → navegar para lista com filtro
                NavigationService.NavigateTo("ListaPacientes");
            }
        }, "Erro ao pesquisar pacientes");
    }

    /// <summary>
    /// Comando para selecionar um paciente recente
    /// SetPacienteAtivo → NavigateTo("FichaPaciente")
    /// </summary>
    [RelayCommand]
    private void SelecionarPacienteRecente(Paciente paciente)
    {
        if (paciente == null) return;

        _logger.LogInformation("Selecionando paciente recente: {Nome}", paciente.Nome);
        
        PacienteService.SetPacienteAtivo(paciente);
        NavigationService.NavigateTo("FichaPaciente");
    }

    /// <summary>
    /// Carrega os dados iniciais do dashboard
    /// </summary>
    public async Task CarregarDadosAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            _logger.LogInformation("Carregando dados do dashboard");
            
            PacientesRecentes = await PacienteService.GetRecentesAsync(5);
            
            _logger.LogInformation("Dashboard carregado - {Quantidade} pacientes recentes", 
                PacientesRecentes.Count);

            // Dashboard fica no dashboard - utilizador escolhe quando navegar
            
        }, "ao carregar dados do dashboard", _logger);
    }

    /// <summary>
    /// Inicia o relógio que atualiza a hora em tempo real
    /// </summary>
    private void IniciarRelogio()
    {
        var timer = new System.Timers.Timer(1000); // 1 segundo
        timer.Elapsed += (s, e) => 
        {
            HoraAtual = DateTime.Now;
            OnPropertyChanged(nameof(DataFormatadaPT));
        };
        timer.Start();
    }
}
