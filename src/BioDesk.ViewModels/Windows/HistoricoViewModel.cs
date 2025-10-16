using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.ViewModels.UserControls.Terapia;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.Windows;

/// <summary>
/// ViewModel para Histórico de Sessões Terapêuticas
/// Permite filtrar por data, tipo e paciente, visualizar detalhes e repetir sessões
/// </summary>
public partial class HistoricoViewModel : ObservableObject
{
    private readonly ISessionHistoricoRepository _repository;

    [ObservableProperty] private DateTime _dataInicio = DateTime.Today.AddDays(-7);
    
    [ObservableProperty] private DateTime _dataFim = DateTime.Today.AddDays(1);
    
    [ObservableProperty] private string _tipoFiltro = "Todas";
    
    [ObservableProperty] private bool _isLoading;
    
    [ObservableProperty] private SessionHistorico? _sessaoSelecionada;
    
    public ObservableCollection<SessionHistorico> Sessions { get; } = new();
    
    public List<string> TiposTerapiaDisplay { get; } = new()
    {
        "Todas",
        "Remota",
        "Local",
        "Biofeedback"
    };
    
    // Eventos para repetir sessões (dispatched para View abrir modais apropriados)
    public event EventHandler<TerapiaRemotaRequestedEventArgs>? TerapiaRemotaRequested;
    public event EventHandler<TerapiaLocalRequestedEventArgs>? TerapiaLocalRequested;
    public event EventHandler<BiofeedbackSessaoRequestedEventArgs>? BiofeedbackSessaoRequested;
    
    public HistoricoViewModel(ISessionHistoricoRepository repository)
    {
        _repository = repository;
    }
    
    [RelayCommand]
    private async Task LoadSessionsAsync()
    {
        try
        {
            IsLoading = true;
            Sessions.Clear();
            
            // Fetch do repository (sempre by date range)
            var sessions = await _repository.GetByDateRangeAsync(DataInicio, DataFim);
            
            // Filtrar por tipo se não for "Todas"
            if (TipoFiltro != "Todas")
            {
                var tipoEnum = TipoFiltro switch
                {
                    "Remota" => TipoTerapia.Remota,
                    "Local" => TipoTerapia.Local,
                    "Biofeedback" => TipoTerapia.Biofeedback,
                    _ => (TipoTerapia?)null
                };
                
                if (tipoEnum.HasValue)
                {
                    sessions = sessions.Where(s => s.TipoTerapia == tipoEnum.Value);
                }
            }
            
            // Popular coleção
            foreach (var session in sessions)
            {
                Sessions.Add(session);
            }
        }
        catch (Exception ex)
        {
            // TODO: Log error
            Console.WriteLine($"❌ Erro ao carregar sessões: {ex.Message}");
        }
        finally
        {
            IsLoading = false;
        }
    }
    
    [RelayCommand(CanExecute = nameof(CanRepetirSessao))]
    private void RepetirSessao(SessionHistorico? sessao)
    {
        if (sessao == null) return;
        
        // Disparar evento apropriado com dados desserializados
        switch (sessao.TipoTerapia)
        {
            case TipoTerapia.Remota:
                // Deserializar protocolos
                var protocolos = JsonSerializer.Deserialize<List<string>>(sessao.ProtocolosJson) ?? new();
                TerapiaRemotaRequested?.Invoke(this, new TerapiaRemotaRequestedEventArgs(protocolos));
                break;
                
            case TipoTerapia.Local:
                // Deserializar frequências
                var frequencias = JsonSerializer.Deserialize<List<FrequenciaInfo>>(sessao.FrequenciasHzJson) ?? new();
                TerapiaLocalRequested?.Invoke(this, new TerapiaLocalRequestedEventArgs(frequencias));
                break;
                
            case TipoTerapia.Biofeedback:
                // Biofeedback é autónomo - sem dados pré-carregados
                BiofeedbackSessaoRequested?.Invoke(this, new BiofeedbackSessaoRequestedEventArgs());
                break;
        }
    }
    
    private bool CanRepetirSessao(SessionHistorico? sessao) => sessao != null;
}
