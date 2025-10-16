using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.Windows;

/// <summary>
/// ViewModel para modal de Terapia Local (Com frequências Hz reais)
/// Usa emissão direta de corrente elétrica com controlo de voltagem
/// </summary>
public partial class TerapiaLocalViewModel : ObservableObject
{
    private readonly ISessionHistoricoRepository? _sessionRepository;
    
    [ObservableProperty] private double _voltagemV = 5.0; // Default 5V
    
    [ObservableProperty] private double _correnteMaxMa = 50.0;
    
    [ObservableProperty] private bool _emExecucao;
    
    [ObservableProperty] private bool _pausado;
    
    [ObservableProperty] private double _progressoPercent;
    
    [ObservableProperty] private string _hzAtual = "---";
    
    [ObservableProperty] private string _tempoDecorrido = "00:00";
    
    [ObservableProperty] private string _tempoRestante = "00:00";
    
    /// <summary>
    /// Frequências a emitir (Hz, Duty %, Duração seg)
    /// </summary>
    public ObservableCollection<FrequenciaStep> Frequencias { get; } = new();
    
    /// <summary>
    /// Duração total calculada (soma de todas as frequências)
    /// </summary>
    public string DuracaoTotal => Frequencias.Any() 
        ? TimeSpan.FromSeconds(Frequencias.Sum(f => f.DuracaoSegundos)).ToString(@"mm\:ss")
        : "00:00";
    
    public TerapiaLocalViewModel() { }
    
    public TerapiaLocalViewModel(ISessionHistoricoRepository sessionRepository)
    {
        _sessionRepository = sessionRepository;
    }
    
    [RelayCommand]
    private async Task IniciarAsync()
    {
        EmExecucao = true;
        Pausado = false;
        
        // TODO: Integrar com ITiePieHardwareService
        // - Configurar voltagem (VoltagemV)
        // - Iterar por Frequencias (foreach step)
        
        // 📊 Persistir em SessionHistorico
        if (_sessionRepository != null && Frequencias.Any())
        {
            try
            {
                var frequenciasJson = Frequencias.Select(f => new 
                { 
                    Hz = f.Hz, 
                    DutyPercent = f.DutyPercent, 
                    DuracaoSegundos = f.DuracaoSegundos 
                }).ToList();
                
                var session = new SessionHistorico
                {
                    DataHoraInicio = DateTime.Now,
                    TipoTerapia = TipoTerapia.Local,
                    FrequenciasHzJson = JsonSerializer.Serialize(frequenciasJson),
                    DuracaoMinutos = (int)(Frequencias.Sum(f => f.DuracaoSegundos) / 60.0),
                    VoltagemV = VoltagemV,
                    CorrenteMa = CorrenteMaxMa
                };
                
                await _sessionRepository.AddAsync(session);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Erro ao persistir SessionHistorico: {ex.Message}");
            }
        }
        // - Emitir cada Hz com Duty e Duração especificados
        // - Atualizar ProgressoPercent, HzAtual, TempoDecorrido
        // - Persistir em SessionHistorico (TipoTerapia.Local)
    }
    
    [RelayCommand]
    private void Pausar()
    {
        Pausado = !Pausado;
    }
    
    [RelayCommand]
    private void Parar()
    {
        EmExecucao = false;
        Pausado = false;
        ProgressoPercent = 0;
    }
    
    partial void OnVoltagemVChanged(double value)
    {
        // Limitar voltagem entre 0 e 12V
        if (value < 0) VoltagemV = 0;
        if (value > 12) VoltagemV = 12;
    }
}

/// <summary>
/// Representa um step de frequência a emitir
/// </summary>
public record FrequenciaStep(double Hz, int DutyPercent, int DuracaoSegundos)
{
    public string HzFormatted => $"{Hz:F1} Hz";
    public string DutyFormatted => $"{DutyPercent}%";
    public string DuracaoFormatted => TimeSpan.FromSeconds(DuracaoSegundos).ToString(@"mm\:ss");
}
