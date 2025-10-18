using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows.Threading;
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;

namespace BioDesk.ViewModels.Windows;

/// <summary>
/// ViewModel para modal de Terapia Local (Com frequências Hz reais)
/// Usa emissão direta de corrente elétrica com controlo de voltagem
/// </summary>
public partial class TerapiaLocalViewModel : ObservableObject, IDisposable
{
    private bool _disposed = false;
    private readonly ISessionHistoricoRepository? _sessionRepository;
    private DispatcherTimer? _timer;
    private int _currentStepIndex = 0;
    private int _currentStepElapsedSeconds = 0;
    private int _totalElapsedSeconds = 0;

    [ObservableProperty] private double _voltagemV = 5.0; // Default 5V

    [ObservableProperty] private double _correnteMaxMa = 50.0;

    [ObservableProperty] private bool _emExecucao;

    [ObservableProperty] private bool _pausado;

    [ObservableProperty] private double _progressoPercent;

    [ObservableProperty] private string _hzAtual = "---";

    [ObservableProperty] private string _tempoDecorrido = "00:00";

    [ObservableProperty] private string _tempoRestante = "00:00";

    /// <summary>
    /// Duração uniforme para TODAS as frequências (5, 10 ou 15 segundos).
    /// User requirement: "o tempo escolhido para a frequência A, passa para a freq B que leva o mesmo tempo"
    /// </summary>
    [ObservableProperty] private int _duracaoUniformeSegundos = 10;

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
        if (!Frequencias.Any()) return;

        EmExecucao = true;
        Pausado = false;
        _currentStepIndex = 0;
        _currentStepElapsedSeconds = 0;
        _totalElapsedSeconds = 0;
        ProgressoPercent = 0;

        // Iniciar com primeira frequência
        var firstStep = Frequencias[_currentStepIndex];
        HzAtual = $"{firstStep.Hz:F1} Hz";

        // 📊 Persistir em SessionHistorico
        if (_sessionRepository != null)
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

        // Iniciar Timer (1 segundo)
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _timer.Tick += Timer_Tick;
        _timer.Start();

        // TODO: Integrar com ITiePieHardwareService para emitir sinal real
        // await _tiepieService.StartEmissionAsync(firstStep.Hz, firstStep.DutyPercent, VoltagemV);
    }

    private void Timer_Tick(object? sender, EventArgs e)
    {
        if (Pausado) return; // Não avançar se pausado

        _currentStepElapsedSeconds++;
        _totalElapsedSeconds++;

        // Atualizar tempo decorrido
        TempoDecorrido = TimeSpan.FromSeconds(_totalElapsedSeconds).ToString(@"mm\:ss");

        // Verificar se step atual terminou
        var currentStep = Frequencias[_currentStepIndex];
        if (_currentStepElapsedSeconds >= currentStep.DuracaoSegundos)
        {
            // Avançar para próxima frequência
            _currentStepIndex++;
            _currentStepElapsedSeconds = 0;

            if (_currentStepIndex < Frequencias.Count)
            {
                // Mudar para próxima frequência
                var nextStep = Frequencias[_currentStepIndex];
                HzAtual = $"{nextStep.Hz:F1} Hz";

                // TODO: Atualizar hardware para nova frequência
                // await _tiepieService.StartEmissionAsync(nextStep.Hz, nextStep.DutyPercent, VoltagemV);
            }
            else
            {
                // Todas as frequências emitidas - terminar
                Parar();
                return;
            }
        }

        // Atualizar progresso (baseado em tempo total)
        var totalDurationSeconds = Frequencias.Sum(f => f.DuracaoSegundos);
        ProgressoPercent = (_totalElapsedSeconds / (double)totalDurationSeconds) * 100.0;

        // Atualizar tempo restante
        var remainingSeconds = totalDurationSeconds - _totalElapsedSeconds;
        TempoRestante = TimeSpan.FromSeconds(remainingSeconds).ToString(@"mm\:ss");
    }

    [RelayCommand]
    private void Pausar()
    {
        Pausado = !Pausado;
        // TODO: Pausar hardware se estiver a emitir
    }

    [RelayCommand]
    private void Parar()
    {
        _timer?.Stop();
        _timer = null;

        EmExecucao = false;
        Pausado = false;
        ProgressoPercent = 0;
        HzAtual = "---";
        TempoDecorrido = "00:00";
        TempoRestante = "00:00";

        // TODO: Parar emissão hardware
        // await _tiepieService.StopEmissionAsync();
    }

    partial void OnVoltagemVChanged(double value)
    {
        // Limitar voltagem entre 0 e 12V
        if (value < 0) VoltagemV = 0;
        if (value > 12) VoltagemV = 12;
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            _timer?.Stop();
            _timer = null;
        }
        _disposed = true;
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
