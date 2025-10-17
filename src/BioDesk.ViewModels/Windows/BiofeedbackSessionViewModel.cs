using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.ObjectModel;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Threading;

namespace BioDesk.ViewModels.Windows;

/// <summary>
/// ViewModel para BiofeedbackSessionWindow.
/// Implementa loop autónomo: auto-scan → deteta Hz → emite → aguarda intervalo → repete.
/// 100% independente de outras abas (não depende de Avaliação/Programas).
/// </summary>
public partial class BiofeedbackSessionViewModel : ObservableObject, IDisposable
{
    private bool _disposed = false;
    private readonly ISessionHistoricoRepository? _sessionRepository;
    private DispatcherTimer? _timer;
    private int _totalElapsedSeconds = 0;
    private int _countdownSeconds = 0;
    private bool _isScanning = false;
    private bool _isEmitting = false;
    private double[] _currentCycleHz = Array.Empty<double>();
    private int _currentHzIndex = 0;
    private int _currentHzElapsedSeconds = 0;
    private DateTime _sessionStartTime = DateTime.Now;

    // ══════════════════════════════════════════════════════════════
    // PROPRIEDADES - Controlo de Sessão
    // ══════════════════════════════════════════════════════════════

    /// <summary>
    /// Indica se sessão está em execução (loop ativo).
    /// </summary>
    [ObservableProperty]
    private bool _isRunning = false;

    /// <summary>
    /// Indica se sessão está pausada (mantém estado mas não executa).
    /// </summary>
    [ObservableProperty]
    private bool _pausado = false;

    /// <summary>
    /// Ciclo atual (incrementa a cada scan+emit completo).
    /// </summary>
    [ObservableProperty]
    private int _currentCycle = 0;

    /// <summary>
    /// Máximo de ciclos (null = infinito, user pode definir limite).
    /// </summary>
    [ObservableProperty]
    private int? _maxCycles = null;

    /// <summary>
    /// Intervalo entre scans em segundos (default 120s = 2 minutos).
    /// User pode ajustar para scans mais frequentes ou menos.
    /// </summary>
    [ObservableProperty]
    private int _scanIntervalSeconds = 120;

    // ══════════════════════════════════════════════════════════════
    // PROPRIEDADES - Voltagem e Corrente
    // ══════════════════════════════════════════════════════════════

    /// <summary>
    /// Voltagem aplicada durante emissão (0-12V).
    /// User REQUIREMENT: "forma clara e óbvia de controlar a voltagem".
    /// </summary>
    [ObservableProperty]
    private double _voltagemV = 5.0;

    /// <summary>
    /// Corrente máxima permitida em miliamperes (segurança).
    /// </summary>
    [ObservableProperty]
    private double _correnteMaxMa = 50.0;

    /// <summary>
    /// Auto-ajustar voltagem baseado em resposta do scan (experimental).
    /// Se true, sistema aumenta/diminui voltagem automaticamente.
    /// </summary>
    [ObservableProperty]
    private bool _autoAdjustVoltage = false;

    /// <summary>
    /// Duração uniforme para cada Hz detectado (5, 10 ou 15 segundos).
    /// User requirement: "o tempo escolhido para a frequência A, passa para a freq B que leva o mesmo tempo"
    /// </summary>
    [ObservableProperty]
    private int _duracaoUniformeSegundos = 10;

    // ══════════════════════════════════════════════════════════════
    // PROPRIEDADES - Estado Atual
    // ══════════════════════════════════════════════════════════════

    /// <summary>
    /// Hz atualmente sendo emitido (ou "A detetar..." durante scan).
    /// </summary>
    [ObservableProperty]
    private string _currentHz = "---";

    /// <summary>
    /// Percentagem de progresso do ciclo atual (0-100).
    /// Durante scan = 0-20%, durante emit = 20-100%.
    /// </summary>
    [ObservableProperty]
    private double _progressoPercent = 0.0;

    /// <summary>
    /// Contagem regressiva até próximo scan (formato "XXs").
    /// Visível apenas quando IsRunning=true e não está a emitir.
    /// </summary>
    [ObservableProperty]
    private string _nextScanCountdown = "---";

    /// <summary>
    /// Tempo decorrido total da sessão (formato "mm:ss").
    /// </summary>
    [ObservableProperty]
    private string _tempoDecorridoTotal = "00:00";

    // ══════════════════════════════════════════════════════════════
    // COLEÇÃO - Histórico de Ciclos
    // ══════════════════════════════════════════════════════════════

    /// <summary>
    /// Histórico dos últimos 3 ciclos (FIFO: remove oldest quando > 3).
    /// Mostra ao user o que foi detetado e emitido em cada ciclo.
    /// </summary>
    public ObservableCollection<CycleHistoryItem> History { get; } = new();

    // ══════════════════════════════════════════════════════════════
    // CONSTRUTORES
    // ══════════════════════════════════════════════════════════════

    public BiofeedbackSessionViewModel() { }

    public BiofeedbackSessionViewModel(ISessionHistoricoRepository sessionRepository)
    {
        _sessionRepository = sessionRepository;
    }

    // ══════════════════════════════════════════════════════════════
    // COMANDOS
    // ══════════════════════════════════════════════════════════════

    /// <summary>
    /// Inicia sessão de biofeedback (loop autónomo).
    /// User requirement: "Botão único" - scan + emit numa só ação.
    /// </summary>
    [RelayCommand]
    private async Task IniciarSessaoAsync()
    {
        IsRunning = true;
        Pausado = false;
        CurrentCycle = 0;
        ProgressoPercent = 0.0;
        CurrentHz = "A detetar...";
        History.Clear();
        _totalElapsedSeconds = 0;
        _sessionStartTime = DateTime.Now;
        _isScanning = true;
        _isEmitting = false;

        // 📊 Persistir em SessionHistorico
        if (_sessionRepository != null)
        {
            try
            {
                var session = new SessionHistorico
                {
                    DataHoraInicio = DateTime.Now,
                    TipoTerapia = TipoTerapia.Biofeedback,
                    VoltagemV = VoltagemV,
                    Notas = $"Ciclos máx: {MaxCycles?.ToString() ?? "∞"}, Intervalo: {ScanIntervalSeconds}s, Auto-ajuste: {(AutoAdjustVoltage ? "Sim" : "Não")}"
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
        _timer.Tick += BiofeedbackTimer_Tick;
        _timer.Start();

        // Simular scan inicial (3 segundos) e começar emissão
        await Task.Delay(3000);
        if (IsRunning && !Pausado)
        {
            StartEmissionCycle();
        }
    }

    private void StartEmissionCycle()
    {
        // Simular Hz detectados (em produção viria do ResonanceEngine)
        _currentCycleHz = new[] { 728.0, 880.0, 1500.0 }; // Exemplo
        _currentHzIndex = 0;
        _currentHzElapsedSeconds = 0;
        _isScanning = false;
        _isEmitting = true;

        CurrentCycle++;
        CurrentHz = $"{_currentCycleHz[_currentHzIndex]:F1} Hz";
        ProgressoPercent = 0;

        // TODO: Iniciar emissão hardware
        // await _tiepieService.StartEmissionAsync(_currentCycleHz[_currentHzIndex], VoltagemV);
    }

    private void BiofeedbackTimer_Tick(object? sender, EventArgs e)
    {
        if (Pausado) return;

        _totalElapsedSeconds++;
        TempoDecorridoTotal = TimeSpan.FromSeconds(_totalElapsedSeconds).ToString(@"mm\:ss");

        if (_isScanning)
        {
            // Simular scan (3 segundos)
            ProgressoPercent = Math.Min(20, (_totalElapsedSeconds % 3) * 6.67);
            return;
        }

        if (_isEmitting)
        {
            _currentHzElapsedSeconds++;

            // Usar duração uniforme configurada pelo user
            int hzDurationSeconds = DuracaoUniformeSegundos;

            if (_currentHzElapsedSeconds >= hzDurationSeconds)
            {
                // Avançar para próximo Hz
                _currentHzIndex++;
                _currentHzElapsedSeconds = 0;

                if (_currentHzIndex < _currentCycleHz.Length)
                {
                    // Próximo Hz
                    CurrentHz = $"{_currentCycleHz[_currentHzIndex]:F1} Hz";
                    // TODO: Mudar frequência hardware
                }
                else
                {
                    // Ciclo completo - adicionar ao histórico
                    var cycleEnd = DateTime.Now;
                    var cycleDuration = (int)(cycleEnd - _sessionStartTime.AddSeconds(_totalElapsedSeconds - (_currentCycleHz.Length * hzDurationSeconds))).TotalSeconds;

                    var historyItem = new CycleHistoryItem(
                        CicloNumero: CurrentCycle,
                        HzDetectados: string.Join(", ", _currentCycleHz.Select(h => $"{h:F1}")),
                        DuracaoSegundos: _currentCycleHz.Length * hzDurationSeconds,
                        VoltagemUsada: VoltagemV,
                        DataHora: cycleEnd
                    );

                    History.Insert(0, historyItem);
                    if (History.Count > 3) History.RemoveAt(3);

                    // Verificar se atingiu limite de ciclos
                    if (MaxCycles.HasValue && CurrentCycle >= MaxCycles.Value)
                    {
                        Parar();
                        return;
                    }

                    // Iniciar countdown para próximo scan
                    _countdownSeconds = ScanIntervalSeconds;
                    _isEmitting = false;
                    CurrentHz = "Aguardando próximo scan...";
                }
            }

            // Atualizar progresso (20% scan + 80% emissão)
            var emissionProgress = (_currentHzIndex * hzDurationSeconds + _currentHzElapsedSeconds) / (double)(_currentCycleHz.Length * hzDurationSeconds);
            ProgressoPercent = 20 + (emissionProgress * 80);
        }
        else
        {
            // Countdown até próximo scan
            _countdownSeconds--;
            NextScanCountdown = $"{_countdownSeconds}s";

            if (_countdownSeconds <= 0)
            {
                // Iniciar novo scan
                _isScanning = true;
                CurrentHz = "A detetar...";
                Task.Delay(3000).ContinueWith(_ =>
                {
                    if (IsRunning && !Pausado)
                    {
                        System.Windows.Application.Current?.Dispatcher.Invoke(() => StartEmissionCycle());
                    }
                });
            }
        }
    }

    /// <summary>
    /// Pausa/retoma sessão (mantém estado mas para execução temporariamente).
    /// </summary>
    [RelayCommand]
    private void Pausar()
    {
        Pausado = !Pausado;
        // TODO: Pausar timers/emissão atual
    }

    /// <summary>
    /// Para sessão completamente (reset estado).
    /// </summary>
    [RelayCommand]
    private void Parar()
    {
        _timer?.Stop();
        _timer = null;

        IsRunning = false;
        Pausado = false;
        CurrentHz = "---";
        ProgressoPercent = 0.0;
        NextScanCountdown = "---";
        _isScanning = false;
        _isEmitting = false;

        // TODO: Parar emissão hardware, cancelar tasks async
    }

    // ══════════════════════════════════════════════════════════════
    // VALIDAÇÃO - Limites de Voltagem (SEGURANÇA)
    // ══════════════════════════════════════════════════════════════

    partial void OnVoltagemVChanged(double value)
    {
        // Enforçar limite 0-12V (mesmo que user tente ultrapassar)
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
/// Item de histórico de um ciclo de biofeedback.
/// Imutável (record) para garantir integridade do histórico.
/// </summary>
/// <param name="CicloNumero">Número sequencial do ciclo (1, 2, 3...)</param>
/// <param name="HzDetectados">Lista de Hz detetados no scan (formato: "728.0, 880.0, 1500.0")</param>
/// <param name="DuracaoSegundos">Duração total do ciclo em segundos (scan + emit)</param>
/// <param name="VoltagemUsada">Voltagem aplicada durante emissão (V)</param>
/// <param name="DataHora">Timestamp do ciclo</param>
public record CycleHistoryItem(
    int CicloNumero,
    string HzDetectados,
    int DuracaoSegundos,
    double VoltagemUsada,
    DateTime DataHora)
{
    /// <summary>
    /// Hz formatados para display (ex: "728.0, 880.0 Hz").
    /// </summary>
    public string HzFormatted => $"{HzDetectados} Hz";

    /// <summary>
    /// Duração formatada (mm:ss).
    /// </summary>
    public string DuracaoFormatted => TimeSpan.FromSeconds(DuracaoSegundos).ToString(@"mm\:ss");

    /// <summary>
    /// Voltagem formatada (V).
    /// </summary>
    public string VoltagemFormatted => $"{VoltagemUsada:F1} V";

    /// <summary>
    /// DataHora formatada (dd/MM HH:mm).
    /// </summary>
    public string DataHoraFormatted => DataHora.ToString("dd/MM HH:mm");
}
