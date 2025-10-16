using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using System;
using System.Collections.ObjectModel;
using System.Threading.Tasks;

namespace BioDesk.ViewModels.Windows;

/// <summary>
/// ViewModel para BiofeedbackSessionWindow.
/// Implementa loop autónomo: auto-scan → deteta Hz → emite → aguarda intervalo → repete.
/// 100% independente de outras abas (não depende de Avaliação/Programas).
/// </summary>
public partial class BiofeedbackSessionViewModel : ObservableObject
{
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

        // TODO: Integrar com IResonanceEngine para loop:
        // 1. Auto-scan → deteta Hz ressonantes
        // 2. Emitir Hz com VoltagemV durante DuracaoSegundos
        // 3. Adicionar CycleHistoryItem ao History (manter max 3)
        // 4. Aguardar ScanIntervalSeconds
        // 5. Repetir até MaxCycles ou user parar
        //
        // Pseudo-código:
        // while (IsRunning && (!MaxCycles.HasValue || CurrentCycle < MaxCycles.Value))
        // {
        //     if (Pausado) { await Task.Delay(500); continue; }
        //     
        //     // 1. Scan (0-20% progress)
        //     CurrentHz = "A detetar...";
        //     var hzList = await _resonanceEngine.AutoScanAsync();
        //     
        //     // 2. Emit (20-100% progress)
        //     foreach (var hz in hzList)
        //     {
        //         CurrentHz = $"{hz:F1} Hz";
        //         await _tiepieService.EmitAsync(hz, VoltagemV, duracaoSegundos);
        //         ProgressoPercent += (80.0 / hzList.Count);
        //     }
        //     
        //     // 3. Adicionar ao histórico
        //     var historyItem = new CycleHistoryItem(
        //         CicloNumero: ++CurrentCycle,
        //         HzDetectados: string.Join(", ", hzList.Select(h => $"{h:F1}")),
        //         DuracaoSegundos: duracaoTotalCiclo,
        //         VoltagemUsada: VoltagemV,
        //         DataHora: DateTime.Now
        //     );
        //     History.Insert(0, historyItem); // FIFO: mais recente no topo
        //     if (History.Count > 3) History.RemoveAt(3); // Manter apenas 3
        //     
        //     // 4. Countdown até próximo scan
        //     for (int i = ScanIntervalSeconds; i > 0; i--)
        //     {
        //         if (!IsRunning || Pausado) break;
        //         NextScanCountdown = $"{i}s";
        //         await Task.Delay(1000);
        //     }
        //     
        //     ProgressoPercent = 0.0; // Reset para próximo ciclo
        // }

        await Task.CompletedTask; // Placeholder
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
        IsRunning = false;
        Pausado = false;
        CurrentHz = "---";
        ProgressoPercent = 0.0;
        NextScanCountdown = "---";
        
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
