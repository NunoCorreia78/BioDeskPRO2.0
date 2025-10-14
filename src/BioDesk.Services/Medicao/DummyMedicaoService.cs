using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Medicao;

/// <summary>
/// Implementação dummy do serviço de medição para testes e desenvolvimento
/// Simula leituras biofeedback sem hardware TiePie real
/// </summary>
public class DummyMedicaoService : IMedicaoService
{
    private readonly ILogger<DummyMedicaoService> _logger;
    private readonly Random _random;
    private LeituraBiofeedback? _baselineSimulada;
    private LeituraBiofeedback? _ultimaLeitura; // ✅ Guardar última leitura para garantir crescimento monotônico
    private double _trendFactor = 1.0; // Fator para simular melhoria progressiva

    public DummyMedicaoService(ILogger<DummyMedicaoService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _random = new Random(DateTime.Now.Millisecond);
        _logger.LogInformation("🎭 DummyMedicaoService inicializado (modo simulação)");
    }

    public async Task<LeituraBiofeedback> CapturarBaselineAsync(int duracaoSegundos = 5)
    {
        _logger.LogInformation("📊 [DUMMY] Simulando captura baseline por {Duracao}s...", duracaoSegundos);

        await Task.Delay(duracaoSegundos * 100); // Simular delay (10% do tempo real)

        // Baseline estável (valores baixos)
        _baselineSimulada = new LeituraBiofeedback
        {
            Rms = 45.0 + _random.NextDouble() * 10.0, // 45-55 mV
            Pico = 75.0 + _random.NextDouble() * 15.0, // 75-90 mV
            FrequenciaDominante = 8.0 + _random.NextDouble() * 5.0, // 8-13 Hz (Alpha)
            PotenciaEspectral = -15.0 + _random.NextDouble() * 5.0, // -15 a -10 dB
            Timestamp = DateTime.Now
        };

        _logger.LogInformation("✅ [DUMMY] Baseline estabelecida: {Baseline}", _baselineSimulada);
        return _baselineSimulada;
    }

    public async Task<LeituraBiofeedback> CapturarLeituraAsync()
    {
        await Task.Delay(50); // Simular latência mínima de hardware

        // Se não há baseline, criar uma
        if (_baselineSimulada == null)
        {
            _baselineSimulada = await CapturarBaselineAsync(1);
        }

        // ✅ CORRIGIDO: Simular melhoria PROGRESSIVA LINEAR (não aleatória)
        // Melhora de forma gradual ao longo do tempo (0→95% em ~30-60s)
        _trendFactor += 0.015; // +1.5% por leitura (crescimento constante)
        _trendFactor = Math.Min(_trendFactor, 1.95); // Máximo +95% melhoria

        // Pequena variação natural (±1%) para realismo SEM descidas
        var jitter = 0.99 + (_random.NextDouble() * 0.02); // 0.99-1.01 (REDUZIDO de ±2% para ±1%)

        // Valores calculados com trend + jitter
        var rmsCalculado = _baselineSimulada.Rms * _trendFactor * jitter;
        var picoCalculado = _baselineSimulada.Pico * _trendFactor * jitter;

        // ✅ GARANTIR CRESCIMENTO MONOTÔNICO (nunca descer)
        if (_ultimaLeitura != null)
        {
            rmsCalculado = Math.Max(rmsCalculado, _ultimaLeitura.Rms);
            picoCalculado = Math.Max(picoCalculado, _ultimaLeitura.Pico);
        }

        // Leitura com trend progressivo + pequena variação
        var leitura = new LeituraBiofeedback
        {
            Rms = rmsCalculado,
            Pico = picoCalculado,
            FrequenciaDominante = _baselineSimulada.FrequenciaDominante + (_random.NextDouble() - 0.5) * 0.5, // ±0.25 Hz
            PotenciaEspectral = _baselineSimulada.PotenciaEspectral + (_trendFactor * 5.0), // Aumento progressivo
            Timestamp = DateTime.Now
        };

        _ultimaLeitura = leitura; // Guardar para comparação monotônica

        return leitura;
    }

    public double CalcularImprovementPercent(LeituraBiofeedback baseline, LeituraBiofeedback current)
    {
        if (baseline == null || current == null)
            throw new ArgumentNullException("Baseline e current não podem ser nulos");

        if (baseline.Rms == 0)
            return 0;

        // Mesma fórmula CoRe 5.0
        var improvement = ((current.Rms - baseline.Rms) / baseline.Rms) * 100;
        return Math.Round(improvement, 2);
    }

    public async Task IniciarCapturaContinuaAsync(int intervalMs = 1000)
    {
        _logger.LogInformation("▶️ [DUMMY] Captura contínua iniciada (intervalo: {Interval}ms)", intervalMs);
        await Task.CompletedTask;
        // Implementação simplificada - apenas log
    }

    public async Task PararCapturaContinuaAsync()
    {
        _logger.LogInformation("⏸️ [DUMMY] Captura contínua parada");
        await Task.CompletedTask;
    }

    public async Task<bool> TestarHardwareAsync()
    {
        _logger.LogInformation("✅ [DUMMY] Hardware simulado sempre disponível");
        await Task.Delay(100);
        return true;
    }
}
