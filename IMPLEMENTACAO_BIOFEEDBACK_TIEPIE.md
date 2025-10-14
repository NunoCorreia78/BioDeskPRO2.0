# 🎯 IMPLEMENTAÇÃO BIOFEEDBACK - TiePie Osciloscópio + Generator
**Data:** 13 de Outubro de 2025
**Hardware:** TiePie Handyscope (com INPUT/OUTPUT)
**Objetivo:** Biofeedback completo tipo CoRe 5.0

---

## ✅ **CONFIRMADO PELO UTILIZADOR**

- ✅ TiePie tem **capacidade de INPUT** (osciloscópio/ADC)
- ✅ TiePie é **recomendado pela Inergetix** para uso com CoRe
- ✅ Utilizador **sente corrente** ao segurar sensores (OUTPUT funciona)
- 🎯 **Objetivo:** Implementar leitura de resposta fisiológica (INPUT)

---

## 📋 **O QUE JÁ ESTÁ IMPLEMENTADO**

### ✅ **OUTPUT (Generator) - 100% Funcional**
```csharp
// RealTiePieHardwareService.cs
- GenSetFrequency()
- GenSetAmplitude()
- GenSetSignalType()
- GenStart() / GenStop()
- SendSignalAsync()
- SendMultipleFrequenciesAsync()
```

**Status:** ✅ Totalmente funcional (emite frequências, utilizador sente corrente)

---

## ❌ **O QUE FALTA IMPLEMENTAR**

### 🔴 **INPUT (Oscilloscope) - 0% Implementado**

#### **1. P/Invoke Declarations (LibTiePie SDK)**

Adicionar ao `RealTiePieHardwareService.cs` (região P/Invoke):

```csharp
// === OSCILLOSCOPE (Input/Medição) ===
private const uint DEVICETYPE_OSCILLOSCOPE = 0x00000001;

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern ushort ScpGetChannelCount(IntPtr hDevice);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpChSetEnabled(IntPtr hDevice, ushort wCh, bool bEnable);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpChSetRange(IntPtr hDevice, ushort wCh, double dRange);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpSetSampleFrequency(IntPtr hDevice, double dSampleFrequency);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern double ScpGetSampleFrequency(IntPtr hDevice);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpSetRecordLength(IntPtr hDevice, ulong qwRecordLength);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern ulong ScpGetRecordLength(IntPtr hDevice);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpStart(IntPtr hDevice);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpStop(IntPtr hDevice);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern ulong ScpGetData(IntPtr hDevice, IntPtr[] pBuffers, ushort wChannelCount, ulong qwStartIndex, ulong qwSampleCount);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpIsDataReady(IntPtr hDevice);

[DllImport(LibTiePieDll, CallingConvention = CallingConvention.Cdecl)]
private static extern bool ScpIsDataOverflow(IntPtr hDevice);
```

---

#### **2. Interface de Medição**

Criar `IMedicaoService.cs` (novo serviço):

```csharp
namespace BioDesk.Services.Hardware;

/// <summary>
/// Serviço de medição fisiológica via TiePie Oscilloscope
/// </summary>
public interface IMedicaoService
{
    /// <summary>
    /// Inicia captura contínua de dados
    /// </summary>
    Task<bool> IniciarCapturaAsync(MedicaoConfig config);

    /// <summary>
    /// Para captura
    /// </summary>
    Task PararCapturaAsync();

    /// <summary>
    /// Lê amostras do buffer (não-bloqueante)
    /// </summary>
    Task<double[]?> LerAmostrasAsync(int canal, int numAmostras);

    /// <summary>
    /// Calcula métricas de biofeedback
    /// </summary>
    Task<MetricasBiofeedback> CalcularMetricasAsync(double[] amostras);

    /// <summary>
    /// Calcula Improvement % comparando antes/depois
    /// </summary>
    double CalcularImprovementPercent(MetricasBiofeedback antes, MetricasBiofeedback depois);
}

public class MedicaoConfig
{
    public int Canal { get; set; } = 0; // Canal 0 ou 1
    public double SampleRateHz { get; set; } = 1000.0; // 1 kHz
    public int RecordLength { get; set; } = 1024; // Amostras por leitura
    public double RangeV { get; set; } = 10.0; // ±10V
}

public class MetricasBiofeedback
{
    public double Rms { get; set; } // Root Mean Square
    public double PicoPositivo { get; set; } // Voltagem máxima
    public double PicoNegativo { get; set; } // Voltagem mínima
    public double FrequenciaDominante { get; set; } // Hz (via FFT)
    public double PotenciaEspectral { get; set; } // Intensidade do pico
    public double Impedancia { get; set; } // Ohms (calculado)
    public DateTime Timestamp { get; set; }
}
```

---

#### **3. Implementação RealMedicaoService**

Criar `RealMedicaoService.cs`:

```csharp
public class RealMedicaoService : IMedicaoService
{
    private readonly ITiePieHardwareService _tiePieService;
    private readonly ILogger<RealMedicaoService> _logger;
    private IntPtr _oscilloscopeHandle = IntPtr.Zero;
    private bool _isCapturing = false;
    private readonly object _lockObject = new object();

    public async Task<bool> IniciarCapturaAsync(MedicaoConfig config)
    {
        return await Task.Run(() =>
        {
            lock (_lockObject)
            {
                try
                {
                    // 1. Abrir dispositivo em modo OSCILLOSCOPE
                    LstUpdate();
                    _oscilloscopeHandle = LstOpenDevice(IDKIND_INDEX, 0, DEVICETYPE_OSCILLOSCOPE);

                    if (_oscilloscopeHandle == IntPtr.Zero)
                    {
                        _logger.LogError("❌ Falha ao abrir TiePie em modo osciloscópio");
                        return false;
                    }

                    // 2. Configurar canal
                    ScpChSetEnabled(_oscilloscopeHandle, (ushort)config.Canal, true);
                    ScpChSetRange(_oscilloscopeHandle, (ushort)config.Canal, config.RangeV);

                    // 3. Configurar sample rate
                    ScpSetSampleFrequency(_oscilloscopeHandle, config.SampleRateHz);
                    ScpSetRecordLength(_oscilloscopeHandle, (ulong)config.RecordLength);

                    // 4. Iniciar captura
                    _isCapturing = ScpStart(_oscilloscopeHandle);

                    if (_isCapturing)
                    {
                        _logger.LogInformation("✅ Captura iniciada: {Rate} Hz, {Length} amostras",
                            config.SampleRateHz, config.RecordLength);
                    }

                    return _isCapturing;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "❌ Erro ao iniciar captura");
                    return false;
                }
            }
        });
    }

    public async Task<double[]?> LerAmostrasAsync(int canal, int numAmostras)
    {
        return await Task.Run(() =>
        {
            lock (_lockObject)
            {
                if (!_isCapturing || _oscilloscopeHandle == IntPtr.Zero)
                    return null;

                try
                {
                    // Verificar se dados estão prontos
                    if (!ScpIsDataReady(_oscilloscopeHandle))
                        return null;

                    // Alocar buffer
                    IntPtr buffer = Marshal.AllocHGlobal(numAmostras * sizeof(float));
                    IntPtr[] buffers = new IntPtr[] { buffer };

                    // Ler dados
                    ulong samplesRead = ScpGetData(_oscilloscopeHandle, buffers, 1, 0, (ulong)numAmostras);

                    if (samplesRead == 0)
                    {
                        Marshal.FreeHGlobal(buffer);
                        return null;
                    }

                    // Copiar para array managed
                    float[] floatData = new float[samplesRead];
                    Marshal.Copy(buffer, floatData, 0, (int)samplesRead);
                    Marshal.FreeHGlobal(buffer);

                    // Converter para double
                    double[] doubleData = Array.ConvertAll(floatData, x => (double)x);

                    return doubleData;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "❌ Erro ao ler amostras");
                    return null;
                }
            }
        });
    }

    public async Task<MetricasBiofeedback> CalcularMetricasAsync(double[] amostras)
    {
        return await Task.Run(() =>
        {
            // 1. RMS (Root Mean Square)
            double rms = Math.Sqrt(amostras.Average(x => x * x));

            // 2. Picos
            double picoPositivo = amostras.Max();
            double picoNegativo = amostras.Min();

            // 3. FFT para frequência dominante (simplificado - usar MathNet.Numerics para FFT real)
            double freqDominante = CalcularFrequenciaDominanteSimples(amostras);

            // 4. Impedância (estimativa baseada em corrente conhecida)
            double impedancia = EstimarImpedancia(rms);

            return new MetricasBiofeedback
            {
                Rms = rms,
                PicoPositivo = picoPositivo,
                PicoNegativo = picoNegativo,
                FrequenciaDominante = freqDominante,
                PotenciaEspectral = picoPositivo - picoNegativo,
                Impedancia = impedancia,
                Timestamp = DateTime.Now
            };
        });
    }

    public double CalcularImprovementPercent(MetricasBiofeedback antes, MetricasBiofeedback depois)
    {
        // Algoritmo CoRe-like:
        // Improvement = melhoria em RMS (menos ruído) + aumento de coerência espectral

        double melhoriaRms = (antes.Rms - depois.Rms) / antes.Rms * 100.0;
        double melhoriaEspectral = (depois.PotenciaEspectral - antes.PotenciaEspectral) / antes.PotenciaEspectral * 50.0;

        double improvement = (melhoriaRms + melhoriaEspectral) / 1.5;

        // Normalizar para [0, 100]
        return Math.Clamp(improvement, 0, 100);
    }

    private double CalcularFrequenciaDominanteSimples(double[] amostras)
    {
        // TODO: Implementar FFT real (MathNet.Numerics)
        // Por agora, retorna estimativa baseada em zero-crossings
        int zeroCrossings = 0;
        for (int i = 1; i < amostras.Length; i++)
        {
            if ((amostras[i - 1] < 0 && amostras[i] >= 0) || (amostras[i - 1] >= 0 && amostras[i] < 0))
                zeroCrossings++;
        }

        double sampleRate = 1000.0; // Hz (configurável)
        double frequency = (zeroCrossings / 2.0) * (sampleRate / amostras.Length);
        return frequency;
    }

    private double EstimarImpedancia(double rms)
    {
        // Se corrente conhecida (ex: 1mA), calcular Z = V/I
        double correnteAplicada = 0.001; // 1mA (ajustar conforme configuração)
        return rms / correnteAplicada; // Ohms
    }

    public async Task PararCapturaAsync()
    {
        await Task.Run(() =>
        {
            lock (_lockObject)
            {
                if (_oscilloscopeHandle != IntPtr.Zero)
                {
                    ScpStop(_oscilloscopeHandle);
                    ObjClose(_oscilloscopeHandle);
                    _oscilloscopeHandle = IntPtr.Zero;
                    _isCapturing = false;
                    _logger.LogInformation("🛑 Captura parada");
                }
            }
        });
    }
}
```

---

#### **4. Integração no ViewModel**

Atualizar `TerapiasBioenergeticasUserControlViewModel.cs`:

```csharp
public partial class TerapiasBioenergeticasUserControlViewModel : ViewModelBase
{
    private readonly IMedicaoService _medicaoService; // ⬅️ NOVO

    [ObservableProperty] private double _improvementPercent; // ⬅️ NOVO
    [ObservableProperty] private bool _biofeedbackAtivo = true; // ⬅️ NOVO

    private MetricasBiofeedback? _medicaoInicial; // ⬅️ NOVO

    [RelayCommand]
    private async Task IniciarTerapiaAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            // ... código existente ...

            // ✅ NOVO: Iniciar captura de biofeedback
            if (BiofeedbackAtivo)
            {
                var configMedicao = new MedicaoConfig
                {
                    Canal = CanalSelecionado == "Ch1" ? 0 : 1,
                    SampleRateHz = 1000.0,
                    RecordLength = 1024
                };

                await _medicaoService.IniciarCapturaAsync(configMedicao);

                // Medição inicial (baseline)
                await Task.Delay(500); // Aguardar estabilização
                var amostrasInicial = await _medicaoService.LerAmostrasAsync(configMedicao.Canal, 1024);
                if (amostrasInicial != null)
                {
                    _medicaoInicial = await _medicaoService.CalcularMetricasAsync(amostrasInicial);
                }
            }

            // Loop de frequências
            for (int i = 0; i < _frequenciasRaw.Length; i++)
            {
                FrequenciaAtualIndex = i + 1;
                ProgressoTexto = $"Frequência {FrequenciaAtualIndex}/{TotalFrequencias}: {_frequenciasRaw[i]:N2} Hz";

                // Enviar sinal
                var config = new SignalConfiguration { /* ... */ };
                await _tiePieService.SendSignalAsync(config);

                // ✅ NOVO: Monitorizar Improvement % em tempo real
                if (BiofeedbackAtivo && _medicaoInicial != null)
                {
                    for (int t = 0; t < DuracaoPorFrequencia; t++)
                    {
                        await Task.Delay(1000); // 1 segundo

                        // Ler amostra atual
                        var amostrasAtual = await _medicaoService.LerAmostrasAsync(configMedicao.Canal, 1024);
                        if (amostrasAtual != null)
                        {
                            var medicaoAtual = await _medicaoService.CalcularMetricasAsync(amostrasAtual);
                            ImprovementPercent = _medicaoService.CalcularImprovementPercent(_medicaoInicial, medicaoAtual);

                            // Se Improvement ~100%, avançar automaticamente
                            if (ImprovementPercent >= 95.0)
                            {
                                _logger.LogInformation("✅ Improvement 100% atingido! Avançando...");
                                break;
                            }
                        }
                    }
                }
            }

            // Parar captura
            if (BiofeedbackAtivo)
            {
                await _medicaoService.PararCapturaAsync();
            }

        }, "ao executar terapia", _logger);
    }
}
```

---

#### **5. UI - Mostrar Improvement %**

Atualizar `TerapiasUserControl.xaml`:

```xml
<!-- Adicionar após seção de progresso -->
<Border Visibility="{Binding BiofeedbackAtivo, Converter={StaticResource BooleanToVisibilityConverter}}"
        Background="White" Padding="20" Margin="0,10,0,0" CornerRadius="8">
    <StackPanel>
        <TextBlock Text="📊 Biofeedback em Tempo Real" FontSize="16" FontWeight="SemiBold" Margin="0,0,0,10"/>

        <!-- Barra de progresso Improvement % -->
        <Grid>
            <ProgressBar Value="{Binding ImprovementPercent}" Maximum="100" Height="30"/>
            <TextBlock Text="{Binding ImprovementPercent, StringFormat='Improvement: {0:N1}%'}"
                       HorizontalAlignment="Center" VerticalAlignment="Center"
                       FontWeight="Bold" Foreground="White"/>
        </Grid>

        <TextBlock Text="Quando atingir ~100%, a frequência será automaticamente avançada"
                   FontSize="11" Foreground="#5A6558" Margin="0,5,0,0" FontStyle="Italic"/>
    </StackPanel>
</Border>
```

---

## 📦 **DEPENDÊNCIAS NECESSÁRIAS**

### **NuGet Packages:**
```bash
dotnet add package MathNet.Numerics --version 5.0.0
# Para FFT real (análise espectral)
```

---

## 🎯 **ROADMAP DE IMPLEMENTAÇÃO**

### **Fase 1: INPUT Básico (4-6 horas)**
1. ✅ Adicionar P/Invoke declarations (osciloscópio)
2. ✅ Criar `IMedicaoService` interface
3. ✅ Implementar `RealMedicaoService` básico (sem FFT)
4. ✅ Testar leitura de amostras

### **Fase 2: Métricas (2-3 horas)**
1. ✅ Implementar cálculo RMS
2. ✅ Implementar cálculo de picos
3. ✅ Implementar FFT (MathNet.Numerics)
4. ✅ Implementar cálculo Improvement %

### **Fase 3: Integração UI (2-3 horas)**
1. ✅ Adicionar `IMedicaoService` ao DI
2. ✅ Atualizar ViewModel com biofeedback
3. ✅ Adicionar UI para Improvement %
4. ✅ Testar fluxo completo

### **Fase 4: Otimizações (2-4 horas)**
1. ✅ Buffer circular para captura contínua
2. ✅ Threads dedicadas (evitar bloqueio UI)
3. ✅ Calibração automática de baseline
4. ✅ Logs de sessão com métricas

---

## 🧪 **TESTES NECESSÁRIOS**

### **Teste 1: Captura INPUT**
```csharp
// Verificar se consegue ler voltagens
var amostras = await _medicaoService.LerAmostrasAsync(canal: 0, numAmostras: 1024);
Assert.NotNull(amostras);
Assert.Equal(1024, amostras.Length);
```

### **Teste 2: Métricas**
```csharp
// Verificar cálculo de RMS
var metricas = await _medicaoService.CalcularMetricasAsync(amostras);
Assert.True(metricas.Rms > 0);
Assert.True(metricas.PicoPositivo > metricas.PicoNegativo);
```

### **Teste 3: Improvement %**
```csharp
// Simular melhoria
var antes = new MetricasBiofeedback { Rms = 2.0, PotenciaEspectral = 1.0 };
var depois = new MetricasBiofeedback { Rms = 1.5, PotenciaEspectral = 1.5 };
var improvement = _medicaoService.CalcularImprovementPercent(antes, depois);
Assert.True(improvement > 0 && improvement <= 100);
```

---

## 📝 **NOTAS IMPORTANTES**

1. **TiePie pode funcionar em modo DUPLO:**
   - Generator (OUTPUT) + Oscilloscope (INPUT) **simultaneamente**
   - Precisa verificar se SDK suporta 2 handles ao mesmo tempo

2. **Sample Rate:**
   - Para biofeedback: 1 kHz é suficiente
   - Para FFT: precisa potência de 2 (1024, 2048 amostras)

3. **Segurança:**
   - Limitar range de voltagem (±10V)
   - Monitorizar overflow (`ScpIsDataOverflow()`)

4. **Performance:**
   - Leitura em thread separada (`Task.Run`)
   - Buffer circular para não perder dados

---

## ✅ **RESULTADO FINAL**

Com esta implementação, terás:
- ✅ **Sentir corrente** (OUTPUT - já funciona)
- ✅ **Ler resposta fisiológica** (INPUT - novo)
- ✅ **Improvement % em tempo real** (cálculo - novo)
- ✅ **Biofeedback completo tipo CoRe 5.0** 🎯

---

**PRÓXIMO PASSO:** Implementar Fase 1 (INPUT Básico)?
