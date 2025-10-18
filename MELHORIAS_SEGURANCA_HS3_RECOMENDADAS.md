# 🛡️ Melhorias de Segurança HS3 - Guia de Implementação

**Data:** 17 de Outubro de 2025  
**Baseado em:** AUDITORIA_INTEGRACAO_HS3_COMPLETA.md  
**Status:** Recomendações Pendentes

---

## 🎯 Visão Geral

Este documento detalha as melhorias de segurança recomendadas após a auditoria completa da integração HS3. São melhorias **opcionais mas fortemente recomendadas** antes de uso clínico em produção.

---

## 🔴 Prioridade ALTA - Implementar Antes de Produção

### 1. Emergency Stop Global (Tecla de Atalho)

**Objetivo:** Parar emissão instantaneamente em caso de emergência médica.

**Localização:** `src/BioDesk.App/App.xaml.cs`

**Código a Adicionar:**

```csharp
// === EMERGENCY STOP HOTKEY ===
// Registar F12 como emergency stop global
private void RegisterEmergencyStopHotkey()
{
    // Usar InputBinding global no MainWindow
    var mainWindow = MainWindow;
    if (mainWindow != null)
    {
        var emergencyStopBinding = new KeyBinding(
            new RelayCommand(ExecuteEmergencyStop),
            Key.F12,
            ModifierKeys.None);
        
        mainWindow.InputBindings.Add(emergencyStopBinding);
        
        _logger?.LogInformation("🚨 Emergency Stop registado: F12");
    }
}

private void ExecuteEmergencyStop()
{
    _logger?.LogWarning("🚨 EMERGENCY STOP ATIVADO!");
    
    // Parar TiePieHS3Service
    var hs3Service = _serviceProvider?.GetService<ITiePieHS3Service>();
    if (hs3Service != null)
    {
        Task.Run(async () =>
        {
            await hs3Service.StopEmissionAsync();
            _logger?.LogInformation("✅ HS3 parado via emergency stop");
        });
    }
    
    // Parar FrequencyEmissionService
    var emissionService = _serviceProvider?.GetService<IFrequencyEmissionService>();
    if (emissionService != null)
    {
        Task.Run(async () =>
        {
            await emissionService.StopAsync();
            _logger?.LogInformation("✅ Emission service parado via emergency stop");
        });
    }
    
    // Mostrar mensagem visual
    MessageBox.Show(
        "🚨 EMERGENCY STOP ATIVADO!\n\nTodas as emissões foram paradas.",
        "Emergency Stop",
        MessageBoxButton.OK,
        MessageBoxImage.Warning);
}

// Chamar em OnStartup após criar MainWindow
protected override void OnStartup(StartupEventArgs e)
{
    base.OnStartup(e);
    
    // ... código existente ...
    
    RegisterEmergencyStopHotkey(); // ⬅️ ADICIONAR AQUI
}
```

**Documentação para Utilizador:**

Adicionar em Help/About:
```
🚨 EMERGENCY STOP: Pressione F12 a qualquer momento para parar 
todas as emissões instantaneamente.
```

---

### 2. Confirmação para Voltagens Altas

**Objetivo:** Prevenir emissões acidentais com voltagem perigosa.

**Localização:** `src/BioDesk.Services/Hardware/TiePie/TiePieHS3Service.cs`

**Modificar Método `EmitFrequencyAsync`:**

```csharp
public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine")
{
    return await Task.Run(() =>
    {
        if (!IsConnected)
        {
            _logger.LogWarning("⚠️ HS3 não conectado");
            return false;
        }
        
        // ✅ NOVA VALIDAÇÃO: Confirmação para voltagens altas
        if (amplitudeVolts > 5.0)
        {
            _logger.LogWarning("⚠️ Voltagem alta solicitada: {Voltage}V", amplitudeVolts);
            
            // Se em contexto UI, mostrar confirmação
            if (Application.Current?.Dispatcher != null)
            {
                var confirmed = false;
                Application.Current.Dispatcher.Invoke(() =>
                {
                    var result = MessageBox.Show(
                        $"⚠️ ATENÇÃO: Voltagem Alta\n\n" +
                        $"Está prestes a emitir {amplitudeVolts:F1}V.\n" +
                        $"Frequência: {frequencyHz:F2} Hz\n" +
                        $"Forma de Onda: {waveform}\n\n" +
                        $"Confirma que:\n" +
                        $"• Verificou as ligações dos eletrodos\n" +
                        $"• Paciente está preparado\n" +
                        $"• Valores estão corretos\n\n" +
                        $"Deseja continuar?",
                        "Confirmação de Voltagem Alta",
                        MessageBoxButton.YesNo,
                        MessageBoxImage.Warning);
                    
                    confirmed = (result == MessageBoxResult.Yes);
                });
                
                if (!confirmed)
                {
                    _logger.LogInformation("❌ Emissão cancelada pelo utilizador (voltagem alta)");
                    return false;
                }
            }
        }
        
        // ✅ NOVA VALIDAÇÃO: Máximo absoluto 10V (segurança)
        if (amplitudeVolts > 10.0)
        {
            _logger.LogError("❌ Voltagem excede máximo permitido: {Voltage}V > 10V", amplitudeVolts);
            return false;
        }
        
        try
        {
            _logger.LogInformation($"🎵 Configurando emissão: {frequencyHz} Hz @ {amplitudeVolts}V ({waveform})");
            
            // ... resto do código existente ...
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao emitir frequência");
            return false;
        }
    });
}
```

**Configuração de Limites (Opcional):**

Adicionar em `appsettings.json`:

```json
{
  "Hardware": {
    "HS3": {
      "MaxVoltageWithoutConfirmation": 5.0,
      "AbsoluteMaxVoltage": 10.0,
      "DefaultSafeVoltage": 2.0
    }
  }
}
```

---

### 3. Timeout Automático de Emissão

**Objetivo:** Prevenir emissões prolongadas acidentalmente (ex: bug de UI, processo travado).

**Localização:** `src/BioDesk.Services/Hardware/TiePie/TiePieHS3Service.cs`

**Adicionar Campos:**

```csharp
private System.Threading.Timer? _emissionTimer;
private const int MAX_EMISSION_SECONDS = 1800; // 30 minutos
```

**Modificar `EmitFrequencyAsync`:**

```csharp
public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine")
{
    return await Task.Run(() =>
    {
        // ... código de validação existente ...
        
        try
        {
            // ... configuração de sinal existente ...
            
            // 6. Iniciar geração
            if (!HS3Native.GenStart(_deviceHandle))
            {
                _logger.LogError("❌ Falha ao iniciar geração de sinal");
                return false;
            }
            
            _logger.LogInformation($"✅ Emissão iniciada: {actualFreq:F2} Hz @ {actualAmp:F2}V");
            
            // ✅ NOVO: Timeout automático de 30 minutos
            _emissionTimer?.Dispose(); // Cancelar timer anterior se existir
            _emissionTimer = new System.Threading.Timer(
                callback: _ =>
                {
                    _logger.LogWarning("⏰ TIMEOUT: Emissão automática após {Minutes} minutos", MAX_EMISSION_SECONDS / 60);
                    StopEmissionAsync().Wait();
                    
                    // Notificar utilizador (se possível)
                    Application.Current?.Dispatcher.Invoke(() =>
                    {
                        MessageBox.Show(
                            $"⏰ Emissão Automática Parada\n\n" +
                            $"A emissão foi automaticamente interrompida após {MAX_EMISSION_SECONDS / 60} minutos " +
                            $"por segurança.\n\n" +
                            $"Se desejar continuar, inicie novamente a emissão.",
                            "Timeout de Segurança",
                            MessageBoxButton.OK,
                            MessageBoxImage.Information);
                    });
                },
                state: null,
                dueTime: TimeSpan.FromSeconds(MAX_EMISSION_SECONDS),
                period: Timeout.InfiniteTimeSpan);
            
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao emitir frequência");
            return false;
        }
    });
}
```

**Modificar `StopEmissionAsync`:**

```csharp
public async Task StopEmissionAsync()
{
    await Task.Run(() =>
    {
        if (!IsConnected)
        {
            return;
        }
        
        try
        {
            _logger.LogInformation("⏹️ Parando emissão...");
            
            // ✅ NOVO: Cancelar timer de timeout
            _emissionTimer?.Dispose();
            _emissionTimer = null;
            
            // Parar geração
            HS3Native.GenStop(_deviceHandle);
            
            // Desativar saída
            HS3Native.GenSetOutputOn(_deviceHandle, false);
            
            _logger.LogInformation("✅ Emissão parada");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao parar emissão");
        }
    });
}
```

**Modificar `Dispose`:**

```csharp
protected virtual void Dispose(bool disposing)
{
    if (_disposed)
        return;
    
    if (disposing)
    {
        try
        {
            // ✅ NOVO: Cancelar timer
            _emissionTimer?.Dispose();
            _emissionTimer = null;
            
            // Parar emissão se estiver ativa
            if (IsConnected)
            {
                HS3Native.GenStop(_deviceHandle);
                HS3Native.GenSetOutputOn(_deviceHandle, false);
                HS3Native.DevClose(_deviceHandle);
                _deviceHandle = nint.Zero;
                _logger.LogInformation("🔌 HS3 desconectado");
            }
            
            // ... resto do código existente ...
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao fazer dispose do HS3Service");
        }
    }
    
    _disposed = true;
}
```

---

## 🟡 Prioridade MÉDIA - Melhorias Futuras

### 4. Session Logging para Auditoria

**Objetivo:** Registar todas as sessões de emissão para rastreabilidade médica.

**Criar Novo Serviço:** `src/BioDesk.Services/Logging/EmissionSessionLogger.cs`

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using BioDesk.Services;

namespace BioDesk.Services.Logging;

/// <summary>
/// Registo de sessões de emissão HS3 para auditoria médica
/// </summary>
public class EmissionSessionLogger
{
    private readonly string _logDirectory;
    
    public EmissionSessionLogger()
    {
        _logDirectory = Path.Combine(PathService.LogsPath, "EmissionSessions");
        Directory.CreateDirectory(_logDirectory);
    }
    
    public void LogSession(EmissionSession session)
    {
        try
        {
            var fileName = $"Sessions_{DateTime.Now:yyyyMM}.jsonl";
            var filePath = Path.Combine(_logDirectory, fileName);
            
            var json = JsonSerializer.Serialize(session, new JsonSerializerOptions
            {
                WriteIndented = false
            });
            
            File.AppendAllText(filePath, json + "\n");
        }
        catch (Exception ex)
        {
            // Não falhar aplicação por erro de logging
            Console.WriteLine($"⚠️ Erro ao registar sessão: {ex.Message}");
        }
    }
    
    public List<EmissionSession> GetSessionsForMonth(int year, int month)
    {
        var sessions = new List<EmissionSession>();
        var fileName = $"Sessions_{year:0000}{month:00}.jsonl";
        var filePath = Path.Combine(_logDirectory, fileName);
        
        if (!File.Exists(filePath))
            return sessions;
        
        foreach (var line in File.ReadLines(filePath))
        {
            try
            {
                var session = JsonSerializer.Deserialize<EmissionSession>(line);
                if (session != null)
                    sessions.Add(session);
            }
            catch
            {
                // Ignorar linhas inválidas
            }
        }
        
        return sessions;
    }
}

/// <summary>
/// Dados de uma sessão de emissão
/// </summary>
public record EmissionSession
{
    public Guid SessionId { get; init; } = Guid.NewGuid();
    public DateTime StartTime { get; init; }
    public DateTime EndTime { get; init; }
    public int? PatientId { get; init; }
    public string PatientName { get; init; } = string.Empty;
    public double FrequencyHz { get; init; }
    public double AmplitudeVolts { get; init; }
    public string Waveform { get; init; } = "Sine";
    public TimeSpan Duration { get; init; }
    public bool CompletedSuccessfully { get; init; }
    public string? ErrorMessage { get; init; }
    public string Operator { get; init; } = Environment.UserName;
}
```

**Integrar em TiePieHS3Service:**

```csharp
private readonly EmissionSessionLogger _sessionLogger;
private EmissionSession? _currentSession;

public TiePieHS3Service(ILogger<TiePieHS3Service> logger, EmissionSessionLogger sessionLogger)
{
    _logger = logger;
    _sessionLogger = sessionLogger;
}

public async Task<bool> EmitFrequencyAsync(double frequencyHz, double amplitudeVolts, string waveform = "Sine")
{
    return await Task.Run(() =>
    {
        // ... validações ...
        
        // ✅ Iniciar sessão
        _currentSession = new EmissionSession
        {
            StartTime = DateTime.UtcNow,
            FrequencyHz = frequencyHz,
            AmplitudeVolts = amplitudeVolts,
            Waveform = waveform,
            // TODO: Obter dados do paciente atual
        };
        
        try
        {
            // ... emissão ...
            
            return true;
        }
        catch (Exception ex)
        {
            // ✅ Registar erro
            if (_currentSession != null)
            {
                _sessionLogger.LogSession(_currentSession with
                {
                    EndTime = DateTime.UtcNow,
                    Duration = DateTime.UtcNow - _currentSession.StartTime,
                    CompletedSuccessfully = false,
                    ErrorMessage = ex.Message
                });
            }
            
            throw;
        }
    });
}

public async Task StopEmissionAsync()
{
    // ... parar emissão ...
    
    // ✅ Registar sessão completa
    if (_currentSession != null)
    {
        _sessionLogger.LogSession(_currentSession with
        {
            EndTime = DateTime.UtcNow,
            Duration = DateTime.UtcNow - _currentSession.StartTime,
            CompletedSuccessfully = true
        });
        
        _currentSession = null;
    }
}
```

**Registar em DI (App.xaml.cs):**

```csharp
services.AddSingleton<EmissionSessionLogger>();
```

---

### 5. Hardware Health Check

**Objetivo:** Verificar se HS3 está funcionando corretamente antes de sessão clínica.

**Adicionar em ITiePieHS3Service:**

```csharp
/// <summary>
/// Verifica saúde do hardware com teste de emissão rápido
/// </summary>
Task<HealthCheckResult> VerifyHardwareHealthAsync();
```

**Implementar em TiePieHS3Service:**

```csharp
public async Task<HealthCheckResult> VerifyHardwareHealthAsync()
{
    return await Task.Run(() =>
    {
        if (!IsConnected)
        {
            return new HealthCheckResult
            {
                IsHealthy = false,
                Message = "HS3 não conectado"
            };
        }
        
        try
        {
            _logger.LogInformation("🔍 Verificando saúde do hardware HS3...");
            
            // Teste 1: Emitir 440 Hz @ 0.5V por 500ms
            var testSuccess = EmitTestFrequency(440.0, 0.5, TimeSpan.FromMilliseconds(500));
            
            if (!testSuccess)
            {
                return new HealthCheckResult
                {
                    IsHealthy = false,
                    Message = "Falha ao emitir frequência de teste"
                };
            }
            
            // Teste 2: Verificar se consegue parar
            HS3Native.GenStop(_deviceHandle);
            HS3Native.GenSetOutputOn(_deviceHandle, false);
            
            // Teste 3: Verificar leitura de configuração
            var freq = HS3Native.GenGetFrequency(_deviceHandle);
            var amp = HS3Native.GenGetAmplitude(_deviceHandle);
            
            _logger.LogInformation("✅ Hardware HS3 saudável");
            
            return new HealthCheckResult
            {
                IsHealthy = true,
                Message = "Hardware funcionando corretamente",
                Details = new Dictionary<string, string>
                {
                    { "LastFrequency", $"{freq:F2} Hz" },
                    { "LastAmplitude", $"{amp:F2} V" },
                    { "SerialNumber", SerialNumber.ToString() }
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao verificar saúde do hardware");
            
            return new HealthCheckResult
            {
                IsHealthy = false,
                Message = $"Erro: {ex.Message}"
            };
        }
    });
}

private bool EmitTestFrequency(double hz, double volts, TimeSpan duration)
{
    try
    {
        HS3Native.GenSetSignalType(_deviceHandle, (uint)HS3Native.SignalType.Sine);
        HS3Native.GenSetFrequency(_deviceHandle, hz);
        HS3Native.GenSetAmplitude(_deviceHandle, volts);
        HS3Native.GenSetOutputOn(_deviceHandle, true);
        HS3Native.GenStart(_deviceHandle);
        
        System.Threading.Thread.Sleep(duration);
        
        HS3Native.GenStop(_deviceHandle);
        HS3Native.GenSetOutputOn(_deviceHandle, false);
        
        return true;
    }
    catch
    {
        return false;
    }
}

public record HealthCheckResult
{
    public bool IsHealthy { get; init; }
    public string Message { get; init; } = string.Empty;
    public Dictionary<string, string>? Details { get; init; }
}
```

**Usar em TesteHS3ViewModel:**

```csharp
[RelayCommand]
private async Task VerificarSaudeAsync()
{
    AddLog("🔍 Verificando saúde do hardware...");
    
    var result = await _hs3Service.VerifyHardwareHealthAsync();
    
    if (result.IsHealthy)
    {
        AddLog("✅ Hardware saudável!");
        if (result.Details != null)
        {
            foreach (var (key, value) in result.Details)
            {
                AddLog($"   {key}: {value}");
            }
        }
    }
    else
    {
        AddLog($"❌ Problema detectado: {result.Message}");
    }
}
```

---

## 🟢 Prioridade BAIXA - Nice to Have

### 6. Mutex para Acesso Exclusivo (Prevenção de Conflito)

**Objetivo:** Garantir que apenas 1 aplicação acede ao HS3 por vez (BioDeskPro2 OU CoRe).

**Modificar TiePieHS3Service.cs:**

```csharp
private static Mutex? _hs3AccessMutex;

public async Task<bool> InitializeAsync()
{
    return await Task.Run(() =>
    {
        try
        {
            _logger.LogInformation("🔌 Inicializando TiePie HS3...");
            
            // ✅ Tentar adquirir mutex global
            _hs3AccessMutex = new Mutex(false, "Global\\TiePieHS3Access");
            
            if (!_hs3AccessMutex.WaitOne(0)) // Timeout 0 = não bloquear
            {
                _logger.LogWarning("⚠️ HS3 já em uso por outra aplicação (ex: Inergetix CoRe)");
                _hs3AccessMutex.Dispose();
                _hs3AccessMutex = null;
                return false;
            }
            
            // Inicializar biblioteca
            if (!HS3Native.LibInit())
            {
                _logger.LogError("❌ Falha ao inicializar hs3.dll");
                _hs3AccessMutex?.ReleaseMutex();
                _hs3AccessMutex?.Dispose();
                _hs3AccessMutex = null;
                return false;
            }
            
            // ... resto do código existente ...
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao inicializar HS3");
            _hs3AccessMutex?.ReleaseMutex();
            _hs3AccessMutex?.Dispose();
            _hs3AccessMutex = null;
            return false;
        }
    });
}

protected virtual void Dispose(bool disposing)
{
    if (_disposed)
        return;
    
    if (disposing)
    {
        try
        {
            // ... código existente ...
            
            // ✅ Liberar mutex
            _hs3AccessMutex?.ReleaseMutex();
            _hs3AccessMutex?.Dispose();
            _hs3AccessMutex = null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao fazer dispose do HS3Service");
        }
    }
    
    _disposed = true;
}
```

**Nota:** Esta implementação garante que:
- Se CoRe estiver usando HS3, BioDeskPro2 detecta e usa modo dummy
- Se BioDeskPro2 estiver usando HS3, CoRe detecta e usa modo simulação
- Apenas 1 aplicação acede ao hardware por vez

---

## 📋 Checklist de Implementação

### Prioridade Alta (Antes de Produção)

- [ ] **Emergency Stop Hotkey (F12)** implementado
- [ ] **Confirmação Voltagens > 5V** implementada
- [ ] **Timeout Automático 30min** implementado
- [ ] Testar emergency stop em cenário real
- [ ] Testar timeout em emissão prolongada
- [ ] Documentar F12 no manual de utilizador

### Prioridade Média (Próxima Sprint)

- [ ] **Session Logging** implementado
- [ ] **Hardware Health Check** implementado
- [ ] UI para visualizar histórico de sessões
- [ ] Botão "Verificar Hardware" em TesteHS3View
- [ ] Exportar logs de sessão para CSV

### Prioridade Baixa (Futuro)

- [ ] **Mutex Global** implementado
- [ ] Testar coexistência com CoRe
- [ ] UI para calibração de voltagem
- [ ] Profiles de emissão salvos

---

## 🧪 Plano de Testes

### Teste 1: Emergency Stop

1. Iniciar emissão 7.83 Hz @ 2V
2. Pressionar F12
3. **Esperado:** Emissão para instantaneamente
4. **Verificar:** Log registra "EMERGENCY STOP ATIVADO"

### Teste 2: Confirmação Voltagem Alta

1. Configurar emissão 100 Hz @ 6V
2. Iniciar emissão
3. **Esperado:** Aparece dialog de confirmação
4. Clicar "Não"
5. **Verificar:** Emissão NÃO inicia
6. Repetir e clicar "Sim"
7. **Verificar:** Emissão inicia normalmente

### Teste 3: Timeout Automático

1. Iniciar emissão 7.83 Hz @ 2V
2. Aguardar 30 minutos (ou reduzir timeout para 1 minuto para teste)
3. **Esperado:** Emissão para automaticamente
4. **Verificar:** Log registra "TIMEOUT"
5. **Verificar:** Aparece MessageBox informando utilizador

### Teste 4: Session Logging

1. Iniciar e parar 3 emissões diferentes
2. Abrir ficheiro `Logs/EmissionSessions/Sessions_YYYYMM.jsonl`
3. **Verificar:** 3 entradas JSON com dados corretos
4. **Verificar:** Timestamps, frequências, voltagens corretas

### Teste 5: Hardware Health Check

1. HS3 conectado: Executar health check
2. **Esperado:** Retorna "Hardware saudável"
3. HS3 desconectado: Executar health check
4. **Esperado:** Retorna "HS3 não conectado"

---

## 📞 Suporte

**Em caso de dúvidas sobre implementação:**
1. Consultar esta documentação
2. Consultar `AUDITORIA_INTEGRACAO_HS3_COMPLETA.md`
3. Consultar `IMPLEMENTACAO_HS3_COMPLETA_17OUT2025.md`

**Em caso de problemas técnicos:**
1. Verificar logs em `Logs/EmissionSessions/`
2. Verificar console de debugging
3. Testar com TesteHS3ViewModel primeiro

---

**Última Atualização:** 17 de Outubro de 2025  
**Versão:** 1.0.0  
**Status:** ⏳ Pendente de Implementação
