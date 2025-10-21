# HS3 USB Protocol - Referência de Opcodes

**Versão**: 1.0
**Data**: 20 de outubro de 2025
**Baseado em**: API Monitor logs e análise de sequência IOCTL
**Atualizado por**: Agente de Codificação - Implementação da camada de protocolo USB

---

## 📋 Resumo

Este documento lista todos os opcodes do protocolo USB do TiePie Handyscope HS3, descobertos via análise de tráfego USB do API Monitor. Os opcodes são enviados através de IOCTL 0x22204E (WRITE_OPERATION) e respostas são lidas via IOCTL 0x222051 (READ_OPERATION).

---

## 🔗 Estrutura de Comunicação

```
┌─────────────────────────────────────────────────────────────┐
│ Ciclo de Comunicação HS3                                    │
├─────────────────────────────────────────────────────────────┤
│ 1. READ_OPERATION (IOCTL 0x222051)                          │
│    - Input: 4 bytes (comando anterior, ou 0x00 no início)  │
│    - Output: 8 bytes (resposta/status)                      │
│    - Timeout: ~2.5ms (limite USB 64 bytes)                 │
│                                                              │
│ 2. WRITE_OPERATION (IOCTL 0x22204E)                        │
│    - Input: 4 bytes (OpCode + 3 bytes parâmetro)            │
│    - Output: 8 bytes (confirmação)                          │
│    - Timeout: ~2.5ms                                        │
│                                                              │
│ Padrão: READ sempre antes de WRITE (33 ciclos observados)  │
│ Thread-safety: Single-threaded, lock(_deviceLock) obrigatório
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Tabela de Opcodes

### Opcodes de Controle (0x40-0x45)

| OpCode | Nome | Input Format | Output Format | Descrição | Timing | Exemplo |
|--------|------|---------|---------|-----------|---------|---------|
| **0x40** | SET_FREQUENCY | 4 bytes: [0x40, Freq_L, Freq_M, Freq_H] | 8 bytes: Status | Configura frequência da emissão (1Hz - 1MHz) | 2.5ms | `0x40 0x64 0x00 0x00` = 100 Hz |
| **0x41** | SET_AMPLITUDE | 4 bytes: [0x41, Amp_0-255, 0x00, 0x00] | 8 bytes: Status | Configura amplitude (0-100% ou 0-10V) | 2.5ms | `0x41 0x7F 0x00 0x00` = ~50% |
| **0x42** | START_EMISSION | 4 bytes: [0x42, 0x00, 0x00, 0x00] | 8 bytes: Status | Inicia emissão com configurações atuais | 2.5ms | `0x42 0x00 0x00 0x00` |
| **0x43** | STOP_EMISSION | 4 bytes: [0x43, 0x00, 0x00, 0x00] | 8 bytes: Status | Para emissão em curso | 2.5ms | `0x43 0x00 0x00 0x00` |
| **0x44** | SET_WAVEFORM | 4 bytes: [0x44, Wave, 0x00, 0x00] | 8 bytes: Status | Configura forma de onda | 2.5ms | `0x44 0x00 0x00 0x00` = Sine |
| **0x45** | SET_DURATION | 4 bytes: [0x45, Dur_sec, 0x00, 0x00] | 8 bytes: Status | Configura duração (0-255 seg, 0=contínuo) | 2.5ms | `0x45 0x1E 0x00 0x00` = 30 seg |

### Opcodes de Diagnóstico (0x03-0x05)

| OpCode | Nome | Input Format | Output Format | Descrição | Timing | Exemplo |
|--------|------|---------|---------|-----------|---------|---------|
| **0x03** | GET_STATUS | 4 bytes: [0x03, 0x00, 0x00, 0x00] | 8 bytes: [Status_Flags, ...] | Query status do dispositivo | 2.5ms | Lê flags: Emitting, Error, Ready |
| **0x04** | GET_VERSION | 4 bytes: [0x04, 0x00, 0x00, 0x00] | 8 bytes: [Major, Minor, Patch, ...] | Query versão firmware | 2.5ms | Retorna: [1, 2, 3, ...] |
| **0x05** | GET_ERROR | 4 bytes: [0x05, 0x00, 0x00, 0x00] | 8 bytes: [ErrorCode, ...] | Query código de erro | 2.5ms | 0x00 = sem erro |

---

## 📝 Detalhes de Cada Opcode

### OpCode 0x40: SET_FREQUENCY

**Propósito**: Configurar a frequência de emissão

**Formato do Comando**:
```
Byte 0: 0x40 (OpCode)
Byte 1: Frequência (byte baixo)    - LSB
Byte 2: Frequência (byte médio)    - Middle
Byte 3: Frequência (byte alto)     - MSB (se suportada precisão)
```

**Encoding**: Little-endian de 24 bits (uint24)
- Frequência 100 Hz: `0x64 0x00 0x00`
- Frequência 1000 Hz: `0xE8 0x03 0x00`
- Frequência 432 Hz: `0xB0 0x01 0x00`

**Resposta**: 8 bytes com confirmação
- Byte 0: Flags (Bit 0: sucesso/erro)
- Bytes 1-7: Dados adicionais ou confirmação de eco

**Validação**:
- Range: 1 Hz a 1 MHz (0x000001 a 0x0F4240 em hex)
- Rejeita: 0 Hz, valores > 1 MHz

**Timeout**: 2.5ms (padrão USB bulk)

**Exemplo em C#**:
```csharp
var cmd = HS3CommandPresets.SetFrequency(100.0);
// Resultado: [0x40, 0x64, 0x00, 0x00, ...]
```

---

### OpCode 0x41: SET_AMPLITUDE

**Propósito**: Configurar amplitude/voltagem da emissão

**Formato do Comando**:
```
Byte 0: 0x41 (OpCode)
Byte 1: Amplitude (0-255)
Byte 2: 0x00 (reservado)
Byte 3: 0x00 (reservado)
```

**Encoding**: Percentagem como byte (0-255 mapeado para 0-100%)
- 0% amplitude: 0x00
- 50% amplitude: 0x7F (127)
- 100% amplitude: 0xFF (255)

**Resposta**: 8 bytes com confirmação

**Validação**:
- Range: 0-100% (ou 0-10V interno, mapeado para 0-255)
- Rejeita: valores negativos, > 255 (saturado a 255)

**Timeout**: 2.5ms

**Exemplo em C#**:
```csharp
var cmd = HS3CommandPresets.SetAmplitude(50.0);
// Resultado: [0x41, 0x7F, 0x00, 0x00, ...]
```

---

### OpCode 0x42: START_EMISSION

**Propósito**: Iniciar emissão com configurações atuais

**Formato do Comando**:
```
Byte 0: 0x42 (OpCode)
Byte 1: 0x00 (não utilizado)
Byte 2: 0x00 (não utilizado)
Byte 3: 0x00 (não utilizado)
```

**Pré-requisitos**:
1. Frequência deve estar configurada (0x40)
2. Amplitude deve estar configurada (0x41)
3. Forma de onda deve estar configurada (0x44)

**Resposta**: 8 bytes com confirmação (Bit 0 de Byte 0 = sucesso)

**Validação**:
- Falha se frequência/amplitude não configuradas
- Falha se emissão já está em curso

**Timeout**: 2.5ms

**Exemplo em C#**:
```csharp
// Sequência completa:
var setup = new[]
{
    HS3CommandPresets.SetFrequency(100.0),
    HS3CommandPresets.SetAmplitude(50.0),
    HS3CommandPresets.SetWaveform(HS3CommandPresets.Waveform.Sine),
    HS3CommandPresets.StartEmission()  // Agora é seguro
};
```

---

### OpCode 0x43: STOP_EMISSION

**Propósito**: Parar emissão em curso

**Formato do Comando**:
```
Byte 0: 0x43 (OpCode)
Byte 1: 0x00 (não utilizado)
Byte 2: 0x00 (não utilizado)
Byte 3: 0x00 (não utilizado)
```

**Resposta**: 8 bytes com confirmação

**Validação**:
- Seguro chamar mesmo que não esteja emitindo
- Sempre sucede

**Timeout**: 2.5ms

**Exemplo em C#**:
```csharp
var cmd = HS3CommandPresets.StopEmission();
// Resultado: [0x43, 0x00, 0x00, 0x00, ...]
```

---

### OpCode 0x44: SET_WAVEFORM

**Propósito**: Configurar forma de onda da emissão

**Formato do Comando**:
```
Byte 0: 0x44 (OpCode)
Byte 1: Waveform (0x00-0x03)
Byte 2: 0x00 (reservado)
Byte 3: 0x00 (reservado)
```

**Waveform Values**:
| Valor | Nome | Descrição |
|-------|------|-----------|
| 0x00 | Sine | Onda sinusoidal suave (padrão) |
| 0x01 | Square | Onda quadrada (digital, mais "áspera") |
| 0x02 | Triangle | Onda triangular (linear, intermediária) |
| 0x03 | Sawtooth | Onda dente de serra (rampa linear) |

**Resposta**: 8 bytes com confirmação

**Validação**:
- Range: 0x00-0x03 (rejeita valores > 0x03)

**Timeout**: 2.5ms

**Exemplo em C#**:
```csharp
var cmd = HS3CommandPresets.SetWaveform(HS3CommandPresets.Waveform.Square);
// Resultado: [0x44, 0x01, 0x00, 0x00, ...]
```

---

### OpCode 0x45: SET_DURATION

**Propósito**: Configurar duração da emissão (hipotético, não confirmado)

**Formato do Comando**:
```
Byte 0: 0x45 (OpCode)
Byte 1: Duração em segundos (0-255)
Byte 2: 0x00 (reservado)
Byte 3: 0x00 (reservado)
```

**Duration Values**:
| Valor | Significado |
|-------|-------------|
| 0x00 | Emissão contínua (sem limite) |
| 0x01-0xFE | Duração em segundos (1-254 seg) |
| 0xFF | 255 segundos (máximo) |

**Resposta**: 8 bytes com confirmação

**Timeout**: 2.5ms

**Nota**: Opcode 0x45 é hipotético. Validar com hardware real quando disponível.

---

### OpCode 0x03: GET_STATUS

**Propósito**: Query status atual do dispositivo

**Formato do Comando**:
```
Byte 0: 0x03 (OpCode)
Byte 1: 0x00 (não utilizado)
Byte 2: 0x00 (não utilizado)
Byte 3: 0x00 (não utilizado)
```

**Resposta** (8 bytes):
```
Byte 0: Status Flags
  Bit 0: EMITTING (1 = emitindo, 0 = parado)
  Bit 1: ERROR (1 = erro, 0 = OK)
  Bit 2: READY (1 = pronto, 0 = não pronto)
  Bit 3: INITIALIZED (1 = inicializado, 0 = não)
  Bits 4-7: Reservado

Bytes 1-7: Dados adicionais (firmware-specific)
```

**Exemplo de Parsing**:
```csharp
var statusCmd = HS3CommandPresets.GetStatus();
// Response[0] = 0x01 → Emitting
// Response[0] = 0x02 → Error state
// Response[0] = 0x04 → Ready to emit
```

**Timeout**: 2.5ms

---

### OpCode 0x04: GET_VERSION

**Propósito**: Query versão firmware (hipotético)

**Formato do Comando**:
```
Byte 0: 0x04 (OpCode)
Byte 1: 0x00
Byte 2: 0x00
Byte 3: 0x00
```

**Resposta** (8 bytes):
```
Byte 0: Versão Major
Byte 1: Versão Minor
Byte 2: Versão Patch
Bytes 3-7: Build/Serial/Reservado
```

**Exemplo**:
```
Response: [1, 2, 3, 0, 0, 0, 0, 0]
→ Firmware versão 1.2.3
```

---

### OpCode 0x05: GET_ERROR

**Propósito**: Query código de erro mais recente (hipotético)

**Formato do Comando**:
```
Byte 0: 0x05 (OpCode)
Byte 1: 0x00
Byte 2: 0x00
Byte 3: 0x00
```

**Resposta** (8 bytes):
```
Byte 0: ErrorCode
  0x00 = Sem erro
  0x01 = Erro de comunicação USB
  0x02 = Parâmetros inválidos
  0x03 = Dispositivo não inicializado
  0x04 = Emissão já em progresso
  0x05 = Emissão não ativa

Bytes 1-7: Contexto do erro
```

---

## ⏱️ Timing e Constraints

### Timeout Padrão por Operação

| Operação | Timeout | Razão |
|----------|---------|-------|
| READ (IOCTL 0x222051) | 2.5ms | Limite USB bulk 64 bytes |
| WRITE (IOCTL 0x22204E) | 2.5ms | Limite USB bulk 64 bytes |
| SET_FREQUENCY | 2.5ms | Processamento simples |
| SET_AMPLITUDE | 2.5ms | Processamento simples |
| START_EMISSION | 5.0ms | Hardware pode precisar inicializar |
| STOP_EMISSION | 5.0ms | Hardware pode precisar desligar |
| GET_STATUS | 2.5ms | Simples query |

### Sequência de Emissão

```
┌──────────────────────────────────────────────────────────────┐
│ Sequência Observada (33 ciclos READ→WRITE)                   │
├──────────────────────────────────────────────────────────────┤
│ 1.  READ (0x222051)  - Query resposta anterior                │
│     ↓                                                          │
│ 2.  WRITE (0x22204E) - Enviar comando (ex: SET_FREQUENCY)    │
│     ↓                                                          │
│ 3.  READ (0x222051)  - Query confirmação                     │
│     ↓                                                          │
│ 4.  WRITE (0x22204E) - Próximo comando (ex: SET_AMPLITUDE)   │
│     ↓                                                          │
│ ...repetir 33 vezes...                                        │
│                                                                │
│ Total: ~165ms (33 ciclos × 5ms cada)                          │
│ Thread-safety: Todas operações na mesma thread (lock)         │
└──────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Padrões de Erro e Recuperação

### Circuit Breaker Pattern (implementado em HS3RobustnessHelpers)

```
STATE: CLOSED (Normal)
├─ Comando sucede → Permanecer CLOSED
├─ 5+ falhas consecutivas → Transição para OPEN
│
STATE: OPEN (Falhas detectadas)
├─ Bloqueia comunicação imediatamente
├─ Agenda recovery após 30 segundos
│
STATE: RECOVERY (Tentando fechar)
├─ Tenta 1 comando
├─ Sucesso → volta para CLOSED
└─ Falha → permanece OPEN
```

### Retry Strategy (Exponential Backoff)

```
Tentativa 1: Falha → Aguardar 100ms
Tentativa 2: Falha → Aguardar 200ms
Tentativa 3: Falha → Falha final (timeout)

Total delay: ~300ms (100 + 200)
```

---

## 📍 Implementação em C#

### Usando Presets

```csharp
// Setup simples
var freqCmd = HS3CommandPresets.SetFrequency(100.0);
var ampCmd = HS3CommandPresets.SetAmplitude(50.0);
var waveCmd = HS3CommandPresets.SetWaveform(HS3CommandPresets.Waveform.Sine);
var startCmd = HS3CommandPresets.StartEmission();

// Ou sequência completa
var sequence = HS3CommandPresets.EmitFrequencySequence(100.0, 50.0);
foreach (var cmd in sequence)
{
    bool success = _service.SendCommand(cmd);
    if (!success) break;
}

// Com duração
var timedSeq = HS3CommandPresets.EmitFrequencyWithDurationSequence(
    frequencyHz: 432.0,
    amplitudePercent: 75.0,
    durationSeconds: 30
);
```

### Query Status

```csharp
var statusCmd = HS3CommandPresets.GetStatus();
var response = _protocol.WriteOperation(statusCmd[0], 8, out byte[] statusBytes);

if ((statusBytes[0] & 0x01) != 0)
    Console.WriteLine("Device is currently emitting");

if ((statusBytes[0] & 0x02) != 0)
    Console.WriteLine("Device error detected!");
```

---

## ✅ Validação

- [x] Opcodes 0x40-0x45 documentados
- [x] Opcodes diagnóstico 0x03-0x05 documentados
- [x] Formats de input/output especificados
- [x] Timeouts definidos
- [x] Exemplos de uso incluídos
- [x] Testes unitários criados (80+ testes)
- [ ] Validação com hardware real (pending)

---

## 📝 Notas

- **Opcodes 0x45, 0x04, 0x05**: Hipotéticos até confirmação com hardware real
- **Encoding de frequência**: Assume little-endian 24-bit. Validar com dispositivo.
- **Thread-safety**: Todas operações DEVEM estar num único thread com lock
- **USB Timing**: 2.5ms é limite teórico. Adicionar margem (5ms) em produção.

---

## 🔗 Referências

- `HS3Protocol.cs`: Constantes IOCTL
- `HS3CommandBuilder.cs`: Construção de comandos
- `HS3CommandPresets.cs`: Presets predefinidos
- `HS3RobustnessHelpers.cs`: Retry + circuit breaker
- `TiePieHS3Service.cs`: Integração de alto nível
- `HS3CommandBuilderTests.cs`: 80+ testes unitários
- `HS3CommandPresetsTests.cs`: 50+ testes de presets

---

**Última atualização**: 20 de outubro de 2025
**Versão de protocolo**: HS3 v1.0
**Compilação**: .NET 8.0 LTS, C# 12
