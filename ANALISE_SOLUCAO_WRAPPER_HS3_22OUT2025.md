# 🔧 ANÁLISE - Solução Wrapper DLL hs3.dll (Compatibilidade Core + Novo Driver)

**Data**: 22 de outubro de 2025
**Contexto**: Proposta de criar DLL wrapper que traduz API antiga hs3.dll → SDK novo libtiepie-hw
**Objetivo**: Permitir Inergetix Core usar novo driver TiePie sem modificações no Core

---

## 🎯 RESUMO EXECUTIVO

### Conceito da Solução
Criar **DLL intermediária** (`hs3.dll` substituta) que:
1. **Exporta** as mesmas funções que a hs3.dll antiga (API que Core conhece)
2. **Internamente** chama o SDK novo `libtiepie-hw.dll` (API moderna)
3. **Traduz** conceitos antigos → novos (ex: `ADC_Start()` → `tiepie_hw_oscilloscope_start()`)

```
┌─────────────────────┐
│  Inergetix Core     │
│  (não modificado)   │
└──────────┬──────────┘
           │ chama ADC_Start(), SetMeasureMode(), etc.
           ↓
┌─────────────────────────────────────────┐
│  hs3.dll NOVA (wrapper/shim)            │ ← ISTO QUE VAIS CRIAR
│  • Exporta API antiga                   │
│  • Traduz chamadas para SDK novo        │
│  • Mapeia conceitos (canais, trigger)   │
└──────────┬──────────────────────────────┘
           │ chama tiepie_hw_oscilloscope_*()
           ↓
┌─────────────────────┐
│  libtiepie-hw.dll   │ ← SDK oficial TiePie (novo driver)
│  (API moderna)      │
└──────────┬──────────┘
           │
           ↓
┌─────────────────────┐
│  TiePie HS3 USB     │
│  Hardware real      │
└─────────────────────┘
```

---

## ✅ VANTAGENS DA SOLUÇÃO

### 1️⃣ **Zero Modificações no Core** ✅
- Core continua a chamar `ADC_Start()`, `SetMeasureMode()`, etc.
- Não precisa de reverse-engineering do Core
- Não viola EULA/licença do Inergetix
- **Risco legal**: ZERO

### 2️⃣ **Usa SDK Oficial TiePie** ✅
- Não precisa de engenharia reversa do protocolo USB
- Calibração mantida (SDK tem tabelas corretas)
- Suporte oficial da TiePie (bugs corrigidos)
- **Risco técnico**: BAIXO

### 3️⃣ **Compatibilidade com Novo Driver** ✅
- Core passa a funcionar com driver moderno
- BioDeskPro2 pode usar mesmo SDK (libtiepie-hw)
- Ambos podem coexistir (não em simultâneo, mas na mesma máquina)
- **Risco de conflito**: BAIXO

### 4️⃣ **Tempo de Desenvolvimento Razoável** ⏱
- Template fornecido está 70% completo
- Estimativa: **20-40 horas** (vs 90-170h de modificar Core)
- Testes iterativos possíveis (não quebra sistema produção)

---

## ⚠️ DESAFIOS E RISCOS

### 1️⃣ **Arquitetura 32-bit vs 64-bit** 🔴 CRÍTICO

**Problema**:
```
Se Core é 32-bit → hs3.dll DEVE ser 32-bit
Se SDK novo só tem 64-bit → BLOQUEIO TOTAL
```

**Verificação URGENTE**:
```powershell
# Verificar se Core é 32-bit ou 64-bit
Get-Process -Name "InergetixCoRe" | Select-Object ProcessName, @{Name="Bits";Expression={if($_.StartInfo.EnvironmentVariables.Contains("PROCESSOR_ARCHITEW6432")){"64-bit"}else{"32-bit"}}}

# OU verificar executável
dumpbin /headers "C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\InergetixCoRe.exe" | findstr "machine"
# Se disser "x86" → 32-bit
# Se disser "x64" → 64-bit
```

**Se Core é 32-bit E SDK novo só tem 64-bit**:
- ❌ Solução wrapper **NÃO VIÁVEL**
- Alternativa: Contactar TiePie para SDK 32-bit legacy

---

### 2️⃣ **Ordinais das Funções** ⚠️ IMPORTANTE

**Problema**:
```c
// Se Core chama por ordinal (não por nome):
HMODULE h = LoadLibrary("hs3.dll");
FuncPtr f = GetProcAddress(h, MAKEINTRESOURCE(10)); // Ordinal 10

// Wrapper DEVE exportar com MESMO ordinal:
// hs3.def:
EXPORTS
  ADC_Start @10  // ← NÚMERO EXATO deve casar
```

**Solução**:
1. Executar `dumpbin /exports hs3.dll` na DLL antiga
2. Copiar **exatamente** os ordinais para `hs3.def`

**Ficheiro necessário**:
```
C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\hs3.dll (ANTIGA)
```

Se não tiveres acesso (driver novo substituiu):
- ⚠️ PROBLEMA: Precisa de backup da DLL antiga
- Solução: Contactar fornecedor Inergetix ou TiePie

---

### 3️⃣ **Calling Convention (__stdcall vs __cdecl)** ⚠️

**Problema**:
```c
// Se DLL antiga usava __stdcall (Windows API padrão):
// Símbolos decorados: _ADC_Start@0, _SetMeasureMode@4

// Wrapper DEVE usar mesma convenção:
extern "C" __declspec(dllexport) word __stdcall ADC_Start(void);
//                                      ^^^^^^^^ CRÍTICO
```

**Verificação**:
```powershell
dumpbin /exports hs3.dll
# Se símbolos têm @NN no final → __stdcall
# Se símbolos simples → __cdecl
```

**Template fornecido assume __stdcall** (correto para 90% dos casos Windows).

---

### 4️⃣ **Mapeamento de Conceitos Complexos** 🔧

**Desafios de tradução**:

| API Antiga (hs3.dll) | SDK Novo (libtiepie-hw) | Dificuldade |
|----------------------|-------------------------|-------------|
| `SetMeasureMode(MM_CH1)` | `channel_set_enabled(0, true)` | ⭐ FÁCIL |
| `SetSampleFrequency(1e6)` | `set_sample_rate(1e6)` | ⭐ FÁCIL |
| `ADC_Start()` | `oscilloscope_start()` | ⭐ FÁCIL |
| `SetResolution(12)` | `set_resolution(12)` | ⭐⭐ MÉDIO (SDK pode não ter resolução pedida) |
| `SetTriggerSource(1)` | `channel_trigger_set_enabled(0, true)` + `set_kind()` + `set_level()` | ⭐⭐⭐ DIFÍCIL (3 chamadas) |
| `ADC_GetDataVoltCh(1, buf)` | `get_data(float**, ...)` + conversão float→double | ⭐⭐⭐ DIFÍCIL (alocação buffers) |

**Problema específico - GetData**:
```c
// API antiga: buffer double já alocado pelo Core
extern "C" word ADC_GetDataVoltCh(word ch, double* Data);

// SDK novo: retorna float**, precisa converter
float** bufs = malloc(...);
tiepie_hw_oscilloscope_get_data(g_scp, bufs, ...);
for(i=0; i<n; i++) Data[i] = (double)bufs[ch][i]; // ← conversão
```

**Risco**: Consumo de memória duplicado (float + double).

---

### 5️⃣ **Gestão de Estado Global** ⚠️

**Problema**:
```c
static tiepie_hw_handle g_scp = INVALID; // ← handle global

// Se Core abrir/fechar múltiplas vezes:
InitInstrument() → g_scp = open(...)
ExitInstrument() → close(g_scp)
InitInstrument() → g_scp = open(...) // ← OK

// Se Core NÃO chamar Exit antes de Init novamente:
InitInstrument() → g_scp = open(...) // 1ª vez
InitInstrument() → g_scp = open(...) // 2ª vez (LEAK do 1º handle!)
```

**Solução**:
```c
extern "C" word __stdcall InitInstrument(word addr) {
  // SEMPRE fechar handle anterior
  if(g_scp != TIEPIE_HW_HANDLE_INVALID) {
    tiepie_hw_object_close(g_scp);
  }
  // Abrir novo
  g_scp = tiepie_hw_devicelistitem_open_oscilloscope(...);
  ...
}
```

---

## 🛠️ PLANO DE IMPLEMENTAÇÃO

### **FASE 1: Inventário e Preparação** (2-4 horas)

#### ✅ **Tarefa 1.1: Verificar Arquitetura Core**
```powershell
# No PC onde Core funciona:
dumpbin /headers "C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\InergetixCoRe.exe" | findstr "machine"
```

**Critério de sucesso**: Confirmar 32-bit (x86) ou 64-bit (x64).

---

#### ✅ **Tarefa 1.2: Extrair Exports da hs3.dll Antiga**
```powershell
# Precisa de DLL antiga (antes de instalar driver novo)
cd "C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0"
dumpbin /exports hs3.dll > C:\Temp\hs3_exports_antigos.txt
```

**Output esperado**:
```
ordinal hint RVA      name
      1    0 00001234 InitInstrument
      2    1 00001245 ExitInstrument
     10    2 00001256 ADC_Start
     11    3 00001267 ADC_Abort
     ...
```

**Critério de sucesso**: Ficheiro com ~20-50 funções exportadas.

**⚠️ SE NÃO TIVERES DLL ANTIGA**:
- Contactar TiePie: pedir backup hs3.dll legacy
- Contactar Inergetix: pedir lista de funções API
- **BLOQUEADOR**: Sem ordinais corretos, Core pode não reconhecer DLL nova

---

#### ✅ **Tarefa 1.3: Obter SDK libtiepie-hw**

**Opções**:

**A) Contactar TiePie** (RECOMENDADO):
```
Email: support@tiepie.com
Assunto: SDK libtiepie-hw for HS3 compatibility wrapper

Body:
We are developing a compatibility layer (wrapper DLL) to allow legacy
software (Inergetix Core) to work with the new libtiepie-hw driver.

REQUEST:
1. SDK download link (C/C++ headers + lib + DLL)
2. Architecture: 32-bit and 64-bit versions
3. Documentation for oscilloscope API
4. Sample code for basic capture

Hardware: HandyScope HS3
Legacy DLL: hs3.dll (exports ADC_*, SetMeasureMode, etc.)
```

**B) Download público** (se disponível):
- https://www.tiepie.com/en/libtiepie-hw (verificar se tem SDK completo)

**Critério de sucesso**: Ter ficheiros:
- `libtiepie-hw.h` (cabeçalho)
- `libtiepie-hw.lib` (biblioteca import)
- `libtiepie-hw.dll` (runtime)

---

### **FASE 2: Criar Projeto Visual Studio** (1-2 horas)

#### ✅ **Tarefa 2.1: Configurar Projeto DLL**

**Passo-a-passo**:
1. Visual Studio → New Project → **Dynamic-Link Library (DLL)** C++
2. Nome: `hs3_wrapper`
3. **Plataforma**: x86 (32-bit) **OU** x64 conforme Tarefa 1.1
4. Adicionar ficheiros:
   - `hs3.h` (tipos/constantes)
   - `hs3.cpp` (implementação)
   - `hs3.def` (exports)

**Estrutura**:
```
hs3_wrapper/
├── hs3.h          ← tipos, enums, protótipos
├── hs3.cpp        ← implementação das funções
├── hs3.def        ← exports com ordinais
├── libtiepie-hw.h ← SDK (copiar)
└── libtiepie-hw.lib ← SDK (linkar)
```

---

#### ✅ **Tarefa 2.2: Configurar Linker**

**Project Properties → Linker**:
- **Module Definition File**: `hs3.def`
- **Additional Library Directories**: pasta com `libtiepie-hw.lib`
- **Additional Dependencies**: `libtiepie-hw.lib`

**Garantir**:
- Output: `hs3.dll` (MESMO NOME que DLL antiga)
- Platform Toolset: compatível com Core (v140 para VS2015, v142 para VS2019)

---

### **FASE 3: Implementar Funções Críticas** (10-20 horas)

#### ✅ **Tarefa 3.1: Init/Exit (Base)**

**Template** (já fornecido no teu exemplo):
```cpp
static tiepie_hw_handle g_scp = TIEPIE_HW_HANDLE_INVALID;
static bool g_inited = false;

extern "C" __declspec(dllexport) word __stdcall InitInstrument(word addr) {
  // Fechar handle anterior se existir (evita leaks)
  if(g_scp != TIEPIE_HW_HANDLE_INVALID) {
    tiepie_hw_object_close(g_scp);
    g_scp = TIEPIE_HW_HANDLE_INVALID;
  }

  // Init SDK (só 1ª vez)
  if(!g_inited) {
    tiepie_hw_init();
    tiepie_hw_devicelist_update();
    g_inited = true;
  }

  // Abrir HS3 por product ID
  tiepie_hw_handle item = tiepie_hw_devicelist_get_item_by_product_id(TIEPIE_HW_PRODUCTID_HS3);
  if(item == TIEPIE_HW_HANDLE_INVALID) {
    return E_NO_HARDWARE;
  }

  g_scp = tiepie_hw_devicelistitem_open_oscilloscope(item);
  tiepie_hw_object_close(item); // fechar item (não é o osciloscópio)

  if(g_scp == TIEPIE_HW_HANDLE_INVALID) {
    return E_NO_HARDWARE;
  }

  // Defaults razoáveis (como DLL antiga fazia)
  tiepie_hw_oscilloscope_set_measure_mode(g_scp, TIEPIE_HW_MM_BLOCK);

  // Ativar canais (CH1 e CH2)
  const uint16_t chCnt = tiepie_hw_oscilloscope_get_channel_count(g_scp);
  for(uint16_t ch = 0; ch < chCnt; ch++) {
    tiepie_hw_oscilloscope_channel_set_enabled(g_scp, ch, TIEPIE_HW_BOOL_TRUE);
    tiepie_hw_oscilloscope_channel_set_range(g_scp, ch, 8.0); // 8V range
    tiepie_hw_oscilloscope_channel_set_coupling(g_scp, ch, TIEPIE_HW_CK_DCV);
  }

  return E_NO_ERRORS;
}
```

**Testes**:
1. Compilar DLL
2. Criar app teste C# que chama `InitInstrument(0)`
3. Verificar que não crashs (retorna E_NO_ERRORS ou E_NO_HARDWARE)

---

#### ✅ **Tarefa 3.2: ADC_Start/Stop/Ready**

**Implementação**:
```cpp
extern "C" __declspec(dllexport) word __stdcall ADC_Start(void) {
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) return E_NOT_INITIALIZED;
  tiepie_hw_oscilloscope_start(g_scp);
  return E_NO_ERRORS;
}

extern "C" __declspec(dllexport) word __stdcall ADC_Abort(void) {
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) return E_NOT_INITIALIZED;
  tiepie_hw_oscilloscope_stop(g_scp);
  return E_NO_ERRORS;
}

extern "C" __declspec(dllexport) word __stdcall ADC_Ready(void) {
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) return E_NOT_INITIALIZED;
  return tiepie_hw_oscilloscope_is_data_ready(g_scp) ? 1 : 0;
}

extern "C" __declspec(dllexport) word __stdcall ADC_ForceTrig(void) {
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) return E_NOT_INITIALIZED;
  tiepie_hw_oscilloscope_force_trigger(g_scp);
  return E_NO_ERRORS;
}
```

**Testes**:
```c
InitInstrument(0);
SetSampleFrequency(1000000); // 1 MHz
SetRecordLength(10000);      // 10k samples
ADC_Start();
Sleep(100);
if(ADC_Ready()) {
  printf("Data ready!\n");
}
ADC_Abort();
```

---

#### ✅ **Tarefa 3.3: GetData (COMPLEXO)**

**Problema**: SDK retorna `float**`, API antiga espera `double*`.

**Implementação**:
```cpp
extern "C" __declspec(dllexport) word __stdcall ADC_GetDataVoltCh(word wCh, double* Data) {
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) return E_NOT_INITIALIZED;
  if(!Data) return E_INVALID_VALUE;

  const uint16_t chCnt = tiepie_hw_oscilloscope_get_channel_count(g_scp);
  uint16_t chIndex = (wCh > 0) ? (uint16_t)(wCh - 1) : 0; // wCh=1 → index=0
  if(chIndex >= chCnt) return E_INVALID_VALUE;

  uint64_t n = tiepie_hw_oscilloscope_get_record_length(g_scp);

  // Alocar array de ponteiros (um por canal)
  float** bufs = (float**)malloc(sizeof(float*) * chCnt);
  for(uint16_t i = 0; i < chCnt; i++) bufs[i] = NULL;

  // Só alocar buffer para canal pedido
  float* tmp = (float*)malloc(sizeof(float) * n);
  bufs[chIndex] = tmp;

  // Ler dados (início=0, n samples)
  uint64_t got = tiepie_hw_oscilloscope_get_data(g_scp, bufs, chCnt, 0, n);

  // Converter float → double
  for(uint64_t i = 0; i < got; i++) {
    Data[i] = (double)tmp[i];
  }

  // Limpar
  free(tmp);
  free(bufs);

  return (got == n) ? E_NO_ERRORS : E_INVALID_VALUE;
}
```

**Otimização futura** (se Core chamar muito):
- Cache global de buffers `float*` para evitar malloc/free repetidos

---

#### ✅ **Tarefa 3.4: Trigger Configuration**

**Implementação**:
```cpp
extern "C" __declspec(dllexport) word __stdcall SetTriggerSource(word src) {
  // src: 0=free-run, 1=CH1, 2=CH2
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) return E_NOT_INITIALIZED;

  const uint16_t chCnt = tiepie_hw_oscilloscope_get_channel_count(g_scp);

  // Desativar trigger em todos os canais
  for(uint16_t ch = 0; ch < chCnt; ch++) {
    tiepie_hw_oscilloscope_channel_trigger_set_enabled(g_scp, ch, TIEPIE_HW_BOOL_FALSE);
  }

  if(src > 0) {
    uint16_t ch = (src == 2) ? 1 : 0; // src=1→CH1(index 0), src=2→CH2(index 1)
    tiepie_hw_oscilloscope_channel_trigger_set_enabled(g_scp, ch, TIEPIE_HW_BOOL_TRUE);
    tiepie_hw_oscilloscope_channel_trigger_set_kind(g_scp, ch, TIEPIE_HW_TK_RISINGEDGE);
    tiepie_hw_oscilloscope_channel_trigger_set_level(g_scp, ch, 0, 0.5); // 50% range
  }

  return E_NO_ERRORS;
}

extern "C" __declspec(dllexport) word __stdcall SetTriggerLevel(word src, double levelPercent) {
  // levelPercent: 0..100
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) return E_NOT_INITIALIZED;
  if(src == 0) return E_NO_ERRORS; // free-run, ignorar

  uint16_t ch = (src == 2) ? 1 : 0;
  double rel = levelPercent / 100.0; // 0..1
  tiepie_hw_oscilloscope_channel_trigger_set_level(g_scp, ch, 0, rel);
  return E_NO_ERRORS;
}
```

---

### **FASE 4: Logging e Debug** (2-4 horas)

#### ✅ **Tarefa 4.1: Adicionar Logging**

**Objetivo**: Ver sequência de chamadas do Core para debug.

**Implementação**:
```cpp
#include <stdio.h>
#include <time.h>

static FILE* g_logFile = NULL;

void LogInit() {
  if(!g_logFile) {
    g_logFile = fopen("C:\\Temp\\hs3_wrapper.log", "a");
    if(g_logFile) {
      time_t now = time(NULL);
      fprintf(g_logFile, "\n=== hs3_wrapper started at %s\n", ctime(&now));
      fflush(g_logFile);
    }
  }
}

void Log(const char* func, const char* msg) {
  if(!g_logFile) LogInit();
  if(g_logFile) {
    fprintf(g_logFile, "[%s] %s\n", func, msg);
    fflush(g_logFile);
  }
}

// Exemplo de uso:
extern "C" word __stdcall ADC_Start(void) {
  Log("ADC_Start", "called");
  if(g_scp == TIEPIE_HW_HANDLE_INVALID) {
    Log("ADC_Start", "ERROR: not initialized");
    return E_NOT_INITIALIZED;
  }
  tiepie_hw_oscilloscope_start(g_scp);
  Log("ADC_Start", "success");
  return E_NO_ERRORS;
}
```

**Ficheiro log esperado**:
```
=== hs3_wrapper started at Tue Oct 22 14:30:00 2025
[InitInstrument] called with addr=0
[InitInstrument] SDK initialized
[InitInstrument] HS3 opened, handle=42
[InitInstrument] success
[SetSampleFrequency] called with hz=1000000.000000
[SetSampleFrequency] success
[ADC_Start] called
[ADC_Start] success
...
```

**Usar logs para**:
1. Ver se Core chama funções esperadas
2. Detectar crashes (última função antes de crash)
3. Verificar parâmetros (ex: frequências pedidas)

---

### **FASE 5: Testes com Core** (4-8 horas)

#### ✅ **Tarefa 5.1: Backup DLL Antiga**

```powershell
# ANTES de substituir, fazer backup
cd "C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0"
copy hs3.dll hs3.dll.BACKUP_ORIGINAL
```

---

#### ✅ **Tarefa 5.2: Instalar Wrapper**

```powershell
# Copiar DLL nova (wrapper) + SDK runtime
copy C:\hs3_wrapper\x86\Release\hs3.dll "C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\hs3.dll"
copy C:\TiePie_SDK\x86\libtiepie-hw.dll "C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\"
```

**Verificar**:
- `hs3.dll` (wrapper) no diretório Core
- `libtiepie-hw.dll` no MESMO diretório (ou PATH)

---

#### ✅ **Tarefa 5.3: Teste Incremental**

**Teste 1: Core Abre?**
```
1. Executar Inergetix Core
2. Verificar se abre sem crash
3. Verificar log: C:\Temp\hs3_wrapper.log
```

**Esperado**:
```
[InitInstrument] called
[InitInstrument] HS3 opened
```

**Se crashar**: Ver Windows Event Viewer → Application Logs.

---

**Teste 2: Core Detecta HS3?**
```
1. Conectar HS3 USB
2. No Core, tentar iniciar sessão/scan
3. Verificar se Core vê dispositivo
```

**Se não detectar**:
- Verificar log wrapper (InitInstrument retornou E_NO_HARDWARE?)
- Verificar Driver Manager (HS3 aparece?)

---

**Teste 3: Core Emite Corrente?**
```
1. Configurar terapia simples (ex: 432 Hz, 5V, 60s)
2. Iniciar emissão
3. Verificar se HS3 LED acende
4. Medir saída com multímetro (se possível)
```

**Se não emitir**:
- Verificar log: ADC_Start foi chamado?
- Verificar log SDK: tiepie_hw_oscilloscope_start retornou erro?

---

#### ✅ **Tarefa 5.4: Testes de Carga**

**Teste 4: Múltiplas Sessões**
```
1. Iniciar terapia → parar
2. Iniciar outra terapia → parar
3. Repetir 5-10 vezes
4. Verificar se Core não travou
```

**Problema comum**: Leak de handles (não fechar g_scp).

---

**Teste 5: Frequências Variadas**
```
Testar programas Core com:
- Frequências baixas (1 Hz)
- Frequências médias (432 Hz, 528 Hz)
- Frequências altas (20 kHz)
```

**Verificar**: HS3 aceita range completo (SDK pode ter limites).

---

## 📊 ESTIMATIVA DE TEMPO TOTAL

| Fase | Tarefas | Tempo | Risco |
|------|---------|-------|-------|
| **1. Inventário** | Arquitetura, exports, SDK | 2-4h | 🔴 ALTO (se não tiver DLL antiga) |
| **2. Setup VS** | Projeto, linker, configs | 1-2h | 🟡 MÉDIO (problemas toolchain) |
| **3. Implementação** | Init/Exit, ADC, Trigger | 10-20h | 🟢 BAIXO (template fornecido) |
| **4. Logging** | Debug, logs, crash handling | 2-4h | 🟢 BAIXO |
| **5. Testes Core** | Incremental, carga, stress | 4-8h | 🔴 ALTO (Core pode ter bugs inesperados) |
| **TOTAL** | | **19-38h** | |

**Comparação**:
- Modificar Core diretamente: 90-170h (risco CRÍTICO)
- Wrapper DLL: **19-38h** (risco MÉDIO)
- Contactar TiePie para solução oficial: 0h (espera de resposta)

---

## 🎯 RECOMENDAÇÃO FINAL

### ✅ **VIÁVEL SE**:
1. ✅ Core é **32-bit** E SDK tem versão 32-bit
2. ✅ Consegues **backup hs3.dll antiga** (para ordinais)
3. ✅ TiePie fornece **SDK completo** (headers + lib + DLL)
4. ✅ Tens **20-40h** disponíveis para implementar/testar
5. ✅ Podes fazer **testes iterativos** sem afetar produção

### ❌ **NÃO VIÁVEL SE**:
1. ❌ Core é 32-bit MAS SDK só tem 64-bit
2. ❌ Não tens backup DLL antiga (ordinais desconhecidos)
3. ❌ TiePie não fornece SDK (só driver)
4. ❌ Core usa funções hs3.dll não documentadas/obscuras
5. ❌ Zero tempo para desenvolvimento (pacientes a aguardar)

---

## 🚀 PRÓXIMOS PASSOS IMEDIATOS

### **HOJE (2h)**:

1. ✅ **Verificar arquitetura Core**
   ```powershell
   dumpbin /headers "C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\InergetixCoRe.exe" | findstr "machine"
   ```

2. ✅ **Procurar backup hs3.dll antiga**
   - Pasta `C:\Program Files (x86)\Inergetix\`
   - Backup Windows (`C:\Windows.old\`)
   - Restauro sistema (se fizeste antes de instalar driver novo)

3. ✅ **Contactar TiePie**
   ```
   To: support@tiepie.com
   Subject: SDK Request - HS3 Wrapper Development

   Dear TiePie Team,

   We need libtiepie-hw SDK (C/C++) for developing a compatibility wrapper
   that allows legacy software (Inergetix Core) to work with new drivers.

   REQUIREMENTS:
   - SDK version: 32-bit (x86) AND 64-bit (x64)
   - Components: headers (.h), import libs (.lib), runtime DLLs
   - Documentation: oscilloscope API reference
   - Sample code: basic capture example

   CONTEXT:
   - Hardware: HandyScope HS3
   - Legacy API: hs3.dll (ADC_*, SetMeasureMode, etc.)
   - Goal: Translate old API → new libtiepie-hw calls

   Timeline: Development starting this week if SDK available.

   Best regards,
   [Nome]
   ```

---

### **ESTA SEMANA (se SDK chegar)**:

4. ✅ **Criar projeto Visual Studio**
5. ✅ **Implementar Init/Exit/ADC_Start** (core mínimo)
6. ✅ **Testar com app teste C#** (não Core ainda)
7. ✅ **Adicionar logging completo**

---

### **PRÓXIMA SEMANA (testes)**:

8. ✅ **Backup completo Core + BD**
9. ✅ **Instalar wrapper no Core**
10. ✅ **Testes incrementais** (abrir → detectar → emitir)
11. ✅ **Rollback se falhar** (restaurar hs3.dll.BACKUP_ORIGINAL)

---

## 💡 ALTERNATIVA PARALELA

**Enquanto develops wrapper, mantém Core funcional**:

1. **PC Produção**: Core + driver ANTIGO (intocado)
2. **PC Desenvolvimento**: Wrapper + driver NOVO (testes)
3. **Quando wrapper funcionar**: Migra produção

**Setup dual-PC**:
- Produção: Tratamentos pacientes (driver antigo)
- Dev: Testes wrapper (driver novo)
- HS3: Alterna entre PCs (USB)

---

## 📋 CHECKLIST FINAL

Antes de começar wrapper, confirmar:

- [ ] Core é 32-bit OU 64-bit (dumpbin verificado)
- [ ] Tens backup hs3.dll antiga
- [ ] SDK libtiepie-hw obtido (32 ou 64-bit conforme necessário)
- [ ] Visual Studio instalado (2017+ com C++ desktop)
- [ ] HS3 hardware acessível para testes
- [ ] Ambiente dev isolado (não afetar produção)
- [ ] Backup completo Core + base dados
- [ ] 20-40h disponíveis nas próximas 2-3 semanas

**Se TODOS checkmarks ✅ → AVANÇAR com wrapper**

**Se 1+ checkbox ❌ → Resolver bloqueador ANTES de começar**

---

**Data**: 22/10/2025
**Autor**: AI Copilot (GitHub)
**Status**: 🟡 **SOLUÇÃO VIÁVEL MAS PRECISA VALIDAÇÃO PRÉ-REQUISITOS**
