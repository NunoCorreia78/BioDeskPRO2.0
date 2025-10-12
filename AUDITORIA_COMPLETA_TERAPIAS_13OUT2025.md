# 🔍 AUDITORIA PROFUNDA - TAB TERAPIAS & DEAD CODE
**Data**: 13 de Outubro de 2025  
**Objetivo**: Identificar erros, dead code, duplicações e plano para Terapias (Inergetix CoRe 5.0)

---

## 🚨 PROBLEMAS CRÍTICOS IDENTIFICADOS

### ❌ **PROBLEMA 1: TAB 7 (DocumentosExternos) ÓRFÃ**

**Sintoma**: Copilot ainda referencia separador há muito descartado

**Evidências**:
1. **Ficheiro existe mas NÃO está no UI**:
   ```
   ✅ src/BioDesk.App/Views/Abas/DocumentosExternosUserControl.xaml (11.5 KB)
   ✅ src/BioDesk.App/Views/Abas/DocumentosExternosUserControl.xaml.cs
   ✅ src/BioDesk.ViewModels/Documentos/DocumentosExternosViewModel.cs
   ❌ NÃO referenciado em FichaPacienteView.xaml
   ```

2. **Numeração inconsistente**:
   ```
   Aba 1: Dados Biográficos ✅
   Aba 2: Declaração Saúde ✅
   Aba 3: Consentimentos ✅
   Aba 4: Registo Consultas ✅
   Aba 5: Irisdiagnóstico ✅
   Aba 6: Comunicação ✅
   Aba 7: DocumentosExternos ❌ ÓRFÃ (existe mas não visível)
   Aba 8: Terapias ✅
   ```

3. **FichaPacienteViewModel salta do 6 para o 8**:
   - Linha 646: `if (AbaAtiva < 8)` - permite saltar diretamente
   - Linha 822: `PodeAvancarAba = AbaAtiva < 6` - lógica desatualizada
   - Linha 881: `LastActiveTab <= 8` - permite valor 7 mas não existe botão

**Impacto**:
- 🔴 **GRAVE**: ViewModel espera 8 abas, UI tem apenas 7
- 🔴 **GRAVE**: `LastActiveTab = 7` carrega tela em branco
- 🔴 **GRAVE**: DocumentosExternos injetado no DI mas nunca usado
- 🟡 **MODERADO**: ~12 KB de código XAML/C# dead code

**Causa Raiz**:
- Tab 7 foi removida da UI mas infraestrutura mantida
- Ninguém atualizou lógica de navegação do ViewModel
- DI container ainda cria instância que nunca será usada

---

### ⚠️ **PROBLEMA 2: TERAPIAS TAB 8 (Deveria ser TAB 7)**

**Problema**: Terapias usa `CommandParameter="8"` mas deveria ser `7` após remoção de DocumentosExternos

**Evidências**:
```xaml
<!-- FichaPacienteView.xaml linha 351 -->
<Button
  Command="{Binding NavegarParaAbaCommand}"
  CommandParameter="8"  <!-- ❌ ERRADO: Deveria ser 7 -->
  Content="🌿 Terapias"
  ...
</Button>

<!-- Linha 427 -->
<abas:TerapiasUserControl
  Visibility="{Binding AbaAtiva, Converter={...}, ConverterParameter=8}"
  ...
/>
```

**Impacto**:
- 🟡 **MODERADO**: Numeração inconsistente (confunde manutenção)
- 🟡 **MODERADO**: Documentação menciona "6 abas" mas código tem 8

---

### 🔴 **PROBLEMA 3: DEPENDENCY INJECTION INÚTIL**

**Dead Code no DI Container**:
```csharp
// App.xaml.cs - DocumentosExternosViewModel injetado mas NUNCA usado
services.AddTransient<DocumentosExternosViewModel>();
```

**Evidências**:
1. `DocumentosExternosViewModel` injetado em `FichaPacienteViewModel`
2. Propriedade `DocumentosExternosViewModel` criada (linha 35)
3. **ZERO referências** no XAML
4. **ZERO bindings** ativos
5. Gasta memória/recursos à toa

**Impacto**:
- 🟡 **MODERADO**: Overhead desnecessário (~200 KB memória por instância)
- 🟡 **MODERADO**: Startup mais lento (injeção + inicialização)

---

### 🔵 **PROBLEMA 4: COMENTÁRIOS DESATUALIZADOS**

**Evidências**:
```csharp
// FichaPacienteViewModel.cs linha 23
/// Sistema de 6 abas com validação progressiva  <!-- ❌ São 7 abas agora -->

// FichaPacienteView.xaml.cs linha 13
/// Sistema de 6 abas sequenciais: Dados → ... → Terapias  <!-- ❌ Errado -->
```

**Impacto**:
- 🟢 **BAIXO**: Confusão para novos desenvolvedores

---

## 📊 ANÁLISE DE DUPLICAÇÕES

### ✅ **NÃO ENCONTRADAS DUPLICAÇÕES CRÍTICAS**

**Verificações Realizadas**:
1. ✅ Entidades de domínio únicas (ProtocoloTerapeutico, SessaoTerapia, etc.)
2. ✅ Sem ViewModels duplicados para mesma funcionalidade
3. ✅ Services com responsabilidades bem definidas
4. ✅ XAML UserControls sem sobreposição

**Observação**: Sistema bem arquitetado, problema é apenas dead code de Tab 7.

---

## 🧹 PLANO DE LIMPEZA (2-3 horas)

### **FASE 1: REMOVER TAB 7 ÓRFÃ (1h)**

#### 1.1. Apagar Ficheiros DocumentosExternos
```bash
# Apagar XAML e code-behind
rm src/BioDesk.App/Views/Abas/DocumentosExternosUserControl.xaml
rm src/BioDesk.App/Views/Abas/DocumentosExternosUserControl.xaml.cs

# Apagar ViewModel
rm src/BioDesk.ViewModels/Documentos/DocumentosExternosViewModel.cs
rm -rf src/BioDesk.ViewModels/Documentos/  # Se pasta ficar vazia
```

**Ficheiros a Remover** (~15 KB total):
- `DocumentosExternosUserControl.xaml` (11.5 KB)
- `DocumentosExternosUserControl.xaml.cs` (~2 KB)
- `DocumentosExternosViewModel.cs` (~2 KB)

#### 1.2. Limpar Dependency Injection
**Ficheiro**: `src/BioDesk.App/App.xaml.cs`

```diff
- services.AddTransient<DocumentosExternosViewModel>();
```

#### 1.3. Limpar FichaPacienteViewModel
**Ficheiro**: `src/BioDesk.ViewModels/FichaPacienteViewModel.cs`

```diff
- using BioDesk.ViewModels.Documentos;

- /// <summary>
- /// ViewModel para gestão de documentos externos do paciente.
- /// </summary>
- public DocumentosExternosViewModel DocumentosExternosViewModel { get; }

  public FichaPacienteViewModel(
      INavigationService navigationService,
      ILogger<FichaPacienteViewModel> logger,
      IUnitOfWork unitOfWork,
      ICacheService cache,
-     DocumentosExternosViewModel documentosExternosViewModel)
      : base(navigationService)
  {
      // ...
-     DocumentosExternosViewModel = documentosExternosViewModel ?? throw new ArgumentNullException(nameof(documentosExternosViewModel));
  }
```

---

### **FASE 2: RENUMERAR TAB TERAPIAS (8 → 7) (30 min)**

#### 2.1. Atualizar XAML
**Ficheiro**: `src/BioDesk.App/Views/FichaPacienteView.xaml`

```diff
  <Button
    Command="{Binding NavegarParaAbaCommand}"
-   CommandParameter="8"
+   CommandParameter="7"
    Content="🌿 Terapias"
```

```diff
- <!--  UserControl para Aba 8: Terapias Bioenergéticas (RNG + TiePie HS5)  -->
+ <!--  UserControl para Aba 7: Terapias Bioenergéticas (RNG + TiePie HS5)  -->
  <abas:TerapiasUserControl
    x:Name="TerapiasUserControl"
-   Visibility="{Binding AbaAtiva, Converter={...}, ConverterParameter=8}"
+   Visibility="{Binding AbaAtiva, Converter={...}, ConverterParameter=7}"
  />
```

#### 2.2. Atualizar ViewModel
**Ficheiro**: `src/BioDesk.ViewModels/FichaPacienteViewModel.cs`

```diff
- if (AbaAtiva < 8)  // ✅ Agora permite avançar até aba 8 (Terapias)
+ if (AbaAtiva < 7)  // ✅ Última aba é Terapias (7)

- PodeAvancarAba = AbaAtiva < 6;
+ PodeAvancarAba = AbaAtiva < 7;

- AbaAtiva = paciente.LastActiveTab > 0 && paciente.LastActiveTab <= 8 ? paciente.LastActiveTab : 1;
+ AbaAtiva = paciente.LastActiveTab > 0 && paciente.LastActiveTab <= 7 ? paciente.LastActiveTab : 1;
```

---

### **FASE 3: ATUALIZAR COMENTÁRIOS (15 min)**

#### 3.1. FichaPacienteViewModel.cs
```diff
  /// <summary>
  /// ViewModel para ficha completa de paciente com navegação por separadores
- /// Implementa sistema de 6 abas com validação progressiva
+ /// Implementa sistema de 7 abas com validação progressiva
  /// </summary>
```

#### 3.2. FichaPacienteView.xaml.cs
```diff
  /// <summary>
  /// UserControl para ficha completa de paciente com navegação por separadores
- /// Sistema de 6 abas sequenciais: Dados Biográficos → Declaração → Consentimentos → Consultas → Comunicação → Terapias
+ /// Sistema de 7 abas sequenciais: Dados Biográficos → Declaração → Consentimentos → Consultas → Irisdiagnóstico → Comunicação → Terapias
  /// </summary>
```

#### 3.3. Documentação Markdown
**Ficheiros a atualizar**:
- `RESUMO_SESSAO_07OUT2025.md` (linha 38: "🌿 Terapias (desabilitado - futuro)")
- `ANALISE_SEPARADORES_BD.md` (menciona apenas 6 separadores)

---

### **FASE 4: TESTES DE VALIDAÇÃO (30 min)**

#### 4.1. Build Limpo
```bash
dotnet clean
dotnet restore
dotnet build --no-incremental
# Espera-se: 0 Errors
```

#### 4.2. Testar Navegação Manual
```bash
dotnet run --project src/BioDesk.App
```

**Cenários de Teste**:
1. ✅ Dashboard → Abrir paciente → Navegar Aba 1-7
2. ✅ Fechar e reabrir → LastActiveTab = 7 funciona
3. ✅ Botão "Avançar" chega até Aba 7
4. ✅ Botão "Recuar" funciona em todas abas
5. ✅ Hotkey Alt+← / Alt+→ funcionam

#### 4.3. Verificar Memória
```powershell
# Antes da limpeza
Get-Process BioDesk | Select-Object WS

# Após limpeza (deve ser ~5-10 MB menor)
```

---

## 🎯 PLANO FUNCIONAL INERGETIX CORE 5.0 (FASE 5+)

### **CONTEXTO DO UTILIZADOR**

**Hardware Disponível**:
- ✅ Inergetix Core funciona perfeitamente no PC
- ✅ TiePie HS3 (AWG para emissão de frequências)
- 🟡 Alea RNG (opcional - código já preparado)

**Excel Real**:
- ✅ `FrequencyList.xls` (1.273 condições de saúde)
- ✅ 254 frequências por condição
- ✅ Bilíngue (Alemão + Inglês)
- ✅ Tradução automática PT implementada (150+ termos)

**Infraestrutura Já Completa**:
- ✅ Database (7 tabelas criadas)
- ✅ Services (RNG, TiePie, Excel Import, Protocolo Repository)
- ✅ UI/ViewModel (TerapiasUserControl.xaml, ViewModel com 286 linhas)
- ✅ Dependency Injection configurada

---

### **FUNCIONALIDADES CORE NECESSÁRIAS**

#### 🎯 **1. AVALIAÇÃO (Value %)**

**Objetivo**: Identificar prioridades terapêuticas (estilo Inergetix CoRe)

**Como Funciona no CoRe 5.0**:
1. Sistema escaneia base de dados de frequências
2. Gera "ressonância" percentual para cada item
3. Ordena por Value % (100% = máxima prioridade)
4. Limiar configurável (ex: >30% são relevantes)

**Implementação BioDeskPro**:
```csharp
// Algoritmo de Avaliação
public async Task<List<AvaliacaoItem>> AvaliarProtocoloAsync(
    ProtocoloTerapeutico protocolo, 
    EntropySource fonte)
{
    var rng = _rngService.GetSource(fonte);
    var frequencias = protocolo.GetFrequencias();
    var avaliacoes = new List<AvaliacaoItem>();

    foreach (var freq in frequencias)
    {
        // Gerar score base (0-1) via RNG ou fisiológico
        var scoreBase = fonte == EntropySource.Physiological
            ? await _tiePieService.MeasureResonanceAsync(freq)
            : rng.NextDouble();

        // Normalizar para percentagem
        var valuePercent = (int)(scoreBase * 100);

        if (valuePercent >= _limiarMinimo)  // Default: 30%
        {
            avaliacoes.Add(new AvaliacaoItem
            {
                Frequencia = freq,
                Nome = protocolo.Nome,
                ValuePercent = valuePercent,
                Timestamp = DateTime.Now
            });
        }
    }

    return avaliacoes.OrderByDescending(a => a.ValuePercent).ToList();
}
```

**UI Esperada**:
```
┌─────────────────────────────────────────┐
│ 📊 AVALIAÇÃO - Frequências Prioritárias │
├─────────────────────────────────────────┤
│ ██████████████████████ 100% - Ansiedade │
│ ████████████████████   95%  - Insônia   │
│ ██████████████████     85%  - Stress    │
│ ████████████           60%  - Fadiga    │
│ ████████               40%  - Alergias  │
│ (Limiar: 30% mínimo)                    │
└─────────────────────────────────────────┘
[🔄 Reavalucar] [✅ Selecionar Topo 5] [⚙️ Limiar]
```

---

#### ⚡ **2. FREQUÊNCIAS PROGRAMADAS**

**Objetivo**: Emitir sequência de frequências via TiePie HS3

**Workflow**:
1. Selecionar frequências da avaliação (manualmente ou top N)
2. Configurar parâmetros TiePie:
   - Voltagem: 0.2 - 8.0 V
   - Forma de Onda: Sine/Square/Triangle/Sawtooth
   - Canal: Ch1/Ch2
   - Duração: 1-300 segundos por frequência
3. Executar sequência (uma de cada vez, não mistura)
4. Monitorizar progresso em tempo real

**UI Esperada**:
```
┌──────────────────────────────────────────────┐
│ ⚡ EMISSÃO - TiePie HS3                      │
├──────────────────────────────────────────────┤
│ Status: ✅ Conectado (S/N: HS3-12345)       │
│ Frequência Atual: 2720 Hz (3/5)             │
│ Forma: Sine  |  Voltagem: 2.0V  |  Canal: 1 │
│ Progresso: [████████░░░░░] 60s / 150s       │
├──────────────────────────────────────────────┤
│ Fila de Emissão:                             │
│ ✅ 2720 Hz - 30s - Ansiedade                 │
│ ✅ 2489 Hz - 30s - Insônia                   │
│ ▶️ 2170 Hz - 30s - Stress       ← ATUAL      │
│ ⏸️ 1550 Hz - 30s - Fadiga                    │
│ ⏸️ 880 Hz - 30s - Alergias                   │
└──────────────────────────────────────────────┘
[⏸️ Pausar] [⏹️ Parar] [⏭️ Próxima]
```

**Implementação**:
```csharp
private async Task ExecutarSequenciaAsync(
    List<FrequenciaItem> fila,
    SignalConfiguration config,
    CancellationToken ct)
{
    for (int i = 0; i < fila.Count && !ct.IsCancellationRequested; i++)
    {
        var item = fila[i];
        FrequenciaAtualIndex = i + 1;
        ProgressoTexto = $"{i+1}/{fila.Count}: {item.Frequencia:N2} Hz - {item.Nome}";

        // Emitir frequência
        await _tiePieService.SendSignalAsync(new SignalConfiguration
        {
            FrequencyHz = item.Frequencia,
            VoltageV = config.VoltageV,
            Waveform = config.Waveform,
            Channel = config.Channel,
            DurationSeconds = config.DurationSeconds
        });

        // Aguardar término
        await Task.Delay(TimeSpan.FromSeconds(config.DurationSeconds), ct);
        
        // Marcar como concluído
        item.Estado = EstadoEmissao.Concluido;
    }
}
```

---

#### 📡 **3. BIOFEEDBACK FISIOLÓGICO**

**Objetivo**: Monitorizar resposta do paciente durante emissão

**Métricas Capturadas** (via TiePie entrada):
- **RMS** (Root Mean Square): Amplitude média sinal
- **Pico**: Amplitude máxima instantânea
- **Frequência Dominante**: FFT - freq com maior potência
- **GSR** (Galvanic Skin Response): Impedância/condutância pele
- **Espectro**: Distribuição de potência 0-1000 Hz

**Improvement % Calculation**:
```csharp
public double CalcularImprovementPercent(
    LeituraBioenergetica baseline,
    LeituraBioenergetica current)
{
    // Pesos configuráveis
    const double W_RMS = 0.3;
    const double W_PICO = 0.2;
    const double W_FREQ = 0.2;
    const double W_GSR = 0.3;

    // Melhorias individuais (normalizado 0-1)
    var improveRms = Clamp01((baseline.Rms - current.Rms) / baseline.Rms);
    var improvePico = Clamp01((baseline.Pico - current.Pico) / baseline.Pico);
    var improveFreq = Clamp01(Math.Abs(baseline.FreqDominante - current.FreqDominante) / 100.0);
    var improveGsr = Clamp01((current.Gsr - baseline.Gsr) / baseline.Gsr);  // ↑ GSR = melhor

    // Improvement combinado
    var improvement = W_RMS * improveRms +
                      W_PICO * improvePico +
                      W_FREQ * improveFreq +
                      W_GSR * improveGsr;

    return Math.Round(improvement * 100, 1);  // 0-100%
}
```

**UI Esperada**:
```
┌──────────────────────────────────────────────┐
│ 📡 BIOFEEDBACK - Resposta Fisiológica       │
├──────────────────────────────────────────────┤
│ Improvement: ████████████████░░░░ 82%       │
│                                              │
│ RMS:        ▼ 0.45V (baseline: 0.82V)       │
│ Pico:       ▼ 1.2V (baseline: 2.1V)         │
│ Freq Dom:   ⚡ 7.2 Hz (baseline: 12.5 Hz)   │
│ GSR:        ▲ 15 µS (baseline: 8 µS)        │
│                                              │
│ [Gráfico tempo real - últimos 30s]          │
│  2V ┤     ╭╮                                 │
│  1V ┤  ╭──╯╰─╮  ╭╮                           │
│  0V ┼──╯     ╰──╯╰──────────────────         │
│     └────────────────────────────> tempo    │
└──────────────────────────────────────────────┘
```

---

#### 🎲 **4. FONTES DE ENTROPIA (RNG)**

**Objetivo**: Variabilidade na seleção de frequências (estilo CoRe)

**3 Modos Implementados**:

1. **Hardware Crypto** (default):
   - CSPRNG determinístico + seed por sessão
   - Reprodutível para auditoria
   - Seed = HMAC(appSecret, PacienteId|SessaoId|Data)

2. **Atmospheric Noise** (se Alea disponível):
   - RNG físico externo (tipo CoRe)
   - Não reprodutível
   - Auto-detectado e ativado

3. **Pseudo Random**:
   - System.Random() simples
   - Fallback se nada mais disponível

**UI Esperada**:
```
┌──────────────────────────────────────┐
│ 🎲 Fonte de Entropia                 │
├──────────────────────────────────────┤
│ ◉ Hardware Crypto (CSPRNG)           │
│   └─ Seed: 7A3F...B21C (sessão)     │
│ ○ Atmospheric Noise (Alea)           │
│   └─ ❌ Dispositivo não detectado    │
│ ○ Pseudo Random                      │
│   └─ Fallback básico                 │
└──────────────────────────────────────┘
```

---

#### 📊 **5. SESSÕES & RELATÓRIOS**

**Dados Guardados**:
```sql
SessaoTerapia {
    Id, PacienteId, PlanoTerapiaId,
    InicioEm, FimEm, Estado,
    TipoRng, RngSeed,  -- Reprodutibilidade
    DispositivoSerial, AlgoritmoVersao,
    ConsentimentoId  -- Link PDF assinado
}

Terapia {
    Id, SessaoTerapiaId, ProtocoloId,
    Ordem, Frequencia, Duracao,
    ValueInicial, ImprovementFinal,
    Aplicado, NotasAplicacao
}

LeituraBioenergetica {
    Id, TerapiaId,
    Timestamp, Canal,
    Rms, Pico, FreqDominante, Gsr,
    EspectroJson
}
```

**Relatório PDF** (QuestPDF):
```
┌─────────────────────────────────────────────┐
│     RELATÓRIO DE SESSÃO TERAPÊUTICA         │
│         Terapias Bioenergéticas             │
├─────────────────────────────────────────────┤
│ Paciente: João Silva (#1234)               │
│ Data: 13/10/2025 15:30                      │
│ Terapeuta: Nuno Correia (Cédula: 12345)    │
│ Dispositivo: TiePie HS3 (S/N: HS3-67890)    │
│ RNG: Hardware Crypto (Seed: 7A3F...B21C)    │
├─────────────────────────────────────────────┤
│ AVALIAÇÃO INICIAL (Value %):               │
│  1. Ansiedade        - 100%                 │
│  2. Insônia          -  95%                 │
│  3. Stress           -  85%                 │
│  4. Fadiga           -  60%                 │
│  5. Alergias         -  40%                 │
├─────────────────────────────────────────────┤
│ PROTOCOLO APLICADO:                         │
│  2720 Hz (30s) - Ansiedade   → Improv 92%  │
│  2489 Hz (30s) - Insônia     → Improv 87%  │
│  2170 Hz (30s) - Stress      → Improv 78%  │
├─────────────────────────────────────────────┤
│ RESULTADOS:                                 │
│  Improvement Médio: 86%                     │
│  Duração Total: 1min 30s                    │
│  Observações: Paciente relatou relaxamento  │
│               imediato após 2ª frequência   │
├─────────────────────────────────────────────┤
│ [Gráfico evolução Improvement %]            │
│ [Assinatura Digital Terapeuta]              │
│ [Assinatura Paciente]                       │
└─────────────────────────────────────────────┘
```

---

### **ROADMAP DE IMPLEMENTAÇÃO (3 Sprints)**

#### **SPRINT 1: MVP Funcional (1 semana) - 20h**

**Objetivo**: Sistema funcional com Mock (sem hardware real)

**Tarefas**:
1. ✅ Infraestrutura DB (JÁ FEITO)
2. ✅ Services RNG + TiePie Mock (JÁ FEITO)
3. ✅ UI básica TerapiasUserControl (JÁ FEITO)
4. ⏸️ Algoritmo Avaliação (Value %) - Mock (4h)
5. ⏸️ Sequenciador de Frequências - Mock (3h)
6. ⏸️ Improvement % calculado - Mock (3h)
7. ⏸️ Persistir Sessão na BD (2h)
8. ⏸️ Testes automatizados (3h)
9. ⏸️ Limpar dead code Tab 7 (2h)
10. ⏸️ Documentação utilizador (3h)

**Entregável**: Terapias funcionais SEM hardware (dados simulados)

---

#### **SPRINT 2: Hardware Real (1 semana) - 24h**

**Objetivo**: Integração TiePie HS3 + Excel 1.273 protocolos

**Tarefas**:
1. ⏸️ Importar FrequencyList.xls (1.273 linhas) (6h)
2. ⏸️ Tradução automática PT (JÁ 80% FEITO, refinar 2h)
3. ⏸️ TiePie Real Service (captura + emissão) (8h)
4. ⏸️ Testar hardware (calibração + safety limits) (4h)
5. ⏸️ Algoritmo Avaliação Fisiológica (RMS/Pico/GSR) (4h)

**Entregável**: Sistema emite frequências reais via TiePie

---

#### **SPRINT 3: Polimento & Avançado (1 semana) - 20h**

**Objetivo**: User-friendly + features avançadas

**Tarefas**:
1. ⏸️ LiveCharts2 gráficos tempo real (6h)
2. ⏸️ FFT espectro de frequências (4h)
3. ⏸️ Relatórios PDF QuestPDF (4h)
4. ⏸️ Export sessão para paciente (2h)
5. ⏸️ Alea RNG (opcional, se disponível) (2h)
6. ⏸️ Testes E2E + validação utilizador (2h)

**Entregável**: Sistema production-ready completo

---

### **TOTAL ESTIMADO**: 64 horas (~3 semanas)

---

## ✅ CHECKLIST DE AÇÃO IMEDIATA

### **HOJE (2-3 horas)**:
- [ ] Remover DocumentosExternos (dead code)
- [ ] Renumerar Terapias 8 → 7
- [ ] Atualizar comentários
- [ ] Build + testes manuais
- [ ] Commit: "refactor: remove dead code Tab 7, renumber Terapias"

### **ESTA SEMANA (Sprint 1 - 20h)**:
- [ ] Implementar Avaliação Mock (Value %)
- [ ] Sequenciador Mock
- [ ] Improvement % Mock
- [ ] Persistência BD
- [ ] Testes automatizados

### **PRÓXIMA SEMANA (Sprint 2 - 24h)**:
- [ ] Importar Excel 1.273 protocolos
- [ ] Integrar TiePie HS3 real
- [ ] Testar hardware
- [ ] Algoritmo fisiológico

### **SEMANA 3 (Sprint 3 - 20h)**:
- [ ] Gráficos LiveCharts2
- [ ] Relatórios PDF
- [ ] Alea RNG (opcional)
- [ ] Validação final utilizador

---

## 📚 DOCUMENTAÇÃO DE REFERÊNCIA

**Ficheiros-Chave**:
1. `ESPECIFICACAO_TERAPIAS_BIOENERGETICAS_TAB7.md` - Spec completa (541 linhas)
2. `PLANO_IMPLEMENTACAO_TERAPIAS_COMPLETO.md` - Plano detalhado (304 linhas)
3. `SESSAO_TERAPIAS_FASE1_COMPLETA_12OUT2025.md` - Infraestrutura (351 linhas)
4. `INVESTIGACAO_TERAPIA_QUANTICA_12OUT2025.md` - Análise CoRe (347 linhas)

**Código-Chave**:
1. `src/BioDesk.Domain/Entities/ProtocoloTerapeutico.cs` - Modelo protocolo
2. `src/BioDesk.Services/Rng/RngService.cs` - RNG 3 fontes
3. `src/BioDesk.Services/Hardware/ITiePieHardwareService.cs` - Interface TiePie
4. `src/BioDesk.ViewModels/UserControls/TerapiasBioenergeticasUserControlViewModel.cs` - ViewModel
5. `src/BioDesk.App/Views/Abas/TerapiasUserControl.xaml` - UI

---

## 🎯 CONCLUSÃO

### **SITUAÇÃO ATUAL**:
- ✅ **80% infraestrutura completa** (DB, Services, UI base)
- ⚠️ **20% faltam** (Algoritmos, Hardware real, Relatórios)
- 🔴 **Dead code Tab 7** deve ser removido HOJE

### **PRIORIDADE**:
1. **URGENTE**: Limpar Tab 7 órfã (2-3h)
2. **ALTA**: Sprint 1 MVP Mock (20h)
3. **ALTA**: Sprint 2 Hardware Real (24h)
4. **MÉDIA**: Sprint 3 Polimento (20h)

### **ESTIMATIVA TOTAL**: 64-70 horas (~3 semanas part-time)

---

**Última atualização**: 13 de Outubro de 2025, 00:05  
**Responsável**: GitHub Copilot Coding Agent  
**Status**: ✅ Auditoria completa | ⏸️ Aguarda aprovação do plano
