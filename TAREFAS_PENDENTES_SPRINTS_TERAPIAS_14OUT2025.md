# 📋 TAREFAS PENDENTES - SPRINTS TERAPIAS BIOENERGÉTICAS

**Data:** 14 de Outubro de 2025
**Status Atual:** Sprint 2 ~95% Completo | Sprint 3-6 Planejados

---

## ✅ SPRINT 2 - TERAPIAS BIOENERGÉTICAS: 95% COMPLETO

### ✅ FUNCIONALIDADES IMPLEMENTADAS (10/12)

1. ✅ **Excel Import (FrequencyList.xls)** - 100%
   - Importação completa de 5.869 protocolos
   - Parsing robusto com ExcelDataReader
   - Validação de frequências
   - Detecção automática de protocolos holísticos
   - Logging detalhado

2. ✅ **Value% Scanning (CoRe Algorithm)** - 100%
   - Algoritmo de medição implementado
   - Cálculo correto de Value% (0-100%)
   - Atualização em tempo real
   - Performance otimizada (< 1s por protocolo)

3. ✅ **Checkbox Selection** - 100%
   - Binding funcional com IsSelected
   - ObservableObject pattern correto
   - Seleção múltipla funciona

4. ✅ **Queue Management (Fila de Terapias)** - 100%
   - Adicionar protocolos selecionados à fila
   - Remover protocolos da fila
   - Reordenar protocolos (arrastar)
   - Persistência de estado
   - Contador visual de protocolos

5. ✅ **Botão "Aplicar Terapias"** - 100%
   - Enable/disable baseado em FilaTerapias.Count
   - NotifyCanExecuteChanged corrigido
   - Inicia sessão de terapia

6. ✅ **Monitorização Real-time** - 90%
   - Progress bar funcional
   - Status: "Preparando", "Aplicando", "Concluído"
   - Improvement% calculado corretamente
   - Atualização UI em tempo real
   - Timer de duração

7. ✅ **DummyMedicaoService (Simulação)** - 100%
   - Simula leituras do TiePie
   - Valores realistas de dC/dt
   - Improvement% baseado em Value%
   - Configurável para testes

8. ✅ **Auto-save Terapia** - 100%
   - Salva automaticamente após 1.5s de inatividade
   - Debounce implementado
   - Sem necessidade de botão "Gravar"
   - Testado e funcional

9. ✅ **Templates Prescrições (QuestPDF)** - 100%
   - Pop-up de seleção de templates (SelecionarTemplatesWindow)
   - 11 templates: Emagrecimento, Antioxidante, Desintoxicação...
   - Geração PDF funcional
   - Formatação profissional

10. ✅ **Sistema de Configurações** - 100%
    - ConfiguracaoClinicaViewModel implementado
    - Persistência de estado (última aba aberta)
    - Configurações de email, documentos, backups
    - UI completa em ConfiguracoesWindow.xaml

### ⏳ FUNCIONALIDADES PENDENTES (2/12)

#### 1. ⚠️ **Auto-stop Improvement >= 95%** - 80% COMPLETO
**Status:** Código implementado, MAS NÃO TESTADO

**Código Existente:**
```csharp
// TerapiasBioenergeticasUserControlViewModel.cs linha ~565
private void OnMedicaoAtualizada(object? sender, MedicaoEventArgs e)
{
    // ... cálculo de Improvement ...

    // Auto-stop quando Improvement >= 95%
    if (Improvement >= 95.0)
    {
        _logger.LogInformation("🎯 Auto-stop: Improvement {Improvement}% >= 95%", Improvement);
        await PararTerapiaAsync();

        // Avançar para próximo protocolo se houver
        if (ProtocoloAtualIndex < FilaTerapias.Count - 1)
        {
            await Task.Delay(500);
            await PassarParaProximoAsync();
        }
    }
}
```

**Tarefas Pendentes:**
- [ ] Teste end-to-end com DummyMedicaoService
- [ ] Validar que para corretamente ao atingir 95%
- [ ] Verificar transição automática para próximo protocolo
- [ ] Testar com múltiplos protocolos na fila
- [ ] Validar estado final no DataGrid ("Auto-Stop" vs "Concluído")

**Estimativa:** 30 minutos de testes

---

#### 2. ⚠️ **Testes End-to-End Completos** - 0% FEITO
**Status:** NÃO INICIADO

**Cenários a Testar:**

**2.1 Fluxo Completo: Scan → Queue → Apply → Monitor → Save**
- [ ] Abrir ficha de paciente existente
- [ ] Ir para Tab "Terapias Bioenergéticas"
- [ ] Clicar "🔍 Escanear Protocolos"
- [ ] Aguardar scan completar (~2 minutos)
- [ ] Verificar resultados ordenados por Value% DESC
- [ ] Selecionar top 5 protocolos (checkbox)
- [ ] Clicar "➕ Adicionar à Fila"
- [ ] Verificar fila atualizada (contador 5/5)
- [ ] Clicar "▶️ Aplicar Terapias"
- [ ] Aguardar sessão completar
- [ ] Verificar Improvement% >= 95% para todos
- [ ] Verificar DataGrid com registos de aplicação
- [ ] Fechar e reabrir ficha
- [ ] Confirmar persistência dos dados

**2.2 Edge Cases**
- [ ] Scan sem protocolos selecionados
- [ ] Adicionar protocolo duplicado à fila
- [ ] Remover protocolo enquanto sessão está ativa
- [ ] Fechar aplicação durante sessão (deve pausar)
- [ ] Reabrir e retomar sessão
- [ ] Scan com 0 resultados (todos Value% = 0)
- [ ] Aplicar terapia com paciente sem ID (deve falhar gracefully)

**2.3 Performance**
- [ ] Scan com 5.869 protocolos (< 3 minutos)
- [ ] Aplicar 10 protocolos em sequência (< 5 minutos)
- [ ] UI não congela durante operações
- [ ] Uso de memória estável (< 500 MB)
- [ ] CPU não excede 50% durante scan

**Estimativa:** 2-3 horas de testes

---

## 📊 RESUMO SPRINT 2

| Categoria | Status | Percentagem |
|-----------|--------|-------------|
| **Excel Import** | ✅ Completo | 100% |
| **Value% Scanning** | ✅ Completo | 100% |
| **UI/UX** | ✅ Completo | 100% |
| **Queue Management** | ✅ Completo | 100% |
| **Aplicar Terapias** | ✅ Completo | 100% |
| **Monitorização** | ✅ Completo | 90% |
| **Auto-stop** | ⚠️ Implementado, não testado | 80% |
| **Testes E2E** | ❌ Não feito | 0% |
| **TOTAL** | ⏳ Quase Completo | **95%** |

**Tempo Estimado para Completar Sprint 2:** 3-4 horas

---

## 🚀 SPRINT 3 - NAVIGATOR UI (GERADOR DE FORMAS DE ONDA)

**Status:** 📝 PLANEJADO (0% COMPLETO)
**Prioridade:** MÉDIA
**Estimativa Total:** 16-20 horas

### Objetivo
Criar interface gráfica para desenhar formas de onda personalizadas e selecionar frequências manualmente, sem depender do scan automático.

### Funcionalidades Planejadas

#### 3.1 **Canvas de Desenho de Forma de Onda** - 8 horas
**Descrição:** Interface para desenhar waveform customizada

**Features:**
- [ ] Canvas WPF interativo (600x400px)
- [ ] Ferramentas de desenho:
  - [ ] Linha reta
  - [ ] Curva senoidal
  - [ ] Onda quadrada
  - [ ] Onda triangular
  - [ ] Desenho livre (freehand)
- [ ] Preview em tempo real
- [ ] Zoom e pan
- [ ] Grid de referência (amplitude -10V a +10V)
- [ ] Eixos X (tempo) e Y (voltagem)

**Controles:**
- [ ] Amplitude (slider: 0-10V)
- [ ] Frequência base (input: 0.1 Hz - 10 MHz)
- [ ] Duty cycle para onda quadrada (slider: 10%-90%)
- [ ] Harmonics (checkboxes: 2ª, 3ª, 5ª harmônicas)

**Output:**
- [ ] Array de pontos (time, voltage)
- [ ] Formato exportável (JSON, CSV)
- [ ] Preview de frequências componentes (FFT)

**UI/UX:**
- [ ] Botão "🎨 Novo Waveform"
- [ ] Toolbar: [Linha] [Seno] [Quadrada] [Triangular] [Livre] [Borracha]
- [ ] Botão "▶️ Preview Sonoro" (gerar tom)
- [ ] Botão "💾 Salvar Preset"
- [ ] Lista de presets salvos

---

#### 3.2 **Seletor Manual de Frequências** - 6 horas
**Descrição:** Interface para escolher frequências específicas sem scan

**Features:**
- [ ] Input numérico com unidades (Hz, kHz, MHz)
- [ ] Slider logarítmico (0.1 Hz - 10 MHz)
- [ ] Lista de frequências famosas:
  - [ ] 7.83 Hz (Ressonância Schumann)
  - [ ] 432 Hz (frequência natural)
  - [ ] 528 Hz (frequência de amor/reparação DNA)
  - [ ] 1000 Hz (teste de calibração)
- [ ] Calculadora de harmonics:
  - Input: frequência fundamental
  - Output: 2ª, 3ª, 5ª, 7ª harmônicas
- [ ] Pesquisa em FrequencyList.xls:
  - Input: termo de pesquisa (ex: "cancer", "stress")
  - Output: lista de frequências associadas
  - Seleção múltipla

**Integração:**
- [ ] Adicionar frequências selecionadas à Fila de Terapias
- [ ] Combinar com scan automático (modo híbrido)
- [ ] Salvar combinações como "Receitas"

**UI/UX:**
- [ ] Tab "🎯 Navigator" na interface Terapias
- [ ] Painel esquerdo: Seletor de frequências
- [ ] Painel direito: Canvas de waveform
- [ ] Botão "➕ Adicionar à Sessão"
- [ ] Preview em tempo real no gerador

---

#### 3.3 **Geração de Sinal para TiePie** - 4 horas
**Descrição:** Converter waveform desenhado em sinais para hardware

**Features:**
- [ ] Conversão de pontos canvas → buffer de voltagens
- [ ] Interpolação para taxa de amostragem (10 kHz - 1 MHz)
- [ ] Normalização de amplitude (-10V a +10V)
- [ ] Aplicação de offset DC (configurável)
- [ ] Loop infinito ou one-shot

**Integração com TiePieHardwareService:**
```csharp
public interface ITiePieHardwareService
{
    // Novo método para waveform customizado
    Task<bool> SetCustomWaveformAsync(double[] samples, double frequency);

    // Existente (manter)
    Task<bool> SetFrequencyAsync(double frequencyHz);
    Task<MedicaoResult> MedirAsync(CancellationToken ct);
}
```

**DummyTiePieHardwareService:**
- [ ] Simular geração de waveform customizado
- [ ] Validar buffer de samples
- [ ] Log de parâmetros aplicados

**Validações:**
- [ ] Amplitude dentro dos limites (-10V a +10V)
- [ ] Frequência suportada pelo hardware (< 10 MHz)
- [ ] Buffer não vazio
- [ ] Taxa de amostragem adequada (Nyquist)

---

#### 3.4 **Biblioteca de Presets** - 2 horas
**Descrição:** Salvar e carregar waveforms e frequências customizadas

**Features:**
- [ ] Salvar waveform como preset (nome, descrição)
- [ ] Formato JSON:
  ```json
  {
    "nome": "Anti-stress Protocol",
    "descricao": "Combinação 7.83 Hz + senoide suave",
    "waveform": {
      "tipo": "senoidal",
      "amplitude": 5.0,
      "frequencia": 7.83,
      "samples": [0.0, 0.5, 1.0, ...]
    },
    "frequencias": [7.83, 14.1, 20.8],
    "duracao": 300
  }
  ```
- [ ] Carregar preset
- [ ] Editar preset
- [ ] Deletar preset
- [ ] Exportar/importar presets (partilhar entre utilizadores)

**UI/UX:**
- [ ] Lista de presets na sidebar
- [ ] Botão "💾 Salvar Como Preset"
- [ ] Dialog de edição de preset
- [ ] Botão "📤 Exportar Presets"
- [ ] Botão "📥 Importar Presets"

**Storage:**
- [ ] Pasta: `Documentos/Presets/`
- [ ] Formato: `preset_nome_timestamp.json`
- [ ] Validação ao carregar (schema JSON)

---

## 🎨 SPRINT 4 - VALUE% VISUALIZATION (GRÁFICOS)

**Status:** 📝 PLANEJADO (0% COMPLETO)
**Prioridade:** BAIXA
**Estimativa Total:** 8-12 horas

### Objetivo
Visualizar resultados do scan de protocolos com gráficos interativos, facilitando seleção dos mais eficazes.

### Funcionalidades Planejadas

#### 4.1 **Gráfico de Barras Interativo** - 6 horas
**Descrição:** Chart com top 20 protocolos por Value%

**Features:**
- [ ] Biblioteca de gráficos: **LiveCharts2** ou **OxyPlot**
- [ ] Gráfico de barras horizontal
- [ ] Eixo X: Value% (0-100%)
- [ ] Eixo Y: Nome do protocolo (truncado se > 30 chars)
- [ ] Cor das barras baseada em range:
  - Verde (80-100%): Alta eficácia
  - Amarelo (60-79%): Média eficácia
  - Laranja (40-59%): Baixa eficácia
  - Vermelho (0-39%): Muito baixa
- [ ] Hover tooltip: Nome completo + Value% + Frequência
- [ ] Click na barra: Seleciona protocolo automaticamente
- [ ] Double-click: Adiciona diretamente à fila

**Configurações:**
- [ ] Número de protocolos visíveis (slider: 10-50)
- [ ] Filtro por categoria (Naturopatia, Osteopatia, Geral)
- [ ] Ordenação (Value% DESC/ASC, Nome A-Z)

**Performance:**
- [ ] Renderização < 500ms para 5.869 protocolos
- [ ] Zoom suave
- [ ] Scroll lazy loading (carregar 20 de cada vez)

---

#### 4.2 **Gráfico de Evolução (Histórico)** - 4 horas
**Descrição:** Line chart mostrando evolução de Value% ao longo de consultas

**Features:**
- [ ] Eixo X: Data das consultas
- [ ] Eixo Y: Average Value% dos protocolos aplicados
- [ ] Múltiplas linhas:
  - Linha azul: Value% médio
  - Linha verde: Improvement% médio
  - Linha vermelha: Número de protocolos aplicados
- [ ] Pontos clicáveis: Mostrar detalhes da consulta
- [ ] Range selector: Últimos 7 dias, 30 dias, 6 meses, tudo

**Dados:**
- [ ] Agregar consultas por data
- [ ] Calcular médias por sessão
- [ ] Persistir no histórico de consultas

**UI/UX:**
- [ ] Botão "📊 Ver Histórico" na tab Terapias
- [ ] Dialog com gráfico fullscreen
- [ ] Botão "💾 Exportar para PNG/PDF"
- [ ] Comparar múltiplos pacientes (overlay)

---

#### 4.3 **Dashboard de Estatísticas** - 2 horas
**Descrição:** Cards com KPIs e resumos

**Features:**
- [ ] Card: Total de scans realizados
- [ ] Card: Protocolo mais usado
- [ ] Card: Improvement% médio (last 30 days)
- [ ] Card: Taxa de sucesso (>= 95%)
- [ ] Card: Duração média de sessão
- [ ] Mini-gráfico sparkline em cada card

**Layout:**
- [ ] Grid 2x3 de cards
- [ ] Refresh automático ao abrir tab
- [ ] Animações de transição

---

## 💊 SPRINT 5 - TERAPIA INFORMACIONAL (SEM FREQUÊNCIAS)

**Status:** 📝 PLANEJADO (0% COMPLETO)
**Prioridade:** MÉDIA
**Estimativa Total:** 6-8 horas

### Objetivo
Permitir aplicação de protocolos SEM emissão de frequências, usando apenas campo informacional (bioressonância passiva).

### Conceito
Alguns terapeutas acreditam que a **intenção** e **informação** de um protocolo pode ter efeito terapêutico mesmo sem gerar o sinal físico. Modo especial para esta abordagem.

### Funcionalidades Planejadas

#### 5.1 **Modo "Informacional Only"** - 4 horas
**Descrição:** Toggle para desligar geração de frequências

**Features:**
- [ ] Checkbox na UI: "🔇 Modo Informacional (sem emissão de frequências)"
- [ ] Quando ativo:
  - [ ] TiePie não gera sinal (SetFrequencyAsync não chamado)
  - [ ] Timer continua (mesma duração configurada)
  - [ ] Monitorização de Improvement% OPCIONAL (pode usar valor fixo simulado)
  - [ ] Registo na BD com flag `ModoInformacional = true`
- [ ] Ícone diferenciado no DataGrid para sessões informacionais

**UI/UX:**
- [ ] Switch na toolbar da tab Terapias
- [ ] Tooltip explicativo: "Modo Informacional aplica apenas a intenção terapêutica sem gerar sinais físicos"
- [ ] Cor diferente na progress bar (roxo em vez de verde)
- [ ] Mensagem ao iniciar: "⚠️ Modo Informacional ativo - hardware não será utilizado"

**Backend:**
```csharp
public class AplicacaoTerapia
{
    public bool ModoInformacional { get; set; } // ← Novo campo

    // Modificar lógica em ApplyTerapiaAsync()
    if (!ModoInformacional)
    {
        await _hardwareService.SetFrequencyAsync(protocolo.Frequencia);
    }
    else
    {
        _logger.LogInformation("🔇 Modo Informacional - hardware não ativado");
    }
}
```

**Validações:**
- [ ] Aviso ao mudar modo com sessão ativa
- [ ] Confirmação: "Mudar modo irá reiniciar sessão. Continuar?"
- [ ] Salvar preferência do utilizador (último modo usado)

---

#### 5.2 **Relatórios Diferenciados** - 2 horas
**Descrição:** Identificar sessões informacionais em relatórios

**Features:**
- [ ] Coluna "Modo" no DataGrid de histórico
  - "Físico" (ícone 📡)
  - "Informacional" (ícone 🔇)
- [ ] Filtro: Mostrar apenas sessões informacionais
- [ ] Estatísticas separadas:
  - [ ] Improvement% médio (Físico vs Informacional)
  - [ ] Comparação side-by-side
- [ ] Export PDF com indicação clara do modo

**Análise:**
- [ ] Permitir terapeuta avaliar eficácia de cada modo
- [ ] Gráfico comparativo (Sprint 4 integration)

---

#### 5.3 **Temporizador Visual Especial** - 2 horas
**Descrição:** Experiência diferenciada para modo informacional

**Features:**
- [ ] Animação de "radiância" em vez de progress bar tradicional
- [ ] Efeitos visuais calmos (ondas, partículas)
- [ ] Som opcional (frequências binaurais simuladas)
- [ ] Contagem regressiva com meditação guiada (texto)

**UI/UX:**
- [ ] Fundo roxo/azul gradiente
- [ ] Ícone de mantra/chakra no centro
- [ ] Mensagens motivacionais:
  - "Conectando energia terapêutica..."
  - "Campo informacional ativo..."
  - "Ressonância em harmonia..."

---

## ⚖️ SPRINT 6 - MODO PONDERADO (PLAYLIST INTELIGENTE)

**Status:** 📝 PLANEJADO (0% COMPLETO)
**Prioridade:** BAIXA
**Estimativa Total:** 10-12 horas

### Objetivo
Aplicar TODOS os protocolos selecionados de forma contínua, com duração proporcional ao Value%, criando uma "playlist terapêutica".

### Conceito
Em vez de aplicar um protocolo de cada vez até 95% Improvement, o modo ponderado:
1. Calcula duração de cada protocolo baseada no Value% (maior Value% = mais tempo)
2. Cria playlist sequencial sem pausas
3. Aplica tudo de uma vez, sem monitorização de Improvement individual

**Exemplo:**
- Protocolo A (Value% 85) → 170 segundos
- Protocolo B (Value% 70) → 140 segundos
- Protocolo C (Value% 55) → 110 segundos
- **Total:** 420 segundos (7 minutos) de sessão contínua

### Funcionalidades Planejadas

#### 6.1 **Algoritmo de Ponderação** - 4 horas
**Descrição:** Calcular durações baseadas em Value%

**Fórmulas:**
```csharp
// Opção 1: Linear
public double CalcularDuracaoLinear(double valuePercent, double duracaoBase = 60)
{
    return (valuePercent / 100.0) * duracaoBase * 2;
}

// Opção 2: Logarítmica (dar mais peso aos altos Value%)
public double CalcularDuracaoLogaritmica(double valuePercent)
{
    return Math.Log10(valuePercent + 1) * 30; // 30-60 segundos
}

// Opção 3: Exponencial (enfatizar diferenças)
public double CalcularDuracaoExponencial(double valuePercent)
{
    return Math.Pow(valuePercent / 100.0, 0.5) * 120; // 0-120 segundos
}
```

**Features:**
- [ ] Escolha de algoritmo via dropdown
- [ ] Slider de "Duração Total Desejada" (5-60 minutos)
- [ ] Normalização: Ajustar todas durações para caber no tempo total
- [ ] Preview da playlist antes de aplicar:
  ```
  Protocolo A - 85% → 2m 50s
  Protocolo B - 70% → 2m 20s
  Protocolo C - 55% → 1m 50s
  ───────────────────────────
  TOTAL: 7 minutos
  ```

**Validações:**
- [ ] Mínimo de 2 protocolos na fila
- [ ] Duração total >= 5 minutos, <= 120 minutos
- [ ] Protocolos com Value% < 20% recebem duração mínima (30s)

---

#### 6.2 **Playlist Player** - 4 horas
**Descrição:** Executar playlist sem pausas

**Features:**
- [ ] Progress bar com segmentos coloridos (1 cor por protocolo)
- [ ] Indicador "Tocando agora": Nome do protocolo atual
- [ ] Próximo protocolo: Preview do que vem a seguir
- [ ] Timer global: Tempo decorrido / Tempo total
- [ ] Timer por protocolo: Tempo restante do protocolo atual

**Controles:**
- [ ] ⏸️ Pausar playlist
- [ ] ⏯️ Retomar playlist
- [ ] ⏭️ Pular para próximo protocolo
- [ ] ⏹️ Parar sessão completa

**UI Layout:**
```
┌────────────────────────────────────────┐
│  🎵 MODO PONDERADO - PLAYLIST ATIVA    │
├────────────────────────────────────────┤
│  Tocando Agora:                        │
│  🔹 Protocolo A (85% Value%)           │
│  Tempo Restante: 1m 23s / 2m 50s      │
├────────────────────────────────────────┤
│  [████████░░░░░░░░░░] 40%              │
│  ← A ──→ B ─→ C ─→ D ──→              │
├────────────────────────────────────────┤
│  Próximo:                              │
│  🔸 Protocolo B (70% Value%)           │
│  Duração: 2m 20s                       │
├────────────────────────────────────────┤
│  Total: 2m 47s / 7m 00s                │
│  [⏸️] [⏭️] [⏹️]                         │
└────────────────────────────────────────┘
```

**Lógica:**
```csharp
private async Task ExecutarPlaylistAsync()
{
    foreach (var item in Playlist)
    {
        _logger.LogInformation("▶️ Iniciando {Nome} - {Duracao}s",
            item.Protocolo.Nome, item.Duracao);

        await _hardwareService.SetFrequencyAsync(item.Protocolo.Frequencia);

        // Timer com cancellation token
        var fim = DateTime.Now.AddSeconds(item.Duracao);
        while (DateTime.Now < fim && !_cts.Token.IsCancellationRequested)
        {
            TempoRestante = (fim - DateTime.Now).TotalSeconds;
            await Task.Delay(100); // Update UI a cada 100ms
        }

        _logger.LogInformation("✅ {Nome} completo", item.Protocolo.Nome);
    }

    _logger.LogInformation("🎉 Playlist completa!");
}
```

---

#### 6.3 **Relatório de Sessão Ponderada** - 2 horas
**Descrição:** Registo e visualização de sessões ponderadas

**Features:**
- [ ] Tabela de resumo:
  ```
  | Protocolo | Value% | Duração | Ordem |
  |-----------|--------|---------|-------|
  | A         | 85%    | 2m 50s  | 1º    |
  | B         | 70%    | 2m 20s  | 2º    |
  | C         | 55%    | 1m 50s  | 3º    |
  ```
- [ ] Gráfico de pizza: % de tempo por protocolo
- [ ] Timeline visual com segmentos coloridos
- [ ] Improvement% final (medido no fim da playlist inteira)

**Persistência:**
```csharp
public class SessaoPonderada
{
    public int Id { get; set; }
    public int PacienteId { get; set; }
    public DateTime DataSessao { get; set; }
    public int DuracaoTotalSegundos { get; set; }
    public double ImprovementFinal { get; set; }
    public List<ItemPlaylist> Protocolos { get; set; }
}

public class ItemPlaylist
{
    public int ProtocoloId { get; set; }
    public double ValuePercent { get; set; }
    public int DuracaoSegundos { get; set; }
    public int Ordem { get; set; }
}
```

---

#### 6.4 **Configurações de Modo Ponderado** - 2 horas
**Descrição:** Opções avançadas para power users

**Features:**
- [ ] **Fade In/Out:** Transição suave entre protocolos
  - Duração do fade: 0-5 segundos
  - Amplitude gradual (evitar "saltos" bruscos)
- [ ] **Gap entre protocolos:** Pausa opcional (0-10 segundos)
- [ ] **Loop:** Repetir playlist N vezes ou infinitamente
- [ ] **Shuffle:** Randomizar ordem (mantendo durações)
- [ ] **Reverse:** Tocar playlist do fim para o início

**UI/UX:**
- [ ] Painel de "Configurações Avançadas" (expansível)
- [ ] Checkboxes e sliders para cada opção
- [ ] Botão "🔀 Randomizar Ordem"
- [ ] Botão "💾 Salvar Playlist como Template"

---

## 📊 ROADMAP GERAL - TERAPIAS BIOENERGÉTICAS

```
SPRINT 2 (Atual)          95% ████████████████████░  ← Falta: Auto-stop + E2E tests
SPRINT 3 (Navigator)       0% ░░░░░░░░░░░░░░░░░░░░  16-20 horas
SPRINT 4 (Gráficos)        0% ░░░░░░░░░░░░░░░░░░░░  8-12 horas
SPRINT 5 (Informacional)   0% ░░░░░░░░░░░░░░░░░░░░  6-8 horas
SPRINT 6 (Ponderado)       0% ░░░░░░░░░░░░░░░░░░░░  10-12 horas
```

**Tempo Total Estimado para Completar Todos os Sprints:** 44-56 horas (~1-1.5 semanas de trabalho full-time)

---

## 🎯 PRÓXIMOS PASSOS RECOMENDADOS

### Curto Prazo (Próximas 2-4 horas)
1. ✅ **Auditar e corrigir sistema de Backup/Restore** - COMPLETO
2. ⏳ **Testar auto-stop >= 95%** - 30 minutos
   - Executar sessão com DummyMedicaoService
   - Validar transição automática entre protocolos
   - Confirmar estado "Auto-Stop" no DataGrid
3. ⏳ **Testes End-to-End básicos** - 1 hora
   - Fluxo completo: Scan → Queue → Apply → Monitor
   - Verificar persistência ao fechar/reabrir ficha
   - Validar performance com 5.869 protocolos

### Médio Prazo (Próxima semana)
4. 🚀 **Iniciar Sprint 3 - Navigator UI** - 16-20 horas
   - Prioridade: Seletor manual de frequências (mais simples)
   - Depois: Canvas de waveform (mais complexo)
   - Integração com sistema existente
5. 📊 **Sprint 4 - Gráficos (se tempo permitir)** - 8-12 horas

### Longo Prazo (Próximo mês)
6. 💊 **Sprint 5 - Modo Informacional** - 6-8 horas
7. ⚖️ **Sprint 6 - Modo Ponderado** - 10-12 horas
8. 🧪 **Testes de aceitação com utilizador final**
9. 📚 **Documentação completa para terapeutas**
10. 🚀 **Preparação para produção**

---

## 📝 NOTAS ADICIONAIS

### Dependências de Hardware
- **TiePie Handyscope HS5**: Necessário para testes em produção
- **DummyTiePieHardwareService**: Adequado para desenvolvimento e testes
- **Modo Informacional**: Não requer hardware (útil para testes offline)

### Bibliotecas Recomendadas
- **LiveCharts2** ou **OxyPlot**: Gráficos interativos (Sprint 4)
- **NAudio**: Geração de som/frequências (Sprint 3 - preview sonoro)
- **MathNet.Numerics**: FFT para análise de waveforms (Sprint 3)

### Integrações Futuras
- **AI/ML**: Sugerir protocolos baseados em histórico do paciente
- **Cloud Sync**: Backup de presets e playlists na nuvem
- **Mobile App**: Controle remoto da sessão via smartphone
- **Biofeedback**: Integrar sensores cardíacos, GSR, EEG

---

**Documento Atualizado:** 14/10/2025 16:30
**Status Geral:** Sprint 2 quase completo, pronto para avançar
**Próxima Revisão:** Após conclusão de Sprint 3 (Navigator UI)
