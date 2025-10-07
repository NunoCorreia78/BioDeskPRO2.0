# 🖼️ TAB 7 - INTERFACE VISUAL

## Layout Geral

```
╔═══════════════════════════════════════════════════════════════════════════════════╗
║ 🌿 TERAPIAS BIOENERGÉTICAS (Inergetix-CoRe)                  👤 João Silva        ║
║ Scan ressonante, emissão sequencial e biofeedback em tempo real                  ║
╠═══════════════════════════════════════════════════════════════════════════════════╣
║ ✓ Checklist pré-sessão:                                                          ║
║ [✓] Consentimento  [✓] Dispositivo  [✓] Protocolo  [✓] Limites   [▶️ INICIAR]   ║
╠═════════════════════╦═══════════════════════╦═══════════════════════════════════╣
║                     ║                       ║                                   ║
║   COLUNA 1          ║    COLUNA 2           ║       COLUNA 3                    ║
║   Catálogo & Fila   ║    Controlo AWG       ║   Visualização Tempo Real         ║
║                     ║                       ║                                   ║
║ ┌─────────────────┐ ║ ⚙️ Controlo de Saída ║ 📊 Biofeedback Tempo Real         ║
║ │ 📚 CATÁLOGO     │ ║                       ║                                   ║
║ │ [📥 Importar]   │ ║ Frequência (Hz)       ║ ┌───────────────────────────────┐ ║
║ └─────────────────┘ ║ ┌──────────────────┐  ║ │                               │ ║
║                     ║ │ 528.0            │  ║ │     📈 FFT / Forma de Onda    │ ║
║ 🔍 [Pesquisar...]   ║ └──────────────────┘  ║ │                               │ ║
║                     ║                       ║ │   [Gráfico em tempo real]     │ ║
║ ┌─────────────────┐ ║ Amplitude (V)         ║ │                               │ ║
║ │ □ Dor Lombar    │ ║ ━━━━━━●━━━━━  5.0 V  ║ │                               │ ║
║ │   528 Hz, 5V    │ ║                       ║ └───────────────────────────────┘ ║
║ └─────────────────┘ ║ Limite Corrente (mA)  ║                                   ║
║                     ║ ━━━━●━━━━━━━  10 mA   ║ ┌─────────┐ ┌─────────┐          ║
║ ┌─────────────────┐ ║                       ║ │  RMS    │ │  PICO   │          ║
║ │ □ Stress        │ ║ Forma de Onda         ║ │ 12.3 mV │ │ 45.2 mV │          ║
║ │   7.83 Hz, 3V   │ ║ ▼ Sine                │ └─────────┘ └─────────┘          ║
║ └─────────────────┘ ║                       ║                                   ║
║                     ║ Modulação             ║ ┌─────────┐ ┌─────────┐          ║
║ ┌─────────────────┐ ║ ▼ None                │ │ FREQ.   │ │ IMPED.  │          ║
║ │ □ Inflamação    │ ║                       ║ │ 528.1Hz │ │ 1250 Ω  │          ║
║ │   174 Hz, 4V    │ ║ Canal                 ║ └─────────┘ └─────────┘          ║
║ └─────────────────┘ ║ ▼ Canal 1             │                                   ║
║                     ║                       ║ ╔═════════════════════════════╗   ║
║ ─────────────────── ║ ┌─────────────────┐   ║ ║   IMPROVEMENT %             ║   ║
║ 🔄 Fila de Emissão  ║ │  ⏸️ PAUSAR      │   ║ ║         67.8%               ║   ║
║                     ║ └─────────────────┘   ║ ║ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░       ║   ║
║ ┌─────────────────┐ ║ ┌─────────────────┐   ║ ╚═════════════════════════════╝   ║
║ │ 1. 528 Hz       │ ║ │  ⏹️ PARAR       │   ║                                   ║
║ │    5V, 10mA     │ ║ └─────────────────┘   ║ ⏱️  145 / 300 seg                 ║
║ └─────────────────┘ ║                       ║                                   ║
║                     ║ ┌─────────────────┐   ║ ┌───────────────────────────────┐ ║
║ ┌─────────────────┐ ║ │ 🔍 SCAN         │   ║ │  📄 Exportar Relatório        │ ║
║ │ 2. 174 Hz       │ ║ │ Limiar: 30%     │   ║ └───────────────────────────────┘ ║
║ │    4V, 8mA      │ ║ │ [▶️ Iniciar]    │   ║                                   ║
║ └─────────────────┘ ║ └─────────────────┘   ║                                   ║
║                     ║                       ║                                   ║
╚═════════════════════╩═══════════════════════╩═══════════════════════════════════╝
```

---

## Detalhes dos Componentes

### Header (Topo)

```
╔═══════════════════════════════════════════════════════════════════╗
║ 🌿 Terapias Bioenergéticas (Inergetix-CoRe)    ┌────────────────┐ ║
║ Scan ressonante, emissão sequencial e bio...   │ 👤 PACIENTE    │ ║
║                                                 │ João Silva     │ ║
║                                                 └────────────────┘ ║
╚═══════════════════════════════════════════════════════════════════╝
```

**Cores**:
- Fundo: `#F7F9F6` (cartão claro)
- Borda: `#E3E9DE` (borda subtil)
- Texto: `#3F4A3D` (texto principal)
- Badge paciente: `#E8F5E9` fundo, `#2E7D32` borda

---

### Checklist Pré-Sessão

```
┌───────────────────────────────────────────────────────────────┐
│ ✓ Checklist pré-sessão:                                      │
│                                                               │
│ [✓] Consentimento   [✓] Dispositivo   [✓] Protocolo          │
│ [✓] Limites V/mA    [ ▶️ Iniciar Sessão ]                    │
└───────────────────────────────────────────────────────────────┘
```

**Estado dos Checkboxes**:
- ✓ Verde: Validado
- ☐ Cinza: Pendente
- ❌ Vermelho: Erro

**Botão Iniciar**:
- Desabilitado se algum checkbox não marcado
- Verde (#9CAF97) quando habilitado
- Hover: #879B83

---

### Coluna 1: Catálogo & Fila

```
┌─────────────────────────────────────────┐
│ 📚 Catálogo de Protocolos               │
│ ┌───────────────────┐                   │
│ │ 📥 Importar Excel │                   │
│ └───────────────────┘                   │
├─────────────────────────────────────────┤
│ 🔍 Pesquisar protocolos...              │
├─────────────────────────────────────────┤
│ ┌─────────────────────────────────────┐ │
│ │ □ Dor Lombar Aguda                  │ │
│ │   528 Hz | 5V | 10mA | 5 min       │ │
│ └─────────────────────────────────────┘ │
│ ┌─────────────────────────────────────┐ │
│ │ □ Stress Crónico                    │ │
│ │   7.83 Hz | 3V | 5mA | 10 min      │ │
│ └─────────────────────────────────────┘ │
│ ┌─────────────────────────────────────┐ │
│ │ □ Inflamação Geral                  │ │
│ │   174 Hz | 4V | 8mA | 8 min        │ │
│ └─────────────────────────────────────┘ │
├─────────────────────────────────────────┤
│ 🔄 Fila de Emissão Sequencial           │
├─────────────────────────────────────────┤
│ ┌─────────────────────────────────────┐ │
│ │ 1️⃣ 528 Hz (Dor Lombar)              │ │
│ │    Amp: 5V | mA: 10 | Dur: 5 min   │ │
│ │    ▓▓▓▓▓▓▓▓▓░░░░░░░ 65%            │ │
│ └─────────────────────────────────────┘ │
│ ┌─────────────────────────────────────┐ │
│ │ 2️⃣ 174 Hz (Inflamação)              │ │
│ │    Amp: 4V | mA: 8 | Dur: 8 min    │ │
│ │    ░░░░░░░░░░░░░░░░ Pendente       │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

**Item de Protocolo**:
- Checkbox para seleção
- Nome do protocolo (bold)
- Parâmetros resumidos (freq/V/mA/duração)
- Hover: Fundo muda para #F0F6EE

**Item na Fila**:
- Número sequencial
- Nome + freq
- Barra de progresso durante emissão
- Status: Pendente / Emitindo (65%) / Concluído ✓

---

### Coluna 2: Controlo AWG

```
┌─────────────────────────────────────┐
│ ⚙️ Controlo de Saída (AWG HS3)      │
├─────────────────────────────────────┤
│ Frequência (Hz)                     │
│ ┌─────────────────────────────────┐ │
│ │ 528.0                           │ │
│ └─────────────────────────────────┘ │
│                                     │
│ Amplitude (V)                       │
│ ━━━━━━●━━━━━━━━━  5.0 V           │
│                                     │
│ Limite Corrente (mA)                │
│ ━━━━●━━━━━━━━━━━  10.0 mA         │
│                                     │
│ Forma de Onda                       │
│ ▼ Sine                              │
│   □ Square                          │
│   □ Triangle                        │
│   □ Saw                             │
│                                     │
│ Modulação                           │
│ ▼ None                              │
│   □ AM                              │
│   □ FM                              │
│   □ Burst                           │
│                                     │
│ Canal                               │
│ ▼ Canal 1                           │
│   □ Canal 2                         │
│                                     │
├─────────────────────────────────────┤
│ ┌─────────────────────────────────┐ │
│ │      ⏸️ PAUSAR                  │ │
│ └─────────────────────────────────┘ │
│ ┌─────────────────────────────────┐ │
│ │      ⏹️ PARAR                   │ │
│ └─────────────────────────────────┘ │
├─────────────────────────────────────┤
│ ╔═══════════════════════════════╗   │
│ ║ 🔍 SCAN RESSONANTE            ║   │
│ ║                               ║   │
│ ║ Limiar de relevância (Value %)║   │
│ ║ ━━━━━●━━━━━━━━  30%          ║   │
│ ║                               ║   │
│ ║ ┌───────────────────────────┐ ║   │
│ ║ │  ▶️ Iniciar Scan          │ ║   │
│ ║ └───────────────────────────┘ ║   │
│ ╚═══════════════════════════════╝   │
└─────────────────────────────────────┘
```

**Sliders**:
- Amplitude: 0-20V (verde quando OK, vermelho se > 20V)
- Corrente: 0-50mA (verde quando OK, vermelho se > 50mA)
- Limiar scan: 0-100% (azul)

**Botões**:
- Pausar: Laranja (#FFA726)
- Parar: Vermelho (#E57373)
- Iniciar Scan: Azul (#42A5F5)

---

### Coluna 3: Visualização Tempo Real

```
┌─────────────────────────────────────────┐
│ 📊 Biofeedback Tempo Real               │
├─────────────────────────────────────────┤
│ ┌─────────────────────────────────────┐ │
│ │                                     │ │
│ │      📈 FFT / Forma de Onda         │ │
│ │                                     │ │
│ │  [Gráfico de barras FFT ou onda]   │ │
│ │                                     │ │
│ │      Freq. dominante: 528.1 Hz     │ │
│ └─────────────────────────────────────┘ │
│                                         │
│ ┌────────────┐  ┌────────────┐         │
│ │    RMS     │  │    PICO    │         │
│ │  12.3 mV   │  │  45.2 mV   │         │
│ └────────────┘  └────────────┘         │
│                                         │
│ ┌────────────┐  ┌────────────┐         │
│ │   FREQ.    │  │   IMPED.   │         │
│ │ 528.1 Hz   │  │  1250 Ω    │         │
│ └────────────┘  └────────────┘         │
│                                         │
│ ╔═════════════════════════════════════╗ │
│ ║       IMPROVEMENT %                 ║ │
│ ║           67.8%                     ║ │
│ ║                                     ║ │
│ ║ ▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░         ║ │
│ ╚═════════════════════════════════════╝ │
│                                         │
│ ┌─────────────────────────────────────┐ │
│ │ ⏱️  145 / 300 seg                   │ │
│ └─────────────────────────────────────┘ │
│                                         │
│ ┌─────────────────────────────────────┐ │
│ │    📄 Exportar Relatório            │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

**Cores dos Indicadores**:
- **RMS**: Verde (#E8F5E9 fundo, #2E7D32 texto)
- **Pico**: Laranja (#FFF3E0 fundo, #E65100 texto)
- **Freq. Dominante**: Azul (#E3F2FD fundo, #0D47A1 texto)
- **Impedância**: Roxo (#F3E5F5 fundo, #6A1B9A texto)

**Improvement %**:
- Fundo: Verde claro (#C8E6C9)
- Borda: Verde médio (#66BB6A)
- Texto: Verde escuro (#1B5E20)
- Barra de progresso: Verde (#66BB6A)

**Tempo**:
- Fundo: Amarelo claro (#FFF9C4)
- Borda: Amarelo (#FDD835)
- Texto: Amarelo escuro (#F57F17)

---

## Estados da Interface

### 1. Estado Inicial (Paciente Ativo)

```
Header: ✅ Verde - "👤 João Silva"
Checklist: Todos ☐ (nenhum marcado)
Botão Iniciar: 🔒 Desabilitado
Fila: Vazia
Indicadores: 0.0 (todos cinza)
```

### 2. Estado Checklist Completo

```
Header: ✅ Verde - "👤 João Silva"
Checklist: Todos ✓ (marcados)
Botão Iniciar: ✅ Habilitado (verde #9CAF97)
Fila: 3 itens
Indicadores: 0.0 (aguardando)
```

### 3. Estado Durante Emissão

```
Header: ✅ Verde - "👤 João Silva"
Checklist: Todos ✓
Botão Iniciar: 🔒 Desabilitado
Fila: Item 1 "Emitindo 65%", Item 2 "Pendente"
Indicadores: Atualizando em tempo real
  RMS: 12.3 mV (verde)
  Pico: 45.2 mV (laranja)
  Freq: 528.1 Hz (azul)
  Imped: 1250 Ω (roxo)
  Improvement: 67.8% (barra verde)
  Tempo: 145 / 300 seg (amarelo)
```

### 4. Estado Pausa Automática (Impedância Fora)

```
Header: ⚠️ Amarelo - "👤 João Silva"
Checklist: ⚠️ "Dispositivo" desmarcado
Botão Iniciar: 🔒 Desabilitado
Fila: Item 1 "⏸️ PAUSADO"
Indicadores: 
  Imped: 85 Ω (VERMELHO - fora de gama)
Mensagem: "⚠️ Impedância fora de gama - verificar eletrodos"
Botão Retomar: Aparece
```

### 5. Estado Sessão Concluída

```
Header: ✅ Verde - "👤 João Silva"
Checklist: Todos ✓
Botão Iniciar: ✅ Habilitado (reiniciar)
Fila: Todos "✓ Concluído"
Indicadores: Valores finais (congelados)
Improvement: 100% (verde completo)
Botão Exportar: 📄 Habilitado e destacado
```

### 6. Estado Sem Paciente

```
Header: ❌ Vermelho - "⚠️ NENHUM PACIENTE"
Mensagem: "Abra a ficha do paciente primeiro"
Checklist: 🔒 Desabilitado
Botão Iniciar: 🔒 Desabilitado
Todas as colunas: Bloqueadas (opacity 0.5)
```

---

## Animações e Transições

### Loading States

**Durante Scan**:
```
🔍 SCAN RESSONANTE
┌───────────────────────────┐
│  ⟳ Scanning...            │
│  ▓▓▓▓▓░░░░░░░░░░░░  25%  │
└───────────────────────────┘
```

**Durante Importação Excel**:
```
📥 IMPORTAR EXCEL
┌───────────────────────────┐
│  ⟳ Validating...          │
│  45 / 100 rows            │
└───────────────────────────┘
```

### Hover Effects

**Botões**:
- Primário: #9CAF97 → #879B83
- Secundário: Escala 1.05 + sombra

**Cards de Protocolo**:
- Fundo: White → #F0F6EE
- Borda: #E3E9DE → #9CAF97
- Cursor: pointer

### Transições

**Aba ativa**:
- Fade in: 0.3s ease
- Slide up: 10px

**Indicadores**:
- Atualização: 0.5s ease
- Pulse quando > limiar

---

## Responsividade

### Breakpoints

**Tela grande (≥1600px)**:
```
Coluna 1: 30%
Coluna 2: 25%
Coluna 3: 35%
Gaps: 10px
```

**Tela média (1200-1599px)**:
```
Coluna 1: 35%
Coluna 2: 25%
Coluna 3: 30%
Gaps: 8px
```

**Tela pequena (<1200px)**:
```
Stack vertical:
- Catálogo (100%)
- Controlo (100%)
- Visualização (100%)
```

---

## Acessibilidade

### Cores com Contraste WCAG AA

- Texto principal (#3F4A3D) em fundo claro (#FCFDFB): 9.2:1 ✅
- Texto secundário (#5A6558) em fundo claro: 6.8:1 ✅
- Botão verde (#9CAF97) com texto branco: 4.6:1 ✅

### Keyboard Navigation

- Tab: Navegar entre campos
- Enter: Executar comando do botão focado
- Space: Toggle checkbox
- Esc: Fechar modais

### Screen Readers

- Todos os botões têm aria-label
- Sliders têm aria-valuenow/valuemin/valuemax
- Indicadores têm role="status" e aria-live="polite"

---

**Última atualização**: 2025-01-09
**Versão**: 1.0
**Plataforma**: WPF .NET 8
