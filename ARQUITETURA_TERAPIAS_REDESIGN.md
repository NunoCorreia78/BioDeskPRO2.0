# 🏗️ Arquitetura Terapias - Redesign "Topo de Gama"

## 🎯 Princípios de Design

1. **Clareza**: Cada aba tem 1 propósito óbvio
2. **Ação Direta**: Botão "Iniciar Terapia X" em cada aba
3. **Autonomia**: Cada módulo independente (sem "lista ativa" partilhada)
4. **Segurança**: Controlo voltagem visível em TODAS as terapias com corrente

---

## 📐 Arquitetura Modular

### **1. ABA AVALIAÇÃO** 
**Função**: Terapia Remota (Informacional)

#### Características:
- **Sem frequências** (apenas seeds, RNG, anchor)
- Scan RNG → Lista protocolos ressonantes
- **Não mostra Hz** (terapia é informacional, não elétrica)

#### UI:
```
┌─────────────────────────────────────────┐
│ Configuração Scan                       │
│ • Fonte semente: Nome+DataNasc          │
│ • Gerador RNG: XorShift128+             │
│ • Filtrar categoria: [Todas ▼]          │
│ • Iterações: 50000                      │
│ └─ [Executar Scan]                      │
│                                         │
│ Resultados                              │
│ ┌──────────────────────┬─────┬────┐    │
│ │ Nome           │ Cat.│Rank│    │    │
│ ├──────────────────────┼─────┼────┤    │
│ │ Yang Wei Mai   │Merid│ 1  │    │    │
│ │ Chakra Palmas  │Chak │ 2  │    │    │
│ └──────────────────────┴─────┴────┘    │
│                                         │
│ [Iniciar Terapia Remota]                │
└─────────────────────────────────────────┘
```

#### Modal "Terapia Remota":
```
┌──────────────────────────────────────┐
│ Configuração Terapia Remota         │
│                                      │
│ Protocolos Selecionados:             │
│ • Yang Wei Mai                       │
│ • Chakra das Palmas                  │
│                                      │
│ Duração: [14] dias (14 dias default)│
│ Anchor: [Nome+DataNasc]              │
│ Hash: [SHA256 ▼]                    │
│ Modulação: [Amplitude ▼]             │
│ Ciclos: [1000]                       │
│                                      │
│ [Iniciar Transmissão] [Cancelar]     │
└──────────────────────────────────────┘
```

---

### **2. ABA PROGRAMAS**
**Função**: Terapia Local (Protocolos Pré-definidos)

#### Características:
- Lista 1,272 protocolos com Hz reais
- Seleção múltipla (Ctrl/Shift)
- **Mostra tabela de frequências** antes de iniciar

#### UI:
```
┌─────────────────────────────────────────┐
│ [Pesquisa: ______] 1,272 disponíveis   │
│                                         │
│ Programas              │ Frequências    │
│ ┌────────────────────┐│┌──────────────┐│
│ │ PROTO::Detox      ││││ # │Hz │Duty│s││
│ │ PROTO::AntiViral  ││││ 1│728│50% │180││
│ │ PROTO::Chakra     ││││ 2│880│50% │180││
│ └────────────────────┘││ 3│1500│50%│180││
│                       │└──────────────┘│
│                       │                │
│    [Iniciar Terapia Local]             │
└─────────────────────────────────────────┘
```

#### Modal "Terapia Local":
```
┌──────────────────────────────────────┐
│ Terapia Local - PROTO::Detox        │
│                                      │
│ Voltagem: ┣━━━━○━━━━┫ 5.2V          │
│ Corrente Max: 50 mA                  │
│                                      │
│ Progresso: ┣━━━━━━━━━━━━┫ 45%       │
│ Hz Atual: 880.0 Hz (Duty: 50%)       │
│ Tempo: 2:15 / 5:00                   │
│                                      │
│ Frequências Restantes:               │
│ ✓ 728 Hz (completo)                  │
│ → 880 Hz (em curso)                  │
│   1500 Hz (pendente)                 │
│                                      │
│ [Pausar] [Parar]                     │
└──────────────────────────────────────┘
```

---

### **3. ABA RESSONANTES**
**Função**: Terapia Local (Frequências Ressonantes)

#### Características:
- Scan encontra Hz individuais ressonantes
- **Não usa protocolos** (só Hz puras)
- Idêntico a Programas mas com Hz descobertas dinamicamente

#### UI:
```
┌─────────────────────────────────────────┐
│ Scan Ressonante                         │
│ Range: [100] Hz a [5000] Hz             │
│ Step: [10] Hz                           │
│ Iterações: [50000]                      │
│ └─ [Executar Scan]                      │
│                                         │
│ Frequências Ressonantes Encontradas     │
│ ┌──────────┬────────┬──────┐           │
│ │ Hz       │ Score  │ Rank │           │
│ ├──────────┼────────┼──────┤           │
│ │ 728.5    │ 98.3%  │  1   │           │
│ │ 1550.0   │ 95.1%  │  2   │           │
│ └──────────┴────────┴──────┘           │
│                                         │
│ [Iniciar Terapia Local]                 │
└─────────────────────────────────────────┘
```

#### Modal: Igual a "Programas" (mesmo controlo voltagem)

---

### **4. ABA BIOFEEDBACK**
**Função**: Terapia Autónoma (Loop Automático)

#### Características:
- **100% independente** de outras abas
- Loop contínuo:
  1. Scan RNG → Deteta Hz necessárias
  2. Emite essas Hz com voltagem configurada
  3. Re-scan após X segundos
  4. Ajusta automaticamente
  5. Repete até terapeuta parar

#### UI:
```
┌──────────────────────────────────────────┐
│ Sessão Biofeedback Autónoma             │
│                                          │
│ Status: ● A EXECUTAR                    │
│                                          │
│ Voltagem: ┣━━━○━━━━━┫ 3.5V             │
│ Corrente: 25 mA                          │
│                                          │
│ Ciclo Atual: 3/∞                         │
│ Scan #3 → 5 Hz detectadas                │
│                                          │
│ A Emitir:                                │
│ → 728.5 Hz (85% score) - 45s restantes   │
│                                          │
│ Histórico (últimos 3 ciclos):           │
│ • Ciclo 1: 728Hz, 880Hz (2 min)         │
│ • Ciclo 2: 1550Hz (1 min)                │
│ • Ciclo 3: 728Hz, 2000Hz (em curso)      │
│                                          │
│ Próximo re-scan em: 120s                 │
│                                          │
│ [Pausar] [Parar Sessão]                  │
└──────────────────────────────────────────┘
```

---

## 🗄️ Persistência (Histórico)

### Tabela `SessionHistorico`:
```sql
CREATE TABLE SessionHistorico (
    Id INTEGER PRIMARY KEY,
    PacienteId INTEGER NOT NULL,
    TipoTerapia TEXT NOT NULL, -- 'Remota' | 'Local' | 'Biofeedback'
    DataHoraInicio DATETIME NOT NULL,
    DuracaoMinutos INTEGER,
    VoltagemV REAL,
    CorrenteMa REAL,
    Protocolos TEXT, -- JSON array: ["PROTO::Detox", "PROTO::AntiViral"]
    FrequenciasHz TEXT, -- JSON array: [728, 880, 1500]
    Notas TEXT,
    CriadoEm DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Aba "Histórico":
- Lista todas as sessões anteriores
- Filtro por data, tipo, paciente
- Botão "Repetir Sessão" (copia configurações)

---

## 🚨 Segurança

### Controlos Obrigatórios:
1. **Voltagem visível** em TODAS as terapias com corrente
2. **Slider grande** (fácil de ajustar)
3. **Valor numérico** sempre visível
4. **Limite máximo** configurável (default: 10V)
5. **Botão Parar** sempre acessível (não "Emergência" - é redundante)

---

## 📊 Fluxo Completo

```
Terapeuta abre paciente
    ↓
┌─────────────────────────────────┐
│ Escolhe tipo de terapia:        │
├─────────────────────────────────┤
│ 1. Avaliação → Terapia Remota   │
│    • Scan RNG                   │
│    • Sem voltagem/Hz            │
│    • Duração: 14 dias default   │
│                                 │
│ 2. Programas → Terapia Local    │
│    • Escolhe protocolo(s)       │
│    • Controlo voltagem          │
│    • Emite Hz                   │
│                                 │
│ 3. Ressonantes → Terapia Local  │
│    • Scan Hz ressonantes        │
│    • Controlo voltagem          │
│    • Emite Hz encontradas       │
│                                 │
│ 4. Biofeedback → Autónomo       │
│    • Loop automático            │
│    • Scan + Emitir + Re-scan    │
│    • Ajusta dinamicamente       │
└─────────────────────────────────┘
    ↓
Sessão registada em Histórico
```

---

## ✅ Checklist Implementação

### Fase 1: Modals (1h)
- [ ] `TerapiaLocalWindow.xaml` (voltagem, progress, Hz)
- [ ] `TerapiaRemotaWindow.xaml` (duração 14 dias, anchor, hash)
- [ ] `TerapiaLocalViewModel.cs`
- [ ] `TerapiaRemotaViewModel.cs`

### Fase 2: Redesign ViewModels (30min)
- [ ] `AvaliacaoViewModel`: Botão "Iniciar Terapia Remota"
- [ ] `ProgramasViewModel`: Botão "Iniciar Terapia Local"
- [ ] `RessonantesViewModel`: Botão "Iniciar Terapia Local"
- [ ] `BiofeedbackViewModel`: Loop autónomo

### Fase 3: Histórico (30min)
- [ ] Migration EF: Tabela `SessionHistorico`
- [ ] `HistoricoViewModel.cs`
- [ ] `HistoricoView.xaml`

### Fase 4: Testes (30min)
- [ ] Testar fluxo completo
- [ ] Verificar persistência
- [ ] Validar controlos voltagem

---

**Total Estimado: 2h30min**

🚀 **Pronto para aprovar e implementar?**
