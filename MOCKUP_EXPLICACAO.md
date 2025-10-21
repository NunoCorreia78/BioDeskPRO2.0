# 📐 MOCKUP: Painel de Configurações Avançadas de Terapia

## 🎯 Onde Vai Aparecer
Este painel será adicionado **dentro de cada sub-aba** de `TerapiasBioenergeticasUserControl`:
- **Aba "Programas"** → Tem o seu próprio painel de configurações
- **Aba "Ressonantes"** → Tem o seu próprio painel de configurações
- **Aba "Biofeedback"** → Tem o seu próprio painel de configurações

Cada aba pode ter configurações **diferentes** guardadas.

---

## 🖼️ Layout Visual (ASCII)

```
╔════════════════════════════════════════════════════════════════════════════╗
║  ⚙️ CONFIGURAÇÕES DE EMISSÃO                                               ║
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                            ║
║  ┌────────────────────────────────┐    ┌────────────────────────────────┐ ║
║  │ Forma de Onda                  │    │ Voltagem            5.0 V      │ ║
║  │ ┌────────────────────────────┐ │    │ ├──────●────────────────────┤ │ ║
║  │ │ 🌊 Seno (Suave)          ▼ │ │    │ 0V                         12V │ ║
║  │ └────────────────────────────┘ │    │ Tensão elétrica aplicada       │ ║
║  │ Padrão de modulação do sinal   │    └────────────────────────────────┘ ║
║  └────────────────────────────────┘                                       ║
║                                                                            ║
║  ┌────────────────────────────────┐    ┌────────────────────────────────┐ ║
║  │ Amplitude (%)           85%    │    │ Duração Total da Sessão        │ ║
║  │ ├────────────●──────────────┤ │    │ ┌─────────┐                    │ ║
║  │ 10%                       100% │    │ │   30    │ minutos            │ ║
║  │ Percentagem da intensidade max │    │ └─────────┘                    │ ║
║  └────────────────────────────────┘    │ Tempo máximo aplicação auto    │ ║
║                                         └────────────────────────────────┘ ║
║                                                                            ║
║  ──────────────────────────────────────────────────────────────────────  ║
║                                                                            ║
║  ⏱️ Tempo de Emissão por Frequência                                       ║
║  ○ 5 segundos    ○ 10 segundos    ● 15 segundos    ○ Personalizado [8]seg║
║  Define quanto tempo cada Hz será emitida antes de passar para próxima    ║
║                                                                            ║
║  ──────────────────────────────────────────────────────────────────────  ║
║                                                                            ║
║                        [💾 Guardar como Padrão]  [🔄 Restaurar Padrão]   ║
║                                                                            ║
║  ┌────────────────────────────────────────────────────────────────────┐  ║
║  │ 💡 Estas configurações aplicam-se a TODOS os protocolos desta aba  │  ║
║  │    (Programas/Ressonantes/Biofeedback). Podes ter configurações    │  ║
║  │    diferentes para cada tipo de terapia.                            │  ║
║  └────────────────────────────────────────────────────────────────────┘  ║
╚════════════════════════════════════════════════════════════════════════════╝
```

---

## 📋 Elementos do Painel

### 🌊 **Forma de Onda** (Dropdown)
Opções disponíveis:
- **🌊 Seno (Suave)** - Onda sinusoidal suave, ideal para terapias prolongadas
- **⬜ Quadrada (Pulsada)** - Onda quadrada com transições abruptas, máxima penetração
- **📐 Triangular (Linear)** - Onda triangular com rampa linear
- **⚡ Pulso (Intenso)** - Pulsos curtos de alta intensidade

**Uso:** Diferentes patologias podem responder melhor a diferentes formas de onda.

---

### ⚡ **Voltagem** (Slider 0-12V)
Controlo da tensão elétrica aplicada ao equipamento TiePie HS3.
- **Mínimo:** 0V (desligado)
- **Máximo:** 12V (máxima potência)
- **Padrão:** 5V (seguro para maioria das terapias)

---

### 📊 **Amplitude** (Slider 10-100%)
Percentagem da intensidade máxima do sinal.
- **10%:** Terapia muito suave (diagnóstico)
- **50%:** Terapia moderada (manutenção)
- **85%:** Terapia intensa (tratamento ativo)
- **100%:** Máxima intensidade (casos agudos)

---

### ⏱️ **Duração Total da Sessão** (Input numérico)
Tempo máximo que a sessão pode durar antes de parar automaticamente.
- **Unidade:** Minutos
- **Padrão:** 30 minutos
- **Exemplo:** 45 minutos para terapias longas (detox)

---

### ⏱️ **Tempo por Frequência** (RadioButtons + Input)
Quanto tempo cada frequência será emitida antes de passar para a próxima.

**Opções pré-definidas:**
- ○ 5 segundos (rápido - scanning)
- ○ 10 segundos (normal - terapia padrão)
- ● 15 segundos (longo - casos crônicos)
- ○ **Personalizado:** [__8__] seg (input manual)

---

## 🎯 Como Funciona

1. **Utilizador abre aba "Programas"** na ficha do paciente
2. **Painel aparece no topo** (antes da lista de protocolos)
3. **Ajusta configurações específicas** para Programas:
   - Forma Onda: Quadrada (penetração máxima para parasitas)
   - Voltagem: 8V
   - Amplitude: 90%
   - Tempo/freq: 10 seg

4. **Clica "Guardar como Padrão"** → Configuração fica persistida na BD
5. **Próxima vez que abrir "Programas"** → Carrega estas configurações automaticamente

6. **Se mudar para aba "Ressonantes":**
   - Pode ter configurações **completamente diferentes** guardadas:
   - Forma Onda: Seno (suave para ressonâncias)
   - Voltagem: 3V
   - Amplitude: 60%
   - Tempo/freq: 15 seg

---

## 💾 Persistência (Base de Dados)

### Tabela: `ConfiguracaoClinica`
Adicionar 3 colunas JSON:

```csharp
public string? TerapiaProgramasSettingsJson { get; set; }
public string? TerapiaRessonantesSettingsJson { get; set; }
public string? TerapiaBiofeedbackSettingsJson { get; set; }
```

### Modelo: `TerapiaSettings`
```csharp
public class TerapiaSettings {
    public TipoTerapia Tipo { get; set; } // Programas/Ressonantes/Biofeedback
    public FormaOnda FormaOnda { get; set; } // Seno/Quadrada/Triangular/Pulso
    public double VoltageemV { get; set; } // 0-12V
    public double AmplitudePercent { get; set; } // 10-100%
    public int DuracaoTotalMinutos { get; set; } // Tempo máximo sessão
    public int TempoPorFrequenciaSegundos { get; set; } // 5/10/15/custom
}
```

---

## 🚀 Próximos Passos

### Opção A - Apenas UI Mockup (para aprovação)
✅ Criar XAML visual básico (FEITO)
- Ver ficheiro `MOCKUP_ConfiguracoesTerapia.xaml`
- Testar visualmente sem backend
- Tu aprovas o layout

### Opção B - Implementação Completa
1. Criar `enum FormaOnda`
2. Criar modelo `TerapiaSettings`
3. Estender `ConfiguracaoClinica` com 3 colunas JSON
4. Criar ViewModel com binding
5. Integrar em `TerapiasBioenergeticasUserControl.xaml`
6. Implementar lógica guardar/carregar
7. Testar com hardware TiePie

---

## ❓ O Que Preferes?

**A) Aprovar layout primeiro** → Depois implemento backend
**B) Implementar tudo agora** → Sprint 6 completo (~2-3h)
**C) Simplificar ainda mais** → Remover opções avançadas

**Diz-me o que achas do mockup! 🎨**
