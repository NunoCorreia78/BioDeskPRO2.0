# 📊 DIAGRAMA VISUAL - Sistema Terapias CoRe

**Versão**: Ilustrada com diagramas ASCII  
**Objetivo**: Compreensão rápida do fluxo de trabalho

---

## 🗂️ Estrutura Completa do Separador Terapias

```
┌─────────────────────────────────────────────────────────────────────┐
│                    🌿 Separador TERAPIAS                            │
│                (Sistema CoRe 5.0 Inspirado)                         │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ├── 📊 Sub-separador 1: AVALIAÇÃO
                              │   └── Scan RNG de 156 itens do Banco Core
                              │
                              ├── 📝 Sub-separador 2: PROGRAMAS
                              │   └── Importação de protocolos Excel
                              │
                              ├── 🎵 Sub-separador 3: RESSONANTES
                              │   └── Sweep de frequências (10-2000 Hz)
                              │
                              ├── ⚡ Sub-separador 4: BIOFEEDBACK
                              │   └── Aplicação Local/Remota
                              │
                              └── 📜 Sub-separador 5: HISTÓRICO
                                  └── Sessões anteriores (🚧 em desenvolvimento)
```

---

## 🔄 Fluxo de Dados entre Sub-separadores

```
┌──────────────┐
│  AVALIAÇÃO   │──┐
│ (Scan RNG)   │  │
└──────────────┘  │
                  │
┌──────────────┐  │         ┌──────────────────┐
│  PROGRAMAS   │──┼────────>│  LISTA ATIVA     │
│ (Excel)      │  │         │  (SharedService) │
└──────────────┘  │         └──────────────────┘
                  │                  │
┌──────────────┐  │                  │
│ RESSONANTES  │──┘                  │
│ (Sweep)      │                     │
└──────────────┘                     │
                                     ▼
                            ┌──────────────────┐
                            │   BIOFEEDBACK    │
                            │   (Aplicação)    │
                            └──────────────────┘
                                     │
                                     ▼
                            ┌──────────────────┐
                            │    HISTÓRICO     │
                            │  (Persistência)  │
                            └──────────────────┘
```

**Explicação**:
- Os 3 primeiros sub-separadores (Avaliação, Programas, Ressonantes) **alimentam** a Lista Ativa
- O sub-separador Biofeedback **consome** a Lista Ativa para aplicação
- O Histórico **regista** as sessões concluídas

---

## 📊 Sub-separador 1: AVALIAÇÃO (Layout)

```
┌─────────────────────────────────────────────────────────────────────┐
│  ⚙️ Configuração do Scan RNG                                        │
├─────────────────────────────────────────────────────────────────────┤
│  Fonte da Semente:  [Nome+DataNasc ▼]                              │
│  Gerador RNG:       [XorShift128+  ▼]                              │
│  Salt da Sessão:    [20251015...   ] [🔄 Regenerar]                │
│  Iterações:         [50000          ]                               │
├─────────────────────────────────────────────────────────────────────┤
│  [🔍 Executar Scan] [➕ Adicionar à Lista] [💾 Guardar]            │
├─────────────────────────────────────────────────────────────────────┤
│  📊 Resultados do Scan                                              │
│  ┌────────────────────────────────────────────────────────────────┐│
│  │ Nome              │ Código      │ Categoria  │ Score  │ Rank  ││
│  ├────────────────────────────────────────────────────────────────┤│
│  │ Rescue Remedy     │ BACH::01    │ FloraisBach│ 87.3%  │ 1     ││
│  │ Chakra Cardíaco   │ CHAKRA::04  │ Chakra     │ 79.2%  │ 2     ││
│  │ Meridiano Fígado  │ MERID::03   │ Meridiano  │ 72.1%  │ 3     ││
│  │ ...               │ ...         │ ...        │ ...    │ ...   ││
│  └────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

---

## 📝 Sub-separador 2: PROGRAMAS (Layout)

```
┌─────────────────────────────────────────────────────────────────────┐
│  [C:\...\Frequencias.xlsx     ] [📥 Importar] [🔍      ] [Atualizar]│
├──────────────────────────┬──────────────────────────────────────────┤
│  📋 Programas Importados │  ⚡ Passos do Programa Selecionado       │
│ ┌────────────────────────┤ ┌────────────────────────────────────────┤
│ │ Rife Cancer Basic      │ │ [➕ Adicionar à Lista Ativa]           │
│ │ Clark Parasites        │ ├────────────────────────────────────────┤
│ │ Hulda Liver Detox      │ │ # │ Hz     │ Duty │ Seg │ Notas       │
│ │ Schumann Resonance     │ ├────────────────────────────────────────┤
│ │ ...                    │ │ 1 │ 666.0  │ 50%  │ 180 │ Freq. base  │
│ └────────────────────────┘ │ 2 │ 690.0  │ 50%  │ 180 │ Harmónica   │
│                            │ 3 │ 727.0  │ 50%  │ 180 │ 3ª harm.    │
│                            └────────────────────────────────────────┘
└─────────────────────────────────────────────────────────────────────┘
```

**⚠️ RESPOSTA DIRETA "ONDE COLAR EXCEL"**:
```
No campo: [C:\...\Frequencias.xlsx     ]
          ▲
          └── AQUI! Cole o caminho completo do ficheiro Excel
```

---

## 🎵 Sub-separador 3: RESSONANTES (Layout)

```
┌─────────────────────────────────────────────────────────────────────┐
│  🎵 Configuração do Sweep                                           │
├─────────────────────────────────────────────────────────────────────┤
│  Início (Hz): [10      ]       Fim (Hz):   [2000    ]              │
│  Passo (Hz):  [1       ]       Dwell (ms): [150     ]              │
├─────────────────────────────────────────────────────────────────────┤
│  [🚀 Executar Sweep]  [➕ Adicionar Selecionado]                   │
├─────────────────────────────────────────────────────────────────────┤
│  📈 Resultados do Sweep                                             │
│  ┌────────────────────────────────────────────────────────────────┐│
│  │ Hz        │ Score    │ Notas                                   ││
│  ├────────────────────────────────────────────────────────────────┤│
│  │ 728.00 Hz │ 92.3%    │ ← Pico muito alto (provável ressonância)││
│  │ 432.00 Hz │ 85.7%    │                                         ││
│  │ 666.00 Hz │ 78.4%    │                                         ││
│  │ ...       │ ...      │                                         ││
│  └────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

**Visualização do Sweep**:
```
Score%
100 │                  *
 90 │        *              *
 80 │  *           *
 70 │
 60 │     *     *
 50 │
    └────────────────────────> Frequência (Hz)
    10       500      1000     2000
```

---

## ⚡ Sub-separador 4: BIOFEEDBACK (Layout)

```
┌──────────────────────┬──────────────────────────────────────────────┐
│  📋 Lista Ativa      │  ⚙️ Configuração                             │
│ ┌────────────────────┤ ┌────────────────────────────────────────────┤
│ │ Nome        Score  │ │ Modo: [Remoto (Informação) ▼]             │
│ ├────────────────────┤ │ Estado: 🟢 Pronto                          │
│ │ Item 1      87.3%  │ ├────────────────────────────────────────────┤
│ │ Item 2      79.2%  │ │ 🌐 Emissão Remota                          │
│ │ Item 3      72.1%  │ │ Âncora:     [João Silva 1980-05-15       ] │
│ │ ...         ...    │ │ Hash:       [SHA256              ▼]       │
│ └────────────────────┘ │ Modulação:  [AM-Ruído            ▼]       │
│                        │ Ciclos:     [3    ]  Tempo/Item: [20 s]   │
│                        │ On (ms):    [800  ]  Off (ms):   [200  ]   │
│                        │ ✅ Verificar Drift                         │
│                        ├────────────────────────────────────────────┤
│                        │ ▶️ Execução                                │
│                        │ [▶️ Iniciar] [⏸️ Pausar] [⏹️ Parar] [🛑]   │
│                        │ 📊 Telemetria:                             │
│                        │ ┌──────────────────────────────────────────┤
│                        │ │[14:32:01] Sessão iniciada - Remoto     ││
│                        │ │[14:32:05] Item 1/10: Rescue (20s)      ││
│                        │ │[14:32:25] Improvement: 15.3%            ││
│                        │ └──────────────────────────────────────────┘
└──────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Cenário de Uso Típico (Sequência Visual)

### Cenário: Avaliação CoRe Standard

```
PASSO 1: Configurar Avaliação
┌─────────────────────────┐
│ Fonte: Nome+DataNasc    │
│ RNG: XorShift128+       │
│ Iterações: 50000        │
└─────────────────────────┘
            │
            ▼
PASSO 2: Executar Scan
┌─────────────────────────┐
│ [🔍 Executar Scan]      │
│                         │
│ ⏳ Aguardar ~10 seg...  │
└─────────────────────────┘
            │
            ▼
PASSO 3: Analisar Resultados
┌─────────────────────────┐
│ ✅ Top 10 scores altos  │
│ 1. Item A - 87.3%       │
│ 2. Item B - 79.2%       │
│ ...                     │
└─────────────────────────┘
            │
            ▼
PASSO 4: Selecionar e Adicionar
┌─────────────────────────┐
│ Ctrl+Click nos Top 10   │
│ [➕ Adicionar à Lista]  │
└─────────────────────────┘
            │
            ▼
PASSO 5: Ir para Biofeedback
┌─────────────────────────┐
│ Sub-separador 4         │
│ Lista Ativa: 10 itens ✅│
└─────────────────────────┘
            │
            ▼
PASSO 6: Configurar Modo Remoto
┌─────────────────────────┐
│ Modo: Remoto            │
│ Âncora: Nome+DataNasc   │
│ Tempo/Item: 20s         │
│ Ciclos: 3               │
└─────────────────────────┘
            │
            ▼
PASSO 7: Iniciar Sessão
┌─────────────────────────┐
│ [▶️ Iniciar]            │
│                         │
│ ⏳ ~10 minutos          │
│ (10 × 20s × 3 ciclos)   │
└─────────────────────────┘
            │
            ▼
PASSO 8: Conclusão
┌─────────────────────────┐
│ ✅ Sessão concluída     │
│ Improvement: 85.7%      │
└─────────────────────────┘
```

---

## 📊 Tabela Comparativa: Modo Local vs Remoto

```
┌─────────────────────┬──────────────────────┬──────────────────────┐
│   CARACTERÍSTICA    │    MODO LOCAL        │    MODO REMOTO       │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ Cliente presente?   │ ✅ Sim (obrigatório) │ ❌ Não (pode estar   │
│                     │                      │    ausente)          │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ Equipamento físico? │ ✅ Sim (gerador +    │ ❌ Não (software)    │
│                     │    eletrodos)        │                      │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ Tipo de emissão     │ ⚡ Energética        │ 🌐 Informacional    │
│                     │    (elétrica)        │    (quântica)        │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ Campos configurar   │ • Forma Onda         │ • Âncora             │
│                     │ • Frequência         │ • Hash               │
│                     │ • Duty %             │ • Modulação          │
│                     │ • Vpp                │ • Ciclos             │
│                     │ • Corrente (mA)      │ • On/Off (ms)        │
│                     │ • Compliance         │ • Drift Check        │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ Sensação física?    │ ✅ Sim (formigueiro, │ ❌ Não (subtil ou    │
│                     │    vibração)         │    nenhuma)          │
├─────────────────────┼──────────────────────┼──────────────────────┤
│ Status              │ 🚧 Não implementado  │ ✅ Funcional         │
│ desenvolvimento     │    (requer hardware) │                      │
└─────────────────────┴──────────────────────┴──────────────────────┘
```

---

## 🎯 Decisão: Qual Sub-separador Usar?

```
                         INÍCIO
                           │
                           ▼
              ┌────────────────────────┐
              │ Já conhece protocolo   │
              │ específico (ex: Rife)? │
              └────────────────────────┘
                     │          │
                   SIM         NÃO
                     │          │
                     ▼          ▼
            ┌────────────┐  ┌────────────┐
            │ PROGRAMAS  │  │ Quer testar│
            │ (Excel)    │  │ itens do   │
            └────────────┘  │ Banco Core?│
                            └────────────┘
                                  │
                            SIM ◄─┴─► NÃO
                             │         │
                             ▼         ▼
                    ┌────────────┐  ┌────────────┐
                    │ AVALIAÇÃO  │  │ Quer       │
                    │ (Scan RNG) │  │ descobrir  │
                    └────────────┘  │ freq. novas?│
                                    └────────────┘
                                         │
                                        SIM
                                         │
                                         ▼
                                ┌────────────────┐
                                │  RESSONANTES   │
                                │  (Sweep)       │
                                └────────────────┘
                                         │
                    ┌────────────────────┴────────────────┐
                    │ Todos convergem em:                 │
                    │         BIOFEEDBACK                 │
                    │        (Aplicação)                  │
                    └─────────────────────────────────────┘
```

---

## 📋 Checklist Visual de Sessão

```
┌────────────────────────────────────────────┐
│ ✅ CHECKLIST DE SESSÃO BIOFEEDBACK         │
├────────────────────────────────────────────┤
│ ANTES:                                     │
│ [ ] Paciente selecionado na ficha          │
│ [ ] Separador Terapias aberto              │
│                                            │
│ SUB-SEPARADOR 1 (se usar Avaliação):       │
│ [ ] Executar Scan (aguardar 10s)           │
│ [ ] Selecionar Top 10 itens                │
│ [ ] Adicionar à Lista Ativa                │
│                                            │
│ SUB-SEPARADOR 2 (se usar Programas):       │
│ [ ] Excel importado com sucesso            │
│ [ ] Protocolo selecionado                  │
│ [ ] Adicionar à Lista Ativa                │
│                                            │
│ SUB-SEPARADOR 4 (Biofeedback):             │
│ [ ] Verificar Lista Ativa NÃO vazia        │
│ [ ] Modo: Remoto (ou Local se tiver HW)   │
│ [ ] Âncora preenchida (se Remoto)          │
│ [ ] Tempo/Item: 20s (ajustar se preciso)   │
│ [ ] Ciclos: 3 (ajustar se preciso)         │
│ [ ] Clicar [▶️ Iniciar]                    │
│                                            │
│ DURANTE:                                   │
│ [ ] Acompanhar telemetria                  │
│ [ ] Verificar Improvement % a subir        │
│ [ ] Pausar/Parar se necessário             │
│                                            │
│ DEPOIS:                                    │
│ [ ] Verificar "Concluído" no Estado        │
│ [ ] Registar Improvement % final           │
│ [ ] (Futuro) Consultar Histórico           │
└────────────────────────────────────────────┘
```

---

## 🔍 Legenda de Símbolos Usados

```
📊 - Dados/Análise           ⚡ - Energia/Aplicação
📝 - Configuração/Input      🌐 - Remoto/Rede
🎵 - Frequências             🔍 - Pesquisa/Scan
📋 - Lista/Tabela            ➕ - Adicionar
⚙️ - Configurações           ▶️ - Iniciar/Play
⏸️ - Pausar                  ⏹️ - Parar
🛑 - Emergência/Stop         💾 - Guardar
🔄 - Regenerar/Atualizar     ✅ - Completo/OK
❌ - Não/Desabilitado        🚧 - Em desenvolvimento
📥 - Importar                🟢 - Pronto
🟡 - Em execução             🔴 - Pausado
⏳ - Aguardar                🔹 - Ponto de escolha
```

---

## 📐 Fórmulas Rápidas

### Duração Estimada de Sweep
```
Duração = (Freq_Fim - Freq_Início) / Passo × Dwell
Exemplo: (2000 - 10) / 1 × 150ms = 298,500ms ≈ 5 minutos
```

### Duração Estimada de Sessão Biofeedback
```
Duração = Nº_Itens × Tempo_por_Item × Ciclos
Exemplo: 10 itens × 20s × 3 ciclos = 600s = 10 minutos
```

### Cálculo de Improvement %
```
Improvement% = (Score_Atual - Baseline) / (100 - Baseline) × 100
Exemplo: (90 - 65) / (100 - 65) × 100 = 71.4%
```

---

## 🎨 Paleta de Cores Sugerida (UI)

```
┌────────────────────────────────────────────┐
│ SCORES ALTOS (>80%):    🟢 Verde (#6B9F5F) │
│ SCORES MÉDIOS (50-80%): 🟡 Amarelo (#F4C430)│
│ SCORES BAIXOS (<50%):   🔴 Vermelho (#D65D5D)│
│                                            │
│ ESTADO PRONTO:          🟢 Verde           │
│ ESTADO EM EXECUÇÃO:     🟡 Amarelo         │
│ ESTADO ERRO:            🔴 Vermelho        │
│                                            │
│ FUNDO PRINCIPAL:        ⬜ Branco (#FCFDFB)│
│ CARTÕES:                🟦 Azul Claro      │
│ BORDAS:                 ⬜ Cinza (#E3E9DE) │
└────────────────────────────────────────────┘
```

---

**Criado**: 15 de Outubro de 2025  
**Tipo**: Documentação Visual com Diagramas ASCII  
**Uso**: Complementar ao GUIA_COMPLETO e REFERENCIA_RAPIDA
