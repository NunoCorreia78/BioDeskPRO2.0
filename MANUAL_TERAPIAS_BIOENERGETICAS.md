# 🌿 TERAPIAS BIOENERGÉTICAS - MANUAL COMPLETO

## 📖 Índice

1. [Visão Geral](#visão-geral)
2. [Fluxo Inergetix-CoRe v5.0](#fluxo-inergetix-core-v50)
3. [Arquitetura do Sistema](#arquitetura-do-sistema)
4. [Interface do Utilizador](#interface-do-utilizador)
5. [Excel Schema v1](#excel-schema-v1)
6. [Segurança Clínica](#segurança-clínica)
7. [Hardware Suportado](#hardware-suportado)
8. [Fluxos de Trabalho](#fluxos-de-trabalho)
9. [Troubleshooting](#troubleshooting)

---

## Visão Geral

O módulo **Terapias Bioenergéticas** (Tab 7) implementa o workflow completo do sistema Inergetix-CoRe v5.0, modernizado para integração com hardware TiePie HS3 e workflow clínico do BioDeskPro2.

### Funcionalidades Principais

✅ **Scan Ressonante**: Detecção de frequências com Value % (ordenadas 100% → 0%)
✅ **Emissão Sequencial**: Não mistura ondas - mantém "pureza" do sinal
✅ **Improvement %**: Feedback em tempo real durante emissão
✅ **Protocolos Excel**: Importação idempotente de protocolos pré-programados
✅ **Biofeedback Fisiológico**: Métricas RMS, Pico, FFT, Impedância
✅ **Segurança Clínica**: Limites hard 0-20V / 0-50mA com pausa automática
✅ **Relatórios Automáticos**: Exportação CSV/PDF com métricas completas

---

## Fluxo Inergetix-CoRe v5.0

### Pré-Requisito Crítico

⚠️ **SEMPRE abrir a ficha do paciente ANTES de usar qualquer módulo de frequências**

Só assim o sistema associa o scan e a emissão ao caso ativo. Sem paciente ativo, o sistema bloqueia todas as operações.

### Três Módulos Principais

#### 1. 🔍 Resonant Frequencies (Scan)

**Objetivo**: Identificar frequências ressonantes específicas do paciente

**Como funciona**:
1. Scan no intervalo configurável (ex: 0.1 Hz - 2 MHz)
2. Tabela ordenada por **Value %** (100% = maior ressonância)
3. Recomendação: trabalhar com itens **> 30%**
4. Durante emissão: acompanhar **Improvement %**
5. Meta: aproximar Improvement de 100%
6. Quando atinge 100% → desmarcar item e seguir próximo

**Interface**: Coluna 2 → Botão "Iniciar Scan" (azul)

#### 2. 🎯 Biofeedback

**Objetivo**: Scan + emissão imediata das frequências mais ressonantes

**Requer**: Hologram Generator (TRNG físico) ou CSPRNG com seed

**Como funciona**:
1. Scan do momento (client-specific)
2. Emissão automática das frequências top
3. Feedback em tempo real (RMS, pico, FFT)
4. Usa gerador de ruído para "aumentar o branco" do sistema

**Interface**: Modo ativado automaticamente quando HG disponível

#### 3. 📋 Frequency Program (Disease-specific)

**Objetivo**: Protocolos pré-definidos para +1100 condições

**Como funciona**:
1. Importar Excel com protocolos (ver Excel Schema v1)
2. Selecionar condição/protocolo
3. Definir: modo, amplitude, sweep/pausas, tempo total
4. Emissão sequencial (padrão CoRe)

**Interface**: Coluna 1 → Catálogo de Protocolos

### Passar do Scan para a Terapia

Após **Resonant Scan** ou **Biofeedback**:

**Opção 1**: Copiar frequências para fila e emitir já
- Selecionar checkboxes das frequências
- Clicar "Adicionar à Fila"
- Clicar "Iniciar Sessão"

**Opção 2**: Editar Excel para guardar conjunto personalizado
- Exportar frequências selecionadas
- Adicionar ao Excel `frequencylist.xls`
- Reimportar como protocolo nomeado

---

## Arquitetura do Sistema

### Domain Entities

#### ProtocoloTerapia
```csharp
- ExternalId: GUID único (Upsert key)
- Nome: Nome do protocolo
- FrequenciaHz: 0.01 - 2,000,000 Hz
- AmplitudeV: 0 - 20V
- LimiteCorrenteMa: 0 - 50mA
- FormaOnda: Sine/Square/Triangle/Saw
- Modulacao: AM/FM/Burst/None
- DuracaoMin: 1 - 180 min
- Canal: 1 ou 2 (TiePie HS3)
- SequenciaJSON: Override passo-a-passo (opcional)
```

#### SessaoTerapia
```csharp
- PacienteId: FK para Paciente
- DataHora: Timestamp da sessão
- TipoSessao: Scan/Biofeedback/Protocolo
- ConsentimentoHash: SHA-256 do PDF assinado
- Emissoes: List<EmissaoFrequencia>
- MetricasBiofeedbackJSON: Séries temporais
```

#### FrequenciaRessonante
```csharp
- FrequenciaHz: Frequência detectada
- ValuePct: 0-100% (ressonância inicial)
- ImprovementPct: 0-100% (evolução durante emissão)
- Status: Pendente/Emitindo/Concluído
```

#### EmissaoFrequencia
```csharp
- FrequenciaHz, AmplitudeV, LimiteCorrenteMa
- ValuePctInicial, ImprovementPctFinal
- RmsMedio, PicoMaximo, ImpedanciaMedia
- FrequenciaDominanteHz (do FFT)
```

### ViewModels

**TerapiaBioenergeticaViewModel**
- Gere todo o workflow do Tab 7
- Comandos: ImportarExcel, IniciarScan, IniciarEmissao, Pausar, Parar
- Observable collections: Protocolos, FrequenciasRessonantes, FilaEmissao
- Biofeedback em tempo real

---

## Interface do Utilizador

### Layout de 3 Colunas

```
┌─────────────────────────────────────────────────────────────┐
│ 🌿 Terapias Bioenergéticas │ 👤 PACIENTE ATIVO: João Silva │
├─────────────────────────────────────────────────────────────┤
│ ✓ Checklist: [x] Consentimento [x] Dispositivo [ ] Válido  │
│              [▶️ Iniciar Sessão]                             │
├────────────────┬──────────────┬──────────────────────────────┤
│ COLUNA 1       │ COLUNA 2     │ COLUNA 3                     │
│ Catálogo & Fila│ Controlo AWG │ Visualização Tempo Real      │
├────────────────┼──────────────┼──────────────────────────────┤
│ 📚 Catálogo    │ ⚙️ Controlo  │ 📊 Biofeedback               │
│ [📥 Importar]  │              │                              │
│ 🔍 Pesquisa... │ Freq: 528 Hz │ [   FFT GRAPH   ]            │
│                │ Amp:  5.0 V  │                              │
│ □ Protocolo 1  │ mA:   10 mA  │ RMS:  12.3 mV                │
│ □ Protocolo 2  │ Onda: Sine   │ Pico: 45.2 mV                │
│ □ Protocolo 3  │ Mod:  None   │ Freq: 528.1 Hz               │
│                │ Canal: 1     │ Imped: 1250 Ω                │
│ ─────────────  │              │                              │
│ 🔄 Fila Emissão│ [⏸️ Pausar]  │ ┌───────────────────┐        │
│ 1. 528 Hz      │ [⏹️ Parar]   │ │ IMPROVEMENT %     │        │
│ 2. 174 Hz      │              │ │      67.8%        │        │
│ 3. 7.83 Hz     │ 🔍 SCAN      │ └───────────────────┘        │
│                │ Limiar: 30%  │                              │
│                │ [▶️ Iniciar] │ ⏱️ 145 / 300 seg             │
│                │              │ [📄 Exportar Relatório]      │
└────────────────┴──────────────┴──────────────────────────────┘
```

### Checklist Pré-Sessão

Antes de clicar **"Iniciar Sessão"**, TODOS os itens devem estar marcados:

1. ✓ **Consentimento assinado**: PDF assinado pelo paciente
2. ✓ **Dispositivo pronto**: TiePie HS3 conectado e funcional
3. ✓ **Protocolo válido**: Pelo menos 1 item na fila de emissão
4. ✓ **Limites V/mA OK**: Amplitude e corrente dentro dos limites

Se qualquer item faltar → sistema bloqueia "Iniciar Sessão"

### Indicadores Tempo Real

**RMS (mV)**: Root Mean Square - valor eficaz do sinal
**Pico (mV)**: Amplitude máxima detectada
**Freq. Dominante (Hz)**: Frequência com maior energia no FFT
**Impedância (Ω)**: Resistência elétrica do circuito
**Improvement %**: 0% → 100% (objetivo: 100% = sessão completa)

---

## Excel Schema v1

### Estrutura do Ficheiro

**Nome**: `protocolos_terapia_v1.xlsx`
**Formato**: Excel 2007+ (.xlsx)

### Colunas Obrigatórias

| Coluna | Tipo | Validação | Exemplo |
|--------|------|-----------|---------|
| ExternalId | GUID | Único | 550e8400-e29b-41d4-a716-446655440000 |
| Nome | String(200) | Obrigatório | Dor Lombar Aguda |
| FrequenciaHz | Decimal | 0.01 - 2000000 | 528.0 |
| AmplitudeV | Decimal | 0 - 20 | 5.0 |
| LimiteCorrenteMa | Decimal | 0 - 50 | 10.0 |
| FormaOnda | Enum | Sine/Square/Triangle/Saw | Sine |
| Modulacao | Enum | AM/FM/Burst/None | None |
| DuracaoMin | Integer | 1 - 180 | 5 |
| Canal | Integer | 1 ou 2 | 1 |
| Versao | String(10) | - | 1.0 |

### Colunas Opcionais

- **Categoria**: String(100) - ex: "Dor", "Digestivo", "Emocional"
- **SequenciaJSON**: JSON com steps - ex: `[{"step":1, "freqHz":100, "durationSec":30}]`
- **Contraindicacoes**: String(1000) - ex: "Gravidez, pacemaker"
- **Notas**: String(2000) - observações adicionais

### Importação Idempotente

**Upsert baseado em ExternalId**:
- Se ExternalId existe → **UPDATE** (atualiza campos)
- Se ExternalId NÃO existe → **INSERT** (nova linha)

**Relatório pós-importação**:
```
✅ 45 protocolos importados com sucesso
⚠️ 3 warnings (frequências ajustadas para limites)
❌ 2 erros (GUIDs inválidos - linhas 12, 34)
```

**Pré-visualização**:
Antes de gravar na BD, sistema mostra:
- Total de linhas válidas
- Total de erros
- Preview das primeiras 10 linhas
- Botão: [✅ Confirmar] [❌ Cancelar]

### Exemplo de Protocolos

```excel
ExternalId                              Nome                FreqHz  AmpV  mA   Forma   Mod   Dur  Canal
550e8400-e29b-41d4-a716-446655440000    Dor Lombar Aguda    528.0   5.0   10   Sine    None  5    1
550e8400-e29b-41d4-a716-446655440001    Stress Crónico      7.83    3.0   5    Sine    None  10   1
550e8400-e29b-41d4-a716-446655440002    Inflamação Geral    174.0   4.0   8    Square  None  8    1
550e8400-e29b-41d4-a716-446655440003    Ansiedade           10.0    2.0   3    Sine    None  15   1
550e8400-e29b-41d4-a716-446655440004    Fadiga Crónica      40.0    6.0   12   Triangle None 10   1
```

---

## Segurança Clínica

### Limites Hard (Não Negociáveis)

```
Amplitude:        0 - 20V      (máximo absoluto)
Corrente:         0 - 50mA     (máximo absoluto)
Frequência:       0.01 Hz - 2 MHz
Duração/sessão:   1 - 180 min
```

### Pausa Automática

Sistema pausa emissão automaticamente se:

1. **Impedância fora de gama** (< 100Ω ou > 10kΩ)
   - Motivo: Eletrodos mal conectados ou curto-circuito
   - Ação: Verificar conexões e reiniciar

2. **Corrente excede limite** (> LimiteCorrenteMa)
   - Motivo: Resistência do paciente menor que esperado
   - Ação: Reduzir amplitude ou aumentar limite (com justificação)

3. **Temperatura elevada** (se sensor disponível)
   - Motivo: Aquecimento excessivo dos eletrodos
   - Ação: Pausar e aguardar arrefecimento

### Override Justificado

Para ultrapassar limites (só com razão clínica):

1. Clique no botão "Override" (só aparece após pausa automática)
2. Sistema exige justificação obrigatória (min 20 caracteres)
3. Justificação é registada na BD e no relatório
4. Responsabilidade do clínico

**Exemplo de justificação válida**:
> "Paciente com histórico de terapia bioenergética há 5 anos, sem reações adversas. Autorização verbal confirmada para amplitude 22V em sessão supervisionada."

---

## Hardware Suportado

### TiePie HS3 (Osciloscópio + AWG)

**Especificações Técnicas**:
- **AWG**: 2 canais independentes, ±12V, até 2 MHz
- **Osciloscópio**: 50 MS/s, 16-bit resolution
- **Impedância de entrada**: 1 MΩ || 25 pF
- **Formas de onda**: Sine, Square, Triangle, Sawtooth, DC, Noise, Arbitrary
- **Modulação**: AM, FM, Burst

**Conexão**:
- USB 3.0 (recomendado) ou USB 2.0
- Driver: [tiepie.com/downloads](https://www.tiepie.com/downloads)
- SDK: LibTiePie (C/C++ + .NET bindings)

**Configuração**:
1. Instalar driver TiePie
2. Conectar HS3 via USB
3. Verificar LED verde no dispositivo
4. BioDesk detecta automaticamente
5. Checkbox "Dispositivo pronto" fica verde ✅

### Hologram Generator / Alea I/II (TRNG)

**Objetivo**: Fonte de aleatoriedade quântica para modo "informacional"

**Status**:
- Alea I/II descontinuado (mas utilizável se já possuir)
- Sistema funciona SEM HG (usa CSPRNG determinístico)
- COM HG: ativa modo "CoRe-like" completo

**Diferença**:
- **Sem HG**: Reprodutível (mesma seed → mesmo scan)
- **Com HG**: Não reprodutível (aleatoriedade física)

No uso clínico: seed muda por sessão, logo não "fica sempre igual" mesmo sem HG

---

## Fluxos de Trabalho

### Fluxo 1: Scan Ressonante + Emissão Manual

```
1. Abrir ficha do paciente (Tab 1)
2. Navegar para Tab 7 (Terapias)
3. Verificar "👤 PACIENTE ATIVO" no header
4. Coluna 2 → Definir "Limiar de relevância" (ex: 30%)
5. Coluna 2 → Clicar "▶️ Iniciar Scan"
6. Aguardar scan (5-10 segundos)
7. Resultados aparecem ordenados por Value % (100% → 0%)
8. Selecionar checkboxes das frequências > 30%
9. Clicar "Adicionar à Fila"
10. Verificar Checklist pré-sessão
11. Clicar "▶️ Iniciar Sessão"
12. Acompanhar Improvement % em tempo real
13. Quando Improvement ≥ 100% → item completo
14. Ao final: "📄 Exportar Relatório"
```

### Fluxo 2: Protocolo Pré-Programado (Excel)

```
1. Preparar Excel com protocolos (ver Excel Schema v1)
2. Abrir ficha do paciente
3. Tab 7 → Coluna 1 → "📥 Importar Excel"
4. Selecionar ficheiro .xlsx
5. Sistema valida e mostra pré-visualização
6. Clicar "✅ Confirmar"
7. Protocolos aparecem em "Catálogo de Protocolos"
8. Pesquisar protocolo desejado (ex: "Dor Lombar")
9. Clicar checkbox ao lado do protocolo
10. Clicar "Adicionar à Fila"
11. Verificar Checklist pré-sessão
12. Clicar "▶️ Iniciar Sessão"
13. Sistema emite sequencialmente
14. Ao final: "📄 Exportar Relatório"
```

### Fluxo 3: Biofeedback Automático (com HG)

```
1. Conectar Hologram Generator (Alea)
2. Abrir ficha do paciente
3. Tab 7 → Sistema detecta HG automaticamente
4. Checkbox "Dispositivo pronto" fica verde
5. Coluna 2 → Modo "Biofeedback" ativa automaticamente
6. Verificar Checklist pré-sessão
7. Clicar "▶️ Iniciar Sessão"
8. Sistema faz scan + emissão imediata (client-specific)
9. Feedback em tempo real ajusta parâmetros
10. Sessão termina automaticamente após tempo definido
11. "📄 Exportar Relatório"
```

---

## Troubleshooting

### ❌ Erro: "Nenhum paciente selecionado"

**Causa**: Tentou usar Tab 7 sem abrir ficha do paciente
**Solução**: Dashboard → Selecionar paciente → Abrir Ficha

### ❌ Erro: "Dispositivo não está pronto"

**Causa**: TiePie HS3 não conectado ou driver não instalado
**Solução**:
1. Verificar cabo USB conectado
2. Verificar LED verde no HS3
3. Reinstalar driver TiePie se necessário
4. Reiniciar aplicação

### ❌ Erro: "Fila de emissão vazia"

**Causa**: Tentou iniciar sessão sem adicionar frequências/protocolos
**Solução**: Fazer scan ou selecionar protocolos primeiro

### ❌ Erro: "Amplitude fora dos limites"

**Causa**: Valor fora de 0-20V
**Solução**: Ajustar slider "Amplitude" para valor válido

### ⚠️ Warning: "Impedância fora de gama"

**Causa**: Eletrodos mal conectados ou pele seca
**Solução**:
1. Verificar conexão dos eletrodos
2. Limpar pele com álcool
3. Aplicar gel condutor
4. Pressionar eletrodos firmemente
5. Clicar "Retomar"

### ⚠️ Warning: "Improvement % não aumenta"

**Causa**: Frequência não ressonante ou sessão muito curta
**Solução**:
1. Aumentar duração da emissão
2. Testar frequência diferente
3. Verificar se paciente está relaxado
4. Considerar fatores ambientais (stress, cansaço)

---

## Referências

### Documentação Externa

- **Inergetix-CoRe Manual**: [Workflow oficial CoRe v5.0](https://core-system.com)
- **TiePie HS3**: [Especificações técnicas](https://www.tiepie.com/hs3)
- **Alea TRNG**: [Archived documentation](https://araneus.fi)

### Documentação Interna

- `EXCEL_PROTOCOLOS_TERAPIA_V1.md`: Schema Excel detalhado
- `Domain/Entities/`: Estrutura de dados
- `ViewModels/Abas/TerapiaBioenergeticaViewModel.cs`: Lógica de negócio

### Frequências de Referência

| Frequência | Nome | Aplicação |
|------------|------|-----------|
| 7.83 Hz | Ressonância Schumann | Stress, ansiedade, equilíbrio |
| 10 Hz | Alpha | Relaxamento, meditação |
| 40 Hz | Gamma | Fadiga, concentração |
| 174 Hz | Solfeggio | Analgésico, anti-inflamatório |
| 528 Hz | Solfeggio (DNA) | Reparação tecidual, cura |
| 639 Hz | Solfeggio | Relações, emocional |
| 741 Hz | Solfeggio | Desintoxicação, expressão |
| 852 Hz | Solfeggio | Intuição, despertar |

---

## Glossário

**AWG**: Arbitrary Waveform Generator - gerador de formas de onda arbitrárias
**FFT**: Fast Fourier Transform - análise espectral em tempo real
**RMS**: Root Mean Square - valor eficaz do sinal AC
**TRNG**: True Random Number Generator - gerador de números aleatórios físico
**CSPRNG**: Cryptographically Secure Pseudo-Random Number Generator
**Upsert**: UPDATE se existe, INSERT se não existe (operação idempotente)
**Value %**: Percentagem de ressonância inicial (100% = máxima)
**Improvement %**: Percentagem de evolução durante emissão (meta: 100%)

---

**Última atualização**: 2025-01-09
**Versão**: 1.0
**Autor**: BioDeskPro2 Development Team
