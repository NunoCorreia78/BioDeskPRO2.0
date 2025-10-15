# 🌿 REFERÊNCIA RÁPIDA - Separador Terapias

**Para**: Utilizadores que precisam de consulta rápida  
**Versão**: Simplificada e direta

---

## 🎯 Resposta Direta: ONDE COLAR O EXCEL?

### No Sub-separador "Programas"

1. **Campo**: "Caminho do Ficheiro Excel" (caixa de texto)
2. **Formato**: Caminho completo do ficheiro
3. **Exemplo**: `C:\ProgramData\BioDeskPro2\Templates\Frequencias\MeuProtocolo.xlsx`
4. **Ação**: Clicar botão "Importar Excel"

### Formato do Excel

| Nome_Programa | Hz    | Duty | Segundos | Notas          |
|---------------|-------|------|----------|----------------|
| Rife Cancer   | 666.0 | 50   | 180      | Frequência 1   |
| Rife Cancer   | 690.0 | 50   | 180      | Frequência 2   |

**Colunas obrigatórias**: Nome_Programa, Hz, Duty, Segundos

---

## 📊 5 Sub-separadores Explicados

### 1️⃣ AVALIAÇÃO
**O que faz**: Testa 156 itens (Florais Bach, Chakras, Meridianos) para ver quais ressoam com o paciente

**Campos principais**:
- **Fonte da Semente**: Como identificar paciente → Manter "Nome+DataNasc"
- **Gerador RNG**: Algoritmo aleatório → Manter "XorShift128+"
- **Salt da Sessão**: Texto aleatório → Regenerar cada nova sessão
- **Iterações**: Precisão → Manter 50000

**Botões**:
- **Executar Scan**: Inicia teste (~10 segundos)
- **Adicionar à Lista Ativa**: Envia itens selecionados para aplicação

---

### 2️⃣ PROGRAMAS
**O que faz**: Importa protocolos de frequências de ficheiro Excel

**Campos principais**:
- **Caminho Excel**: **AQUI COLAS O CAMINHO DO FICHEIRO** ⬅️
- **Pesquisa**: Filtrar protocolos por nome

**Botões**:
- **Importar Excel**: Lê e guarda protocolos na base de dados
- **Atualizar**: Recarrega lista de protocolos
- **Adicionar à Lista Ativa**: Envia protocolo selecionado para aplicação

---

### 3️⃣ RESSONANTES
**O que faz**: Varre frequências numéricas (ex: 10 Hz até 2000 Hz) para encontrar ressonâncias

**Campos principais**:
- **Start Hz**: Frequência inicial → Ex: 10
- **Stop Hz**: Frequência final → Ex: 2000
- **Step Hz**: Saltos → Ex: 1 (testa 10, 11, 12...)
- **Dwell Ms**: Tempo por frequência → Ex: 150

**Botões**:
- **Executar Sweep**: Inicia varredura (~5 minutos para 1990 pontos)
- **Adicionar Selecionado**: Envia frequência escolhida para aplicação

---

### 4️⃣ BIOFEEDBACK
**O que faz**: Aplica os itens da Lista Ativa no paciente

**Modo Local** (Energia física - requer equipamento):
- **Forma de Onda**: Sine/Square/Pulse
- **Frequência Hz**: Frequência base
- **Duty %**: Percentagem do ciclo "ligado"
- **Vpp V**: Tensão
- **Limite Corrente mA**: Segurança

**Modo Remoto** (Informação - SEM equipamento):
- **Ancora**: Identificador do paciente (Nome + Data Nasc)
- **Hash**: SHA256 ou BLAKE3
- **Modulação**: AM-Ruído / FM-Ruído / PSK
- **Ciclos**: Quantas vezes repetir lista
- **Tempo por Item s**: Duração de cada item

**Botões**:
- **Iniciar**: Começa aplicação
- **Pausar**: Pausa (pode retomar)
- **Parar**: Para completamente
- **Emergência**: STOP imediato

---

### 5️⃣ HISTÓRICO
**O que faz**: Mostra sessões anteriores do paciente

**Status**: 🚧 Em desenvolvimento

---

## ⚡ Fluxos de Trabalho Rápidos

### Workflow 1: Avaliação Básica CoRe
```
Avaliação → Executar Scan → Selecionar Top 10 → Adicionar à Lista 
→ Biofeedback (Remoto) → Preencher Ancora → Iniciar
```

### Workflow 2: Aplicar Protocolo Excel
```
Programas → Colar caminho Excel → Importar → Selecionar protocolo 
→ Adicionar à Lista → Biofeedback → Iniciar
```

### Workflow 3: Descobrir Frequências
```
Ressonantes → Configurar 10-2000 Hz → Executar Sweep → Ver picos altos 
→ Adicionar selecionados → Biofeedback → Iniciar
```

---

## 🔑 Valores Recomendados (Copy-Paste Ready)

### Avaliação
- Fonte: `Nome+DataNasc`
- RNG: `XorShift128+`
- Iterações: `50000`

### Ressonantes (Range Standard)
- Start: `10` Hz
- Stop: `2000` Hz
- Step: `1` Hz
- Dwell: `150` ms

### Biofeedback Local (Seguro)
- Forma: `Square`
- Duty: `50` %
- Vpp: `3.0` V
- Corrente: `0.8` mA
- Compliance: `12.0` V

### Biofeedback Remoto (Standard)
- Hash: `SHA256`
- Modulação: `AM-Ruído`
- Ciclos: `3`
- Tempo/Item: `20` s
- On: `800` ms
- Off: `200` ms
- Drift Check: `✅` (marcado)

---

## ❓ FAQ Rápido

**Qual sub-separador usar para importar Excel?**
→ **Programas** (2º separador)

**Como identificar paciente em modo Remoto?**
→ Campo **Ancora** no Biofeedback → Ex: "João Silva 1980-05-15"

**Quanto tempo demora um Scan?**
→ ~10 segundos (com 50000 iterações)

**Quanto tempo demora aplicação Biofeedback?**
→ Nº itens × Tempo/item × Ciclos  
→ Ex: 10 itens × 20s × 3 ciclos = 10 minutos

**Posso aplicar sem fazer Scan primeiro?**
→ Sim! Importa protocolo Excel e aplica diretamente

**Excel pode ter quantas linhas?**
→ Até ~10.000 (prático: 50-200 protocolos)

---

## 📋 Checklist de Sessão Típica

- [ ] Paciente selecionado na ficha
- [ ] Separador Terapias aberto
- [ ] **Avaliação**: Executar Scan → Aguardar 10s
- [ ] **Avaliação**: Selecionar Top 10 itens
- [ ] **Avaliação**: Adicionar à Lista Ativa
- [ ] **Biofeedback**: Verificar Lista tem 10 itens
- [ ] **Biofeedback**: Modo = Remoto
- [ ] **Biofeedback**: Ancora = "Nome DataNasc"
- [ ] **Biofeedback**: Tempo/Item = 20s, Ciclos = 3
- [ ] **Biofeedback**: Iniciar → Aguardar ~10 min
- [ ] **Histórico**: Registar sessão (futuro)

---

## 🎯 Conceitos-Chave em 1 Linha

| Termo | Significado |
|-------|-------------|
| **Value %** | Quão bem o item ressoa com o paciente (0-100%) |
| **Improvement %** | Melhoria conseguida após aplicar item (0-100%) |
| **RNG** | Gerador de números aleatórios para medir ressonância |
| **Scanning** | Testar múltiplos itens com RNG |
| **Lista Ativa** | Itens selecionados para aplicar no paciente |
| **Ancora** | Identificador único do paciente (Nome+DataNasc) |
| **Sweep** | Varrer frequências numéricas automaticamente |
| **Duty %** | Percentagem do tempo que onda está "ligada" |
| **Dwell** | Tempo que fica em cada frequência durante sweep |

---

## 📞 Apoio

- **Documentação Completa**: Ver ficheiro `GUIA_COMPLETO_TERAPIAS_CORE.md`
- **Checklist Integridade**: Ver ficheiro `CHECKLIST_INTEGRACAO_CORE.md`
- **Banco Core (156 itens)**: Ver ficheiro `IMPLEMENTACAO_BANCO_CORE_COMPLETA_15OUT2025.md`

---

**Criado**: 15 de Outubro de 2025  
**Tipo**: Referência rápida para consulta diária
