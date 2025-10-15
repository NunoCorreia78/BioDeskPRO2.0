# 📥 EXEMPLO DE EXCEL - Protocolos de Frequências

**Ficheiro**: Template para importar no sub-separador Programas  
**Formato**: Excel (.xlsx ou .xls)  
**Local para colar caminho**: Campo "Caminho do Ficheiro Excel"

---

## 📋 Estrutura do Excel (Copy-Paste para Excel)

### Folha 1 (Nome não importa, apenas primeira folha é lida)

```
Nome_Programa	Hz	Duty	Segundos	Notas
Rife Cancer Basic	666.0	50	180	Frequência primária Rife
Rife Cancer Basic	690.0	50	180	Harmónica 2
Rife Cancer Basic	727.0	50	180	Harmónica 3
Rife Cancer Basic	728.0	50	180	Frequência base
Rife Cancer Basic	880.0	50	180	Frequência complementar
Clark Parasites	20.0	33	120	Frequência muito baixa
Clark Parasites	60.0	33	120	Harmónica baixa
Clark Parasites	95.0	33	120	Frequência base Clark
Clark Parasites	125.0	33	120	Harmónica média
Clark Parasites	434.0	33	180	Frequência principal
Clark Parasites	800.0	33	120	Frequência alta
Hulda Liver Detox	728.0	50	240	Fase 1 - Desintoxicação
Hulda Liver Detox	880.0	50	180	Fase 2 - Regeneração
Hulda Liver Detox	10000.0	50	120	Fase 3 - Alta frequência
Schumann Resonance	7.83	50	300	Ressonância Schumann base
Schumann Resonance	14.1	50	180	2ª harmónica Schumann
Schumann Resonance	20.3	50	180	3ª harmónica Schumann
Solfeggio 528 Hz	528.0	50	240	Frequência de reparação DNA
Solfeggio 432 Hz	432.0	50	240	Frequência universal
Chakra Base	256.0	50	180	Lá (A) - Chakra raiz
Chakra Sacral	288.0	50	180	Ré (D) - Chakra sacral
Chakra Plexo Solar	320.0	50	180	Mi (E) - Plexo solar
Chakra Cardíaco	341.3	50	180	Fá (F) - Coração
Chakra Laríngeo	384.0	50	180	Sol (G) - Garganta
Chakra Terceiro Olho	426.7	50	180	Lá (A) - Terceiro olho
Chakra Coronário	480.0	50	180	Si (B) - Coronário
```

---

## 🎯 Como Usar Este Template

### Opção 1: Criar Excel Manualmente
1. Abrir Microsoft Excel (ou LibreOffice Calc, Google Sheets)
2. Criar nova folha
3. **Primeira linha** (header obrigatório):
   ```
   Nome_Programa | Hz | Duty | Segundos | Notas
   ```
4. Preencher linhas seguintes com dados (ver exemplo acima)
5. Guardar como: `Protocolos_Terapeuticos.xlsx`

### Opção 2: Copy-Paste Direto
1. Copiar tabela acima (desde "Nome_Programa" até última linha)
2. Abrir Excel novo
3. Colar na célula A1
4. Excel reconhece automaticamente separação por tabs
5. Guardar como: `Protocolos_Terapeuticos.xlsx`

---

## 📍 Onde Guardar o Ficheiro

### Localização Recomendada:
```
C:\ProgramData\BioDeskPro2\Templates\Frequencias\Protocolos_Terapeuticos.xlsx
```

### Passos para Criar Pasta:
1. Abrir Explorador de Ficheiros
2. Navegar para `C:\ProgramData\`
3. Criar pasta `BioDeskPro2` (se não existir)
4. Dentro, criar pasta `Templates`
5. Dentro, criar pasta `Frequencias`
6. Guardar Excel nesta pasta

---

## 🔧 Como Importar no BioDeskPro2

### Passo-a-Passo Completo:

```
1. Abrir BioDeskPro2
   │
   ▼
2. Selecionar paciente na ficha
   │
   ▼
3. Clicar separador 🌿 Terapias
   │
   ▼
4. Clicar sub-separador 📝 Programas (2º)
   │
   ▼
5. No campo "Caminho do Ficheiro Excel":
   │
   ├─► COLAR: C:\ProgramData\BioDeskPro2\Templates\Frequencias\Protocolos_Terapeuticos.xlsx
   │
   ▼
6. Clicar botão [📥 Importar Excel]
   │
   ▼
7. Aguardar mensagem "Importação concluída"
   │
   ▼
8. Ver lista de programas à esquerda:
   ├─ Rife Cancer Basic (5 passos)
   ├─ Clark Parasites (6 passos)
   ├─ Hulda Liver Detox (3 passos)
   ├─ Schumann Resonance (3 passos)
   ├─ Solfeggio 528 Hz (1 passo)
   ├─ Solfeggio 432 Hz (1 passo)
   └─ Chakra Base...Coronário (7 programas)
```

---

## ✅ Validação do Excel

### Checklist Antes de Importar:

- [ ] **Primeira linha é header** com nomes exatos: Nome_Programa, Hz, Duty, Segundos, Notas
- [ ] **Coluna Hz**: Valores numéricos (ex: 666.0, 728.0)
- [ ] **Coluna Duty**: Valores 1-100 (percentagem)
- [ ] **Coluna Segundos**: Valores inteiros (ex: 180, 240)
- [ ] **Coluna Notas**: Texto livre (pode estar vazia)
- [ ] **Sem linhas vazias** entre dados
- [ ] **Extensão .xlsx ou .xls** (não .csv)
- [ ] **Apenas primeira folha** será lida

### Erros Comuns:

❌ **Erro**: Coluna "Hz" com texto (ex: "666 Hz")  
✅ **Correto**: Apenas número (ex: 666.0)

❌ **Erro**: Header em português (ex: "Frequência" em vez de "Hz")  
✅ **Correto**: Nomes exatos em inglês: Hz, Duty, Segundos

❌ **Erro**: Duty com símbolo % (ex: "50%")  
✅ **Correto**: Apenas número (ex: 50)

❌ **Erro**: Caminho com barra invertida única (ex: C:\Pasta\Ficheiro.xlsx)  
✅ **Correto**: Copy-paste direto do Explorador funciona

---

## 📊 Resultado Esperado Após Importação

### Lista de Programas (esquerda):
```
┌────────────────────────────┐
│ 📋 Programas Importados    │
├────────────────────────────┤
│ Rife Cancer Basic          │ ← Clique para ver passos
│ Clark Parasites            │
│ Hulda Liver Detox          │
│ Schumann Resonance         │
│ Solfeggio 528 Hz           │
│ Solfeggio 432 Hz           │
│ Chakra Base                │
│ Chakra Sacral              │
│ Chakra Plexo Solar         │
│ Chakra Cardíaco            │
│ Chakra Laríngeo            │
│ Chakra Terceiro Olho       │
│ Chakra Coronário           │
└────────────────────────────┘
```

### Passos do Programa (direita, ao clicar "Rife Cancer Basic"):
```
┌────────────────────────────────────────────────────────────┐
│ ⚡ Passos do Programa Selecionado                          │
├────────────────────────────────────────────────────────────┤
│ [➕ Adicionar à Lista Ativa]                               │
├───┬─────────┬──────┬─────┬───────────────────────────────┤
│ # │ Hz      │ Duty │ Seg │ Notas                         │
├───┼─────────┼──────┼─────┼───────────────────────────────┤
│ 1 │ 666.0   │ 50%  │ 180 │ Frequência primária Rife      │
│ 2 │ 690.0   │ 50%  │ 180 │ Harmónica 2                   │
│ 3 │ 727.0   │ 50%  │ 180 │ Harmónica 3                   │
│ 4 │ 728.0   │ 50%  │ 180 │ Frequência base               │
│ 5 │ 880.0   │ 50%  │ 180 │ Frequência complementar       │
└───┴─────────┴──────┴─────┴───────────────────────────────┘
```

---

## 🎯 Exemplo de Sessão Completa

### Workflow: Aplicar Protocolo Rife

```
1. Importar Excel (passos acima) ✅
   │
   ▼
2. Na lista, clicar "Rife Cancer Basic"
   │
   ▼
3. Ver 5 passos à direita
   │
   ▼
4. Clicar [➕ Adicionar à Lista Ativa]
   │
   ▼
5. Ir para sub-separador ⚡ Biofeedback
   │
   ▼
6. Verificar Lista Ativa tem 5 itens ✅
   │
   ▼
7. Configurar:
   ├─ Modo: Remoto (Informação)
   ├─ Âncora: João Silva 1980-05-15
   ├─ Tempo/Item: 180 segundos (já vem do Excel!)
   └─ Ciclos: 3
   │
   ▼
8. Clicar [▶️ Iniciar]
   │
   ▼
9. Aguardar: 5 itens × 180s × 3 ciclos = 45 minutos
   │
   ▼
10. Sessão concluída ✅
```

---

## 📚 Protocolos Incluídos no Template

### 1. Rife Cancer Basic (5 passos)
**Origem**: Royal Raymond Rife (1930s)  
**Uso**: Protocolo base para investigação

### 2. Clark Parasites (6 passos)
**Origem**: Dra. Hulda Clark  
**Uso**: Protocolo anti-parasitário

### 3. Hulda Liver Detox (3 passos)
**Origem**: Dra. Hulda Clark  
**Uso**: Desintoxicação hepática

### 4. Schumann Resonance (3 passos)
**Origem**: Ressonância natural da Terra  
**Uso**: Harmonização com frequências planetárias

### 5. Solfeggio (2 programas)
**Origem**: Frequências antigas de cura  
**Uso**: 528 Hz (reparação DNA), 432 Hz (universal)

### 6. Chakras (7 programas)
**Origem**: Sistema de chakras tradicional  
**Uso**: Equilíbrio energético por chakra

---

## 🔗 Links Relacionados

- **Documentação Completa**: `GUIA_COMPLETO_TERAPIAS_CORE.md`
- **Referência Rápida**: `REFERENCIA_RAPIDA_TERAPIAS.md`
- **Diagramas Visuais**: `DIAGRAMA_VISUAL_TERAPIAS.md`

---

## ⚠️ Notas Importantes

### Sobre os Dados:
- ✅ Todos os protocolos são **exemplos educativos**
- ⚠️ Frequências baseadas em literatura histórica (Rife, Clark)
- 🔬 **Não substitui diagnóstico médico profissional**
- 📖 Use apenas para fins de investigação pessoal

### Sobre o Formato:
- ✅ Excel aceita até ~10,000 linhas
- ✅ Prático: 50-200 protocolos (100-2000 passos)
- ✅ Linhas vazias são ignoradas
- ✅ Protocolos com mesmo nome são atualizados (não duplicados)

---

**Criado**: 15 de Outubro de 2025  
**Tipo**: Template de exemplo para importação  
**Status**: Pronto para uso imediato
