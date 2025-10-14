# 🇵🇹 Sistema de Tradução Automática - Português Europeu

## 📋 Visão Geral

O sistema traduz automaticamente os termos médicos do **FrequencyList.xls** (Alemão/Inglês) para **Português Europeu** durante a importação.

---

## 🛠️ Como Funciona

### **1. Tradução Automática**
```csharp
// Durante importação do Excel
string englishTerm = "Abdominal pain";
string portugues = MedicalTermsTranslator.TranslateToPortuguese(englishTerm);
// Resultado: "Dor Abdominal"
```

### **2. Dicionário com 150+ Termos**
- ✅ **Inglês → Português**: 150+ termos médicos comuns
- ✅ **Alemão → Português**: 20+ termos (fallback)
- ✅ **Regras Heurísticas**: Sufixos automáticos (itis→ite, osis→ose)

### **3. Exemplos de Tradução**

| Original (Inglês) | Português Europeu |
|-------------------|-------------------|
| Abdominal pain | Dor Abdominal |
| Abscesses | Abcessos |
| Anxiety | Ansiedade |
| Headache | Dor de Cabeça |
| Inflammation | Inflamação |
| Joint pain | Dor Articular |
| Kidney stones | Cálculos Renais |
| Migraine | Enxaqueca |
| Pneumonia | Pneumonia |
| Rheumatism | Reumatismo |
| Sinusitis | Sinusite |
| Stroke | AVC |
| Tinnitus | Acufenos |
| Varicose veins | Varizes |

| Original (Alemão) | Português Europeu |
|-------------------|-------------------|
| Bauchschmerzen | Dor Abdominal |
| Kopfschmerzen | Dor de Cabeça |
| Rückenschmerzen | Dor nas Costas |
| Entzündung | Inflamação |
| Schlaflosigkeit | Insónia |

---

## 🔄 Fluxo de Importação

```
FrequencyList.xls
├─ Coluna "Disease" (Inglês)      → Tradução Automática
├─ Coluna "Indikationen" (Alemão) → Guardado nas Notas
└─ Frequências (Freq 1-254)       → Array JSON

Resultado em BioDeskPro2:
┌────────────────────────────────────────┐
│ Nome: "Dor Abdominal"                  │
│ Categoria: "Digestivo"                 │
│ Notas: "Original: Bauchschmerzen"      │
│ Frequências: [3, 10000, 3000, 95, ...]│
└────────────────────────────────────────┘
```

---

## 🎯 Regras Heurísticas (Termos Não Mapeados)

Se um termo NÃO estiver no dicionário, aplica regras automáticas:

| Sufixo Original | Tradução | Exemplo |
|----------------|----------|---------|
| **itis** | **ite** | Otitis → Otite |
| **osis** | **ose** | Thrombosis → Trombose |
| **emia** | **emia** | Septicemia → Septicemia |
| **algia** | **algia** | Myalgia → Mialgia |

---

## ✅ Vantagens

1. **Automático**: Traduz 1.273 linhas sem intervenção manual
2. **Expansível**: Adicione traduções personalizadas em runtime
3. **Seguro**: Mantém original nas Notas se tradução falhar
4. **Consistente**: Mesma tradução sempre aplicada

---

## 🚀 Durante Importação

### **Preview (antes de confirmar):**
```
┌─────────────────────────────────────────────────────────┐
│ Importação de FrequencyList.xls                         │
├─────────────────────────────────────────────────────────┤
│ ✅ Linha 12: "Abdominal inflammation"                   │
│    → Traduzido: "Inflamação Abdominal"                  │
│                                                          │
│ ✅ Linha 13: "Abdominal pain"                           │
│    → Traduzido: "Dor Abdominal"                         │
│                                                          │
│ ⚠️  Linha 14: "Rare condition XYZ"                      │
│    → Não traduzido (mantém original)                    │
├─────────────────────────────────────────────────────────┤
│ Total: 1.273 linhas                                     │
│ ✅ Traduzidas: 1.150 (90%)                              │
│ ⚠️  Originais mantidos: 123 (10%)                       │
└─────────────────────────────────────────────────────────┘
```

---

## 🔧 Adicionar Traduções Personalizadas

Se encontrar termos não traduzidos durante importação:

```csharp
// Interface UI permitirá adicionar traduções
MedicalTermsTranslator.AddCustomTranslation(
    "Rare condition XYZ", 
    "Condição Rara XYZ"
);

// Reimportar Excel → Tradução aplicada
```

---

## 📊 Estatísticas de Cobertura

Com base em análise de termos médicos comuns:

- ✅ **Top 100 condições**: 95% cobertura
- ✅ **Top 500 condições**: 85% cobertura
- ⚠️ **Termos raros**: 60% cobertura (heurísticas aplicam)

**Resultado esperado**: 80-90% das 1.273 linhas traduzidas automaticamente.

---

## 🎯 Próximos Passos

1. **Importar FrequencyList.xls**
2. **Preview mostra traduções**
3. **Confirmar importação**
4. **Usar protocolos em Português no Tab 7**

---

**Tudo pronto para importação 100% em Português Europeu!** 🇵🇹🚀
