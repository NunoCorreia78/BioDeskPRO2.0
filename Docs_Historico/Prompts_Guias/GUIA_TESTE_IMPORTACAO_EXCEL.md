# 🧪 Guia de Teste - Importação Excel (Idempotência)

**Objetivo**: Verificar que reimportar o mesmo ficheiro Excel NÃO cria duplicados na base de dados.

---

## 📋 Passo a Passo

### 1️⃣ Preparar Ficheiro Excel
Precisas de um ficheiro `FrequencyList.xls` com protocolos terapêuticos.

**Formato esperado** (colunas no Excel):
- **Coluna A**: Nome do protocolo (ex: "Artrite", "Dor Crónica", "Stress")
- **Coluna B em diante**: Frequências em Hz (ex: 10.00, 20.00, 30.00)

**Onde encontrar?**
- Se tens o CoRe 5.0 instalado: `C:\Program Files\Inergetix\CoRe\FrequencyList.xls`
- Ou cria um ficheiro de teste com 3-5 protocolos simples

---

### 2️⃣ Primeira Importação

1. **Clica em "Importar Excel"** (botão verde no canto superior direito)
2. **Seleciona o ficheiro** `FrequencyList.xls`
3. **Aguarda mensagem de sucesso** (pode demorar 5-10 segundos se tiver muitos protocolos)

**Resultado esperado**:
```
✅ Importação concluída com sucesso!
   X protocolos importados
```

---

### 3️⃣ Verificar Base de Dados (Primeira Vez)

#### Opção A: Via VS Code (SQLite Extension)
1. Instala extensão: `alexcvzz.vscode-sqlite` (se ainda não tens)
2. Abre Command Palette (`Ctrl+Shift+P`)
3. Escreve: `SQLite: Open Database`
4. Seleciona: `C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2\biodesk.db`
5. No painel "SQLITE EXPLORER", expande `biodesk.db`
6. Clica direito em `ProtocolosTerapeuticos` → **Show Table**

**Conta quantos registos existem** (ex: 150 protocolos)

#### Opção B: Via DB Browser for SQLite
1. Abre [DB Browser for SQLite](https://sqlitebrowser.org/) (se instalado)
2. `File → Open Database` → seleciona `biodesk.db`
3. Aba `Browse Data` → Tabela `ProtocolosTerapeuticos`
4. **Conta quantos registos existem**

---

### 4️⃣ Segunda Importação (TESTE DE IDEMPOTÊNCIA)

1. **Clica novamente em "Importar Excel"**
2. **Seleciona O MESMO ficheiro** `FrequencyList.xls`
3. **Aguarda mensagem de sucesso**

**Resultado esperado**:
```
✅ Importação concluída com sucesso!
   X protocolos importados (mesmo número que antes)
```

---

### 5️⃣ Verificar Idempotência

**Repete verificação da base de dados**:
- Abre `ProtocolosTerapeuticos` novamente
- **Conta os registos**

**✅ SUCESSO**: Número de registos **MANTÉM-SE IGUAL** (ex: 150 → 150)
**❌ FALHA**: Número duplicou (ex: 150 → 300) ← Idempotência não funciona

---

### 6️⃣ Verificar Log de Importações

**Na base de dados, tabela `ImportacoesExcelLog`**:

Deves ver **2 registos**:

| NomeFicheiro | ImportadoEm | TotalLinhas | LinhasOk | LinhasErros | Sucesso |
|--------------|-------------|-------------|----------|-------------|---------|
| FrequencyList.xls | 2025-10-13 14:50:00 | 150 | 150 | 0 | true |
| FrequencyList.xls | 2025-10-13 14:52:00 | 150 | 150 | 0 | true |

**Confirma**:
- ✅ 2 entradas (1 por cada importação)
- ✅ Ambas com `Sucesso = true`
- ✅ Timestamps diferentes (minutos de diferença)

---

## 🎯 Resultados Esperados

### ✅ Teste PASSOU (Idempotência funciona)
- Primeira importação: 150 protocolos criados
- Segunda importação: 150 protocolos (mesmos IDs atualizados via Upsert)
- **Total na BD**: 150 registos (sem duplicados!)
- **Log**: 2 entradas em `ImportacoesExcelLog`

### ❌ Teste FALHOU (Idempotência NÃO funciona)
- Primeira importação: 150 protocolos
- Segunda importação: +150 protocolos novos
- **Total na BD**: 300 registos (DUPLICADOS!)
- **Log**: 2 entradas, mas protocolos duplicados

---

## 🔍 Verificação Extra: ExternalId Estável

**Query SQL para verificar** (se quiseres ser rigoroso):

```sql
-- Ver se há ExternalIds duplicados (NÃO DEVE HAVER!)
SELECT ExternalId, COUNT(*) as Total
FROM ProtocolosTerapeuticos
GROUP BY ExternalId
HAVING COUNT(*) > 1;
```

**Resultado esperado**: 0 linhas (nenhum ExternalId duplicado)

---

## 📊 Query Útil: Ver Protocolos Importados

```sql
-- Ver todos os protocolos com suas frequências
SELECT
    Nome,
    Categoria,
    ExternalId,
    LEFT(FrequenciasJson, 50) as Frequencias_Preview
FROM ProtocolosTerapeuticos
ORDER BY Nome;
```

---

## 🐛 Se Encontrares Problemas

### Problema 1: Botão "Importar Excel" não faz nada
**Causa**: Possivelmente erro no ViewModel ou binding.
**Solução**: Verifica console do VS Code (pode ter exceções no log).

### Problema 2: Erro "Ficheiro não encontrado"
**Causa**: ExcelImportService não encontra o ficheiro.
**Solução**: Certifica-te que selecionas um `.xls` válido (não `.xlsx`).

### Problema 3: Duplicados criados
**Causa**: SHA256 hash não está a funcionar corretamente.
**Solução**: Informa-me e eu corrijo o `GerarHashEstavel`.

---

## ✅ Checklist Final

Após testar, confirma comigo:

- [ ] Importação funcionou (1ª vez)
- [ ] Contei registos na BD (1ª contagem)
- [ ] Reimportei o mesmo ficheiro (2ª vez)
- [ ] Contei registos novamente (2ª contagem)
- [ ] Número de registos manteve-se igual ✅ ou duplicou ❌
- [ ] Tabela `ImportacoesExcelLog` tem 2 entradas
- [ ] Query de ExternalIds duplicados retorna 0 linhas

---

## 🎓 Explicação Técnica (Opcional)

**Como funciona a idempotência?**

1. **SHA256 Hash**: Cada protocolo gera um hash baseado em `Nome|Categoria|Frequências`
   ```csharp
   // Exemplo:
   Input: "Artrite|Geral|10.00;20.00;30.00"
   SHA256: a3f5b2...
   GUID: a3f5b2e1-c4d6-7890-abcd-ef1234567890
   ```

2. **ExternalId Determinístico**: Mesmos dados → Mesmo GUID sempre

3. **Upsert**:
   - Se `ExternalId` existe → **UPDATE** (atualiza frequências/nome)
   - Se `ExternalId` não existe → **INSERT** (cria novo)

**Resultado**: Reimportar = atualizar, não duplicar! 🎯

---

**Nota**: Se tudo funcionar, marca ✅ e avançamos para Sprint 2!
