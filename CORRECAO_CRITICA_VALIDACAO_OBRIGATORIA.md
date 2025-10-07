# 🚨 CORREÇÃO CRÍTICA - VALIDAÇÃO OBRIGATÓRIA

**Data**: 08 de Outubro de 2025
**Problema Reportado**: "Guardei esta ficha sem alerta nenhum..."

---

## ❌ PROBLEMAS IDENTIFICADOS

### **Problema 1: Data mostra "01/01/0001" em vez de vazio**
- **Causa**: `DateTime.MinValue` não é `null`
- **Impacto**: Campo mostra data estranha em vez de ficar vazio
- **Screenshot fornecido**: Data nascimento mostrando "01/01/0001"

### **Problema 2: Validação NÃO bloqueia gravação**
- **Causa**: Método `GuardarRascunho()` não valida antes de gravar
- **Impacto**: Ficha com dados inválidos é guardada sem alertas
- **Exemplo**: Nome "ss" (2 caracteres), NIF "12345677" (inválido) guardados sem erro

---

## ✅ CORREÇÕES IMPLEMENTADAS

### **Correção 1: Data de Nascimento Nullable**

#### **Ficheiro: `Paciente.cs` (Domain)**
```csharp
// ANTES ❌
[Required]
public DateTime DataNascimento { get; set; }

public int Idade => DateTime.Now.Year - DataNascimento.Year - ...

// DEPOIS ✅
public DateTime? DataNascimento { get; set; } // Nullable

public int? Idade => DataNascimento.HasValue
    ? DateTime.Now.Year - DataNascimento.Value.Year - ...
    : null;
```

**Resultado**: Campo fica **verdadeiramente vazio** até utilizador preencher.

---

### **Correção 2: Validação Obrigatória no Guardar**

#### **Ficheiro: `FichaPacienteViewModel.cs`**
```csharp
[RelayCommand]
private async Task GuardarRascunho()
{
    // ⭐ NOVO: VALIDAÇÃO OBRIGATÓRIA
    var erros = new List<string>();

    // 1. Nome Completo (mínimo 3 caracteres)
    if (string.IsNullOrWhiteSpace(PacienteAtual.NomeCompleto) ||
        PacienteAtual.NomeCompleto.Trim().Length < 3)
        erros.Add("• Nome Completo (mínimo 3 caracteres)");

    // 2. Data Nascimento (obrigatório)
    if (!PacienteAtual.DataNascimento.HasValue ||
        PacienteAtual.DataNascimento == DateTime.MinValue)
        erros.Add("• Data de Nascimento");

    // 3. NIF válido (se houver erro de validação)
    if (!string.IsNullOrEmpty(ErroNIF))
        erros.Add("• NIF inválido");

    // 4. Telefone válido (se houver erro de validação)
    if (!string.IsNullOrEmpty(ErroTelefonePrincipal))
        erros.Add("• Telefone inválido");

    // 5. Email válido (se houver erro de validação)
    if (!string.IsNullOrEmpty(ErroEmail))
        erros.Add("• Email inválido");

    // ⚠️ SE HÁ ERROS → BLOQUEAR GRAVAÇÃO
    if (erros.Any())
    {
        ErrorMessage = "❌ Corrija os seguintes campos obrigatórios:\n"
                     + string.Join("\n", erros);
        _logger.LogWarning("⚠️ Tentativa de guardar com {Count} erros", erros.Count);
        return; // ⛔ NÃO GUARDA
    }

    // ✅ SE PASSOU → GRAVAR
    IsLoading = true;
    // ... (código de gravação existente)
}
```

**Resultado**: **Impossível guardar** com dados inválidos!

---

## 📋 REGRAS DE VALIDAÇÃO OBRIGATÓRIAS

### ✅ **Campos Obrigatórios (Bloqueiam Guardar)**
1. **Nome Completo** → Mínimo 3 caracteres
2. **Data de Nascimento** → Deve ser preenchida

### ⚠️ **Campos com Validação Condicional**
3. **NIF** → Se preenchido, deve ser válido (9 dígitos + checkdigit)
4. **Telefone** → Se preenchido, deve ser válido (9 dígitos, inicia com 2 ou 9)
5. **Email** → Se preenchido, deve ser válido (formato padrão)

---

## 🎬 COMPORTAMENTO ESPERADO AGORA

### **Cenário de Teste**
1. Novo paciente
2. Nome: "ss" (2 caracteres)
3. Data: (vazia)
4. NIF: "12345677" (8 dígitos)
5. Clicar "Guardar Rascunho"

### **Resultado ANTES** ❌
- Grava sem alertas
- Dados inválidos na base de dados
- Utilizador não percebe o erro

### **Resultado AGORA** ✅
```
❌ Corrija os seguintes campos obrigatórios:
• Nome Completo (mínimo 3 caracteres)
• Data de Nascimento
• NIF inválido
```
- **NÃO GRAVA**
- Mensagem de erro clara
- Utilizador corrige antes de continuar

---

## 📦 FICHEIROS ALTERADOS

### **1. Domain Layer**
- `src/BioDesk.Domain/Entities/Paciente.cs`
  - `DataNascimento`: `DateTime` → `DateTime?`
  - `Idade`: `int` → `int?` com null check

### **2. ViewModel Layer**
- `src/BioDesk.ViewModels/FichaPacienteViewModel.cs`
  - Adicionado `using System.Collections.Generic;`
  - Método `GuardarRascunho()`: Validação obrigatória antes de gravar
  - Inicialização: `DataNascimento = null` (em vez de `DateTime.MinValue`)

---

## 🧪 TESTES MANUAIS NECESSÁRIOS

### **Teste 1: Campo Vazio**
✅ Verificar que data de nascimento aparece **vazio** (não "01/01/0001")

### **Teste 2: Validação Bloqueia**
✅ Tentar guardar ficha incompleta → deve mostrar erro e NÃO gravar

### **Teste 3: Validação Permite**
✅ Preencher todos os campos corretamente → deve guardar com sucesso

---

## ⚠️ IMPACTO NA BASE DE DADOS

### **Migração Necessária?**
**SIM** - Campo `DataNascimento` mudou de `NOT NULL` para `NULL`

### **Comando SQLite**
```sql
-- BACKUP ANTES DE EXECUTAR!
-- Verificar estrutura atual
PRAGMA table_info(Pacientes);

-- Se DataNascimento for NOT NULL, executar:
-- (SQLite não suporta ALTER COLUMN, precisa recrear tabela)
```

**⚠️ NOTA**: Se a base de dados já tiver pacientes com `DataNascimento`, migração é complexa. Considerar:
1. Manter campo obrigatório no C# mas nullable no DB
2. OU criar migration manual para recrear tabela

---

## 📝 DOCUMENTAÇÃO ATUALIZADA

### **Documentos Relacionados**
- `RESUMO_SESSAO_VALIDACOES_TEMPO_REAL.md` - Sessão anterior
- `CHECKLIST_TESTE_VALIDACOES.md` - Testes manuais

### **Próximos Passos**
1. ✅ **Testar aplicação** com as correções
2. ✅ **Verificar mensagens de erro** aparecem corretamente
3. ⏳ **Verificar base de dados** se aceita `NULL` em DataNascimento
4. ⏳ **Criar migration** se necessário

---

## 🎯 RESUMO EXECUTIVO

### **O que estava errado?**
- Data mostrava "01/01/0001" em vez de vazio
- Validações não bloqueavam gravação
- Dados inválidos eram guardados sem alerta

### **O que foi corrigido?**
- Data nullable (fica vazia até preenchimento)
- Validação obrigatória antes de guardar
- Mensagens de erro claras com lista de campos

### **Como testar?**
1. Novo paciente
2. Deixar campos vazios/inválidos
3. Tentar guardar
4. **Deve bloquear** com mensagem de erro

---

**FIM DO DOCUMENTO** 🎯
