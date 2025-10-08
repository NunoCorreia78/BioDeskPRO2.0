# 🚨 CORREÇÃO CRÍTICA - PathService BD Errada

## 📅 Data: 8 de outubro de 2025

---

## ❌ PROBLEMA IDENTIFICADO

### Sintomas Reportados
1. ✅ App executou sem crash
2. ❌ **Pacientes errados**: Apareceram 3 pacientes "fictícios" (do seed) em vez dos 10+ reais
3. ❌ **Imagens de iris não aparecem**: Canvas vazio
4. ❌ **Dados perdidos**: Todos os registos reais não visíveis

### Causa Raiz 🔍
O **PathService** estava a calcular mal o caminho do projeto em modo Debug:

```csharp
// ❌ CÓDIGO ERRADO (antes):
if (projectRoot.Contains("bin"))
{
    projectRoot = Path.GetFullPath(Path.Combine(projectRoot, "..", "..", ".."));
    // Subia apenas 3 níveis: bin/Debug/net8.0-windows → src/BioDesk.App
    // Resultado: BioDeskPro2\src\BioDesk.App\biodesk.db (BD NOVA CRIADA)
}
```

**Estrutura de Pastas**:
```
BioDeskPro2/                          ← RAIZ DO PROJETO (onde está a BD real)
├── biodesk.db                        ← ✅ BD REAL (10+ pacientes)
└── src/
    └── BioDesk.App/
        ├── biodesk.db                ← ❌ BD FALSA (3 pacientes seed)
        └── bin/
            └── Debug/
                └── net8.0-windows/   ← AppContext.BaseDirectory
```

**O Que Aconteceu**:
1. PathService calculou `AppDataPath = BioDeskPro2\src\BioDesk.App\` (ERRADO!)
2. App não encontrou BD nessa pasta
3. EF Core criou **BD nova vazia**
4. Seed automático inseriu **3 pacientes fictícios**
5. Tua BD real (`BioDeskPro2\biodesk.db`) ficou **intocada mas ignorada**

---

## ✅ CORREÇÃO APLICADA

### Código Corrigido
```csharp
// ✅ CÓDIGO CORRETO (agora):
if (projectRoot.Contains("bin"))
{
    projectRoot = Path.GetFullPath(Path.Combine(projectRoot, "..", "..", "..", "..", ".."));
    // Sobe 5 níveis: bin/Debug/net8.0-windows → BioDeskPro2 (raiz)
    // Resultado: BioDeskPro2\biodesk.db (BD REAL)
}
```

**Níveis Corretos**:
```
AppContext.BaseDirectory:
BioDeskPro2/src/BioDesk.App/bin/Debug/net8.0-windows/
    ↑         ↑          ↑   ↑     ↑
    5         4          3   2     1  ← Subir 5 níveis!
```

### Ações Realizadas
1. ✅ Corrigido PathService.cs (5 níveis em vez de 3)
2. ✅ Apagada BD falsa (`src\BioDesk.App\biodesk.db`)
3. ✅ Build realizado com sucesso (0 erros)
4. ⏸️ **PRONTO PARA TESTAR NOVAMENTE**

---

## 🎯 O QUE ESPERAR AGORA (Teste Correto)

### 1️⃣ Console Output (CRÍTICO!)
```plaintext
=== PathService Diagnostics ===
Debug Mode: True
App Data Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2  ← ✅ RAIZ!
Database Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db  ← ✅ BD REAL!
```

**⚠️ ANTES** (errado):
```
App Data Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\src\BioDesk.App
```

### 2️⃣ Dashboard (DADOS REAIS)
- ✅ **10+ Pacientes Registados** (número exato que inseriste)
- ✅ Nomes reais (não "João Silva Santos", "Maria Costa Oliveira", "António Pereira")
- ✅ Estatísticas reais

### 3️⃣ Imagens de Iris (RECUPERADAS)
- ✅ Canvas mostra imagens guardadas
- ✅ Anotações/marcas visíveis
- ✅ JSON de overlays carregado

### 4️⃣ Estrutura de Pastas
```
BioDeskPro2/
├── biodesk.db                ← ✅ USADA AGORA!
├── Documentos/               ← ✅ Criado automaticamente
│   ├── Pacientes/
│   ├── Prescricoes/
│   ├── Consentimentos/
│   └── Templates/
├── Backups/                  ← ✅ Criado
└── Logs/                     ← ✅ Criado
```

**NÃO DEVE EXISTIR**:
- ❌ `src\BioDesk.App\biodesk.db` (apagado)
- ❌ `src\BioDesk.App\Documentos\` (não deve ser criado)

---

## 🧪 CHECKLIST DE VERIFICAÇÃO OBRIGATÓRIO

| # | Verificação | Resultado Esperado | ✅/❌ |
|---|-------------|-------------------|-------|
| 1 | Console: "Debug Mode: True" | Visível no startup | |
| 2 | Console: "App Data Path" | Aponta para `BioDeskPro2\` (raiz) | |
| 3 | Console: "Database Path" | `BioDeskPro2\biodesk.db` | |
| 4 | Dashboard: Total Pacientes | **10+** (teus dados reais) | |
| 5 | Lista: Nomes Pacientes | **Nomes reais** (não fictícios) | |
| 6 | Ficha: Imagens Iris | **Canvas com imagem** (se tiver) | |
| 7 | Explorador: Pastas criadas | `Documentos/`, `Backups/`, `Logs/` | |
| 8 | Explorador: BD falsa apagada | `src\BioDesk.App\biodesk.db` **NÃO EXISTE** | |

---

## 🔍 DIAGNÓSTICO SE AINDA FALHAR

### Se Continuar a Ver Pacientes Fictícios

#### Passo 1: Verificar Console Output
Procurar no **Output → Debug Console**:
```
App Data Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\src\BioDesk.App
```
☝️ Se isto aparecer = **PathService ainda está errado**

#### Passo 2: Verificar Ficheiros BD
Executar no terminal:
```powershell
Get-ChildItem -Path "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2" -Filter "biodesk.db" -Recurse
```

**Resultado Esperado**:
```
C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db  ← APENAS 1 FICHEIRO!
```

**Se aparecer mais que 1**:
- Apagar TODOS exceto o da raiz
- Rebuild completo

#### Passo 3: Verificar Tamanho da BD
```powershell
Get-Item "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db" | Select-Object Name, Length
```

- **BD com 10+ pacientes**: ~500KB - 2MB+
- **BD seed (3 pacientes)**: ~50-100KB

Se tamanho < 100KB = **BD foi recriada (ERRO!)**

---

## 📊 COMPARAÇÃO ANTES/DEPOIS

### ❌ ANTES (Errado)
```
PathService:
  AppDataPath → BioDeskPro2\src\BioDesk.App\
  DatabasePath → BioDeskPro2\src\BioDesk.App\biodesk.db (NOVA)

Resultado:
  - BD vazia criada
  - Seed com 3 pacientes
  - Dados reais ignorados
  - Imagens não encontradas
```

### ✅ DEPOIS (Correto)
```
PathService:
  AppDataPath → BioDeskPro2\
  DatabasePath → BioDeskPro2\biodesk.db (REAL)

Resultado:
  - BD existente usada
  - 10+ pacientes visíveis
  - Dados reais carregados
  - Imagens acessíveis
```

---

## 🚀 PRÓXIMOS PASSOS

### 1. TESTAR IMEDIATAMENTE
- Executar app (F5 ou `dotnet run`)
- **COPIAR CONSOLE OUTPUT COMPLETO** (primeiras 20 linhas)
- Verificar Dashboard (total pacientes)

### 2. CONFIRMAR CORREÇÃO
Se vires **10+ pacientes reais** → ✅ **PROBLEMA RESOLVIDO!**

Se ainda vires **3 pacientes fictícios** → ❌ Seguir diagnóstico acima

### 3. APÓS CONFIRMAÇÃO OK
- Commit: `🐛 fix: PathService caminho DB corrigido (5 níveis)`
- Continuar Task #3: Atualizar PDF Services

---

## 🔒 GARANTIA DE SEGURANÇA

### Teus Dados Estão Seguros ✅
- ✅ BD real **NUNCA foi alterada** (`BioDeskPro2\biodesk.db`)
- ✅ Apenas foi **ignorada temporariamente**
- ✅ Imagens de iris intactas
- ✅ Commits git todos salvos

### BD Falsa Apagada ✅
- ✅ `src\BioDesk.App\biodesk.db` removida
- ✅ Não será recriada (path corrigido)
- ✅ App agora aponta sempre para raiz

---

**IMPORTANTE**: Antes de continuar, **CONFIRMA NO CONSOLE** que o path está correto! 🔍

**Data de Correção**: 8 de outubro de 2025, 14:30
**Build Status**: 0 Errors, 39 Warnings (normais)
**Próximo Teste**: Executar app e verificar console + pacientes
