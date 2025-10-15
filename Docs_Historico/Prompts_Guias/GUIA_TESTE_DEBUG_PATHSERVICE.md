# 🧪 GUIA DE TESTE - PathService em Modo Debug

## 📅 Data: 8 de outubro de 2025

---

## ✅ O QUE ESPERAS VER AO EXECUTAR EM DEBUG (VS Code F5)

### 1️⃣ **Startup - Console Output** ⭐ CRÍTICO
Assim que a app iniciar, **DEVES VER** no **Output → Debug Console**:

```plaintext
=== PathService Diagnostics ===
Debug Mode: True
App Data Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2
Database Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db
Documentos Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Documentos
Pacientes Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Documentos\Pacientes
Prescricoes Path: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Documentos\Prescricoes
...
```

**✅ SINAL CORRETO**: `Debug Mode: True` + todos os paths apontam para a pasta do projeto
**❌ SINAL ERRADO**: `Debug Mode: False` (significa que Debugger.IsAttached falhou)

---

### 2️⃣ **Base de Dados - Ficheiro Atual**
- **Localização**: `C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db`
- **Conteúdo**: Os teus 10+ pacientes existentes
- **Comportamento Esperado**: App carrega NORMALMENTE, como sempre fez

**✅ SINAL CORRETO**: Dashboard mostra estatísticas dos pacientes (ex: "12 Pacientes Registados")
**❌ SINAL ERRADO**: Base de dados vazia ou erro "Cannot open database"

---

### 3️⃣ **Navegação - Testar Funcionalidades Existentes**

#### 3.1 Dashboard → Lista de Pacientes
1. Clicar no botão **"📋 Lista de Pacientes"**
2. Verificar que aparece a lista completa
3. **Novo**: Botão **"🗑️ Eliminar"** visível (apenas ativo se paciente selecionado)

#### 3.2 Ver Ficha de Paciente
1. Clicar em qualquer paciente da lista
2. Clicar **"Ver Ficha"**
3. **Novo**: Tab **"Consultas"** deve ter campo **"💊 TERAPIA ATUAL"** (fundo amarelo claro)

---

### 4️⃣ **Pastas de Documentos - Estrutura Criada**
Ao arrancar, o PathService deve criar automaticamente (se não existirem):

```plaintext
BioDeskPro2/
├── Documentos/
│   ├── Pacientes/
│   ├── Prescricoes/
│   ├── Consentimentos/
│   └── Templates/
├── Backups/
└── Logs/
```

**Como Verificar**:
1. Abrir explorador de ficheiros
2. Navegar para `C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2`
3. Confirmar que estas pastas existem

**✅ SINAL CORRETO**: Pastas criadas automaticamente
**❌ SINAL ERRADO**: Pastas não existem (PathService.EnsureDirectories() falhou)

---

### 5️⃣ **PDF Generation - POSSÍVEL FALHA** ⚠️
**ATENÇÃO**: Os serviços de PDF (prescrições, consentimentos) **AINDA NÃO** foram atualizados para usar PathService.

**Se tentares gerar PDF**:
- ✅ Pode funcionar (se ainda encontrar pastas antigas)
- ⚠️ Pode falhar com erro "Path not found" (esperado)

**Solução**: Após este teste, vamos atualizar os serviços de PDF (Task #3 da TODO list).

---

## 🎯 CHECKLIST DE VALIDAÇÃO

### ✅ TESTES OBRIGATÓRIOS

| # | Teste | Resultado Esperado | ✅/❌ |
|---|-------|-------------------|-------|
| 1 | App inicia sem erros | Janela abre normalmente | |
| 2 | Console mostra diagnostics | "Debug Mode: True" visível | |
| 3 | Database Path correto | Aponta para `biodesk.db` no projeto | |
| 4 | Dashboard carrega pacientes | Estatísticas mostram dados reais | |
| 5 | Lista Pacientes funciona | Botão "🗑️ Eliminar" visível | |
| 6 | Ficha Paciente abre | Campo "Terapia Atual" presente (amarelo) | |
| 7 | Pastas criadas automaticamente | Documentos/, Backups/, Logs/ existem | |
| 8 | Sem crashes ou exceções | Nenhum erro no console | |

---

## 🐛 POSSÍVEIS PROBLEMAS E SOLUÇÕES

### ⚠️ Problema 1: "Debug Mode: False" (raro)
**Sintoma**: Console mostra `Debug Mode: False` ao executar do VS Code
**Causa**: Debugger.IsAttached não detetado
**Solução Imediata**: Continuar testes normalmente (path vai para projeto mesmo assim)
**Nota**: Se isto acontecer, avisar para investigar

### ⚠️ Problema 2: PDF Generation Fails
**Sintoma**: Erro "Path not found" ao criar prescrição
**Causa Esperada**: PrescricaoPdfService ainda usa paths hardcoded ("../../../..")
**Solução**: Normal! Vamos corrigir na próxima fase (Task #3)

### ⚠️ Problema 3: Pastas não criadas
**Sintoma**: Documentos/, Backups/, Logs/ não aparecem no explorador
**Causa**: PathService.EnsureDirectories() não executou
**Solução**: Verificar exceções no console, ler mensagem de erro

### ⚠️ Problema 4: Base de Dados vazia
**Sintoma**: Dashboard mostra "0 Pacientes"
**Causa**: Database Path aponta para local errado
**Solução**: Verificar console diagnostics, confirmar path correto

---

## 📊 RESULTADOS ESPERADOS (RESUMO)

### ✅ SUCESSO TOTAL
```plaintext
- App inicia < 5 segundos
- Console mostra "Debug Mode: True"
- Dashboard com dados reais (10+ pacientes)
- Navegação funciona perfeitamente
- Campo "Terapia Atual" visível
- Botão "Eliminar" funcional
- Pastas Documentos/Backups/Logs criadas
- ZERO crashes/exceções
```

### ⚠️ SUCESSO PARCIAL (Aceitável)
```plaintext
- App inicia e funciona normalmente
- PDF generation falha (esperado)
- Console pode ter warnings (nullable, CA1063)
- Tudo o resto OK
```

### ❌ FALHA (Requer Correção Imediata)
```plaintext
- App não inicia / crash imediato
- Database não carrega (0 pacientes quando deveria ter 10+)
- Navegação quebrada
- "Debug Mode: False" E paths errados
- Exceções não capturadas
```

---

## 🚀 PRÓXIMOS PASSOS (Após Teste OK)

### Se Teste Sucesso ✅
1. **Continuar Task #3**: Atualizar PrescricaoPdfService, ConsentimentoPdfService, DeclaracaoSaudePdfService
2. Gerar PDF de prescrição e verificar que salva em `Documentos/Prescricoes/`
3. Marcar Task #4 como completa

### Se Teste Falha ❌
1. Copiar TODA a mensagem de erro do console
2. Verificar stack trace completa
3. Analisar logs se gerados
4. Corrigir antes de avançar

---

## 📝 NOTAS IMPORTANTES

### ⭐ Modo Debug vs Release
- **Debug** (agora): Usa pasta do projeto (`BioDeskPro2/`)
- **Release** (futuro): Usará `C:\ProgramData\BioDeskPro2\`
- **Transição**: Automática via `Debugger.IsAttached`

### 🔒 Dados Seguros
- Base de dados atual **NÃO É ALTERADA**
- PathService apenas **lê** (não move/deleta)
- Commits git estão todos salvos

### 🎯 Foco do Teste
- Verificar que **Debug mode funciona 100%**
- Confirmar que **nada quebrou** (navegação, BD, UI)
- Identificar se **PDF services precisam update urgente**

---

**Data de Criação**: 8 de outubro de 2025
**Próximo Milestone**: Task #3 - Update PDF Services
**Objetivo Final**: Preparar app para instalação multi-PC com licensing system
