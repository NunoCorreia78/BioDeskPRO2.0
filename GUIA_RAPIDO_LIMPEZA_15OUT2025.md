# 📋 GUIA RÁPIDO: LIMPEZA DO WORKSPACE - BioDeskPro2
**Data**: 15 de outubro de 2025

---

## 🎯 OBJETIVO

Limpar workspace mantendo:
- ✅ **TODOS os backups de outubro/2025** (11 ficheiros)
- ✅ Documentação ativa e recente
- ❌ Remover ficheiros debug/temp/obsoletos
- 📁 Organizar documentação histórica

---

## ⚡ EXECUÇÃO RÁPIDA (2 comandos)

```powershell
# 1. Remover ficheiros obsoletos
.\LimparFicheirosObsoletos_15OUT2025.ps1

# 2. Organizar documentação histórica
.\OrganizarDocumentacaoHistorica_15OUT2025.ps1
```

**Tempo estimado**: 30 segundos
**Reversível**: Sim (via Git)

---

## 📊 O QUE SERÁ FEITO

### Script 1: LimparFicheirosObsoletos
**Remove ~20 ficheiros temporários:**
- 🔴 4 ficheiros `.txt` de debug (DEBUG_DOCUMENTOS, CRASH_LOG, seed_dummy, etc.)
- 🔴 2 scripts `.csx` temporários (TesteLastActiveTab, VerificarSeedBancoCore)
- 🔴 2 JSON duplicados na raiz (iris_drt.json, iris_esq.json)
- 🔴 3 ficheiros `.backup` no código (DeclaracaoSaudeUserControl, BioDesk.Services.csproj, etc.)
- 🔴 5 scripts `.ps1` temporários (tmp, TesteLastActiveTab, TestarImportacaoExcel, etc.)
- ✅ **Verifica e preserva** todos os backups de outubro

### Script 2: OrganizarDocumentacaoHistorica
**Move ~80 ficheiros .md para `Docs_Historico/`:**
- 📁 `Sessoes_SET_OUT_2025/` - 9 ficheiros (resumos sessões)
- 📁 `Correcoes_OUT_2025/` - 10 ficheiros (correções antigas)
- 📁 `Auditorias_OUT_2025/` - 9 ficheiros (auditorias)
- 📁 `Implementacoes_OUT_2025/` - 10 ficheiros (implementações)
- 📁 `Sprints_OUT_2025/` - 11 ficheiros (relatórios sprint)
- 📁 `Prompts_Guias/` - 10 ficheiros (guias/prompts)
- 📁 `Planos_Resumos/` - 12 ficheiros (planos antigos)
- 📁 `Especificacoes/` - 9 ficheiros (specs técnicas)

**Mantém na raiz (17 ficheiros ativos):**
- ✅ README.md
- ✅ CHECKLIST_*.md (4 ficheiros)
- ✅ GESTAO_BASE_DADOS.md
- ✅ REGRAS_*.md (2 ficheiros)
- ✅ SISTEMA_*.md (3 ficheiros)
- ✅ PLANO_DESENVOLVIMENTO_RESTANTE.md
- ✅ O_QUE_FALTA_FAZER_SIMPLES.md
- ✅ WORKSPACE_LIMPO_TRANSFERENCIA.md
- ✅ CORRECAO_CRITICA_CONCORRENCIA_15OUT2025.md ⭐
- ✅ IMPLEMENTACAO_BANCO_CORE_COMPLETA_15OUT2025.md ⭐
- ✅ AUDITORIA_FICHEIROS_OBSOLETOS_15OUT2025.md ⭐

---

## ✅ VERIFICAÇÃO PÓS-LIMPEZA

```powershell
# 1. Build limpo
dotnet clean && dotnet build

# 2. Testes
dotnet test

# 3. Executar aplicação
dotnet run --project src/BioDesk.App

# 4. Verificar estrutura
Get-ChildItem Docs_Historico -Directory
Get-ChildItem Backups
```

**Resultado esperado**:
- Build: ✅ Succeeded
- Testes: ✅ 150/150 passed
- App: ✅ MainWindow abre
- Backups: ✅ 11 ficheiros outubro preservados

---

## 🔄 REVERTER (se necessário)

```powershell
# Reverter ficheiros removidos
git checkout -- <ficheiro>

# Reverter ficheiros movidos
git reset --hard HEAD

# OU reverter commit
git revert <commit-hash>
```

---

## 📈 RESULTADO FINAL

### Antes
```
BioDeskPro2/
├── 150+ ficheiros .md (raiz)
├── 20+ ficheiros diversos
├── Navegação confusa
└── Dificuldade encontrar docs ativas
```

### Depois
```
BioDeskPro2/
├── 17 ficheiros .md ATIVOS ⭐
├── Docs_Historico/ (80+ docs organizados)
│   ├── Sessoes_SET_OUT_2025/
│   ├── Correcoes_OUT_2025/
│   ├── Auditorias_OUT_2025/
│   ├── Implementacoes_OUT_2025/
│   ├── Sprints_OUT_2025/
│   ├── Prompts_Guias/
│   ├── Planos_Resumos/
│   └── Especificacoes/
├── Backups/ (11 ficheiros OUT/2025) ✅
└── Navegação LIMPA e CLARA 🎯
```

**Ganhos:**
- ✅ Workspace limpo e organizado
- ✅ Documentação ativa facilmente acessível
- ✅ Histórico preservado e estruturado
- ✅ Backups de outubro 100% intactos
- ✅ ~8 MB espaço libertado (ficheiros temp)

---

## 📝 NOTAS IMPORTANTES

1. **Git tracked**: Ficheiros .md estão no Git. Scripts usam `Move-Item` (Git detecta automaticamente).
2. **Backups OUT/2025**: Scripts verificam datas, **NÃO TOCAM** em nada de outubro.
3. **Segurança**: Ambos os scripts têm `$ErrorActionPreference = "Stop"` e contador de erros.
4. **Logs**: Scripts mostram progresso colorido e resumo final detalhado.

---

## 🚀 EXECUTAR AGORA

```powershell
# Limpeza completa (2 comandos)
.\LimparFicheirosObsoletos_15OUT2025.ps1
.\OrganizarDocumentacaoHistorica_15OUT2025.ps1

# Verificar
dotnet build && dotnet test
```

**Pronto para limpar o workspace!** 🧹✨
