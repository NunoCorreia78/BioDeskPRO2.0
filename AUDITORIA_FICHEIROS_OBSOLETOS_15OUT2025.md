# 🗑️ AUDITORIA DE FICHEIROS OBSOLETOS - BioDeskPro2
**Data**: 15 de outubro de 2025
**Critério**: Preservar APENAS backups de outubro/2025, remover todo o resto obsoleto

---

## 📊 RESUMO EXECUTIVO

| Categoria | Ficheiros | Espaço Estimado | Ação |
|-----------|-----------|-----------------|------|
| 🔴 Debug/Temp | ~15 | ~2 MB | **REMOVER** |
| 🔴 Documentação Antiga | ~80 | ~5 MB | **MOVER → Docs_Historico/** |
| 🔴 Scripts Temporários | ~8 | ~500 KB | **REMOVER** |
| 🔴 Backups Código | ~3 | ~100 KB | **REMOVER** |
| 🔴 JSON Duplicados | 2 | ~200 KB | **REMOVER** |
| 🟢 Backups OUT/2025 | 11 | ~50 MB | **MANTER** ✅ |

**Total a Limpar**: ~100 ficheiros | ~8 MB (sem contar Docs)

---

## 🔴 CATEGORIA 1: FICHEIROS DEBUG/TEMP (REMOVER IMEDIATAMENTE)

### 📄 Ficheiros .txt de Debug
```
❌ DEBUG_DOCUMENTOS.txt                     # Log de debug antigo
❌ CRASH_LOG_DISPATCHER.txt                 # Crash já resolvido (15/out)
❌ seed_dummy.txt                            # Dados de teste obsoletos
❌ Logs/DISPATCHER_EXCEPTION.txt            # Exception já corrigida
```
**Razão**: Logs temporários de erros já corrigidos. Não são usados em runtime.

### 📄 Scripts .csx (C# Script)
```
❌ TesteLastActiveTab.csx                   # Teste temporário de persistência abas
❌ VerificarSeedBancoCore.csx               # Script de verificação seed (já migrado para .ps1)
```
**Razão**: Scripts C# temporários criados para debug. Funcionalidade já está em código permanente.

### 📄 JSON na Raiz (Duplicados)
```
❌ iris_drt.json                            # DUPLICADO de src/BioDesk.App/Resources/IridologyMaps/
❌ iris_esq.json                            # DUPLICADO de src/BioDesk.App/Resources/IridologyMaps/
```
**Razão**: Mapas de iridologia já existem em `Resources/IridologyMaps/`. Estes são resíduos de desenvolvimento.

### 📄 Ficheiros .backup no Código-Fonte
```
❌ src/BioDesk.App/Views/Abas/DeclaracaoSaudeUserControl.xaml.cs.backup
❌ src/BioDesk.Services/BioDesk.Services.csproj.backup
❌ src/BioDesk.Services/Excel/ExcelImportService_ORIGINAL_BUG.txt
```
**Razão**: Backups manuais de código já corrigido e funcional. Git já tem histórico completo.

---

## 🔴 CATEGORIA 2: SCRIPTS TEMPORÁRIOS .ps1 (REMOVER)

### Scripts de Debug/Teste na Raiz
```
❌ tmp.ps1                                  # Script temporário genérico
❌ TesteLastActiveTab.ps1                   # Teste de persistência abas (funcionalidade já implementada)
❌ TestarImportacaoExcel.ps1                # Teste de importação (já tem testes xUnit)
❌ SeedItemBancoCore.ps1                    # Seed manual (já obsoleto após IMPLEMENTACAO_BANCO_CORE_COMPLETA)
❌ VerificarSeedBancoCore.ps1               # Verificação manual (funcionalidade em Admin)
```
**Razão**: Scripts PowerShell criados para testes pontuais. Funcionalidades já estão em código permanente ou testes xUnit.

### Scripts Organizados (MANTER)
```
✅ backup.ps1                               # Script de backup manual (MANTER)
✅ LimparWorkspaceCompleto.ps1              # Script de limpeza (MANTER)
✅ Scripts/LimparWorkspace.ps1              # Script de limpeza organizado (MANTER)
✅ Scripts/ConfigurarEmail.ps1              # Configuração email (MANTER)
✅ Debug_Scripts/*.ps1                      # Scripts organizados de debug (MANTER)
```

---

## 🔴 CATEGORIA 3: DOCUMENTAÇÃO ANTIGA (MOVER → Docs_Historico/)

### 📚 Sessões Antigas (Setembro/Outubro - Semanas 1-2)
```
📁 Docs_Historico/Sessoes_SET_OUT_2025/
   ↳ RESUMO_SESSAO_01OUT2025.md             # Sessão 01/out
   ↳ RESUMO_SESSAO_04OUT2025.md             # Sessão 04/out
   ↳ RESUMO_SESSAO_05OUT2025.md             # Sessão 05/out
   ↳ RESUMO_SESSAO_06OUT2025.md             # Sessão 06/out
   ↳ RESUMO_SESSAO_07OUT2025.md             # Sessão 07/out
   ↳ RESUMO_SESSAO_09OUT2025.md             # Sessão 09/out
   ↳ RESUMO_SESSAO_10OUT2025.md             # Sessão 10/out
   ↳ RESUMO_SESSAO_12OUT2025.md             # Sessão 12/out
   ↳ REFACTORING_SESSAO_03OUT2025.md        # Refactoring 03/out
```
**Razão**: Histórico de sessões antigas. Importante para contexto, mas não para trabalho diário.

### 📚 Correções Antigas (07-12 Outubro)
```
📁 Docs_Historico/Correcoes_OUT_2025/
   ↳ CORRECOES_FINAIS_SESSAO_07OUT2025.md
   ↳ CORRECOES_SESSAO_07OUT2025_PARTE2.md
   ↳ CORRECOES_UX_COMPLETAS.md
   ↳ CORRECAO_STATICRESOURCE_EXCEPTION.md
   ↳ CORRECAO_PATHSERVICE_BD_ERRADA.md
   ↳ CORRECAO_CRITICA_VALIDACAO_OBRIGATORIA.md
   ↳ DIAGNOSTICO_PROBLEMA_EMAIL_07OUT2025.md
   ↳ SOLUCAO_COMPLETA_EMAIL_07OUT2025.md
   ↳ SOLUCAO_CROP_QUADRADO_IRIS_07OUT2025.md
   ↳ OTIMIZACAO_CANVAS_IRIS_07OUT2025.md
```

### 📚 Auditorias Antigas (07-09 Outubro)
```
📁 Docs_Historico/Auditorias_OUT_2025/
   ↳ AUDITORIA_WORKSPACE_E_PLANO_TEMPLATES_07OUT2025.md
   ↳ RESUMO_AUDITORIA_TEMPLATES_07OUT2025.md
   ↳ AUDITORIA_STATICRESOURCES_CRITICA_09OUT2025.md
   ↳ AUDITORIA_COMMANDPARAMETER.md
   ↳ AUDITORIA_IMAGENS_IRIS_CANVAS.md
   ↳ AUDITORIA_BINDINGS_COMPLETA.md
   ↳ AUDITORIA_OTIMIZACAO_COMPLETA.md
   ↳ AUDITORIA_LIMPEZA_WORKSPACE.md
   ↳ ANALISE_OTIMIZACAO_CANVAS_IRIS.md
```

### 📚 Implementações Antigas (07-14 Outubro)
```
📁 Docs_Historico/Implementacoes_OUT_2025/
   ↳ IMPLEMENTACAO_CONFIGURACOES_08OUT2025.md
   ↳ IMPLEMENTACAO_BIOFEEDBACK_TIEPIE.md
   ↳ FASE2_IRISDIAGNOSTICO_COMPLETA.md
   ↳ FASE3_IRISDIAGNOSTICO_COMPLETA.md
   ↳ FASE4_TIEPIE_DUMMY_COMPLETO_12OUT2025.md
   ↳ INVESTIGACAO_TERAPIA_QUANTICA_12OUT2025.md
   ↳ LIMPEZA_CODIGO_MORTO_12OUT2025.md
   ↳ NOVO_EXCEL_IMPORT_SERVICE_EXCELDATAREADER.md
   ↳ SESSAO_TERAPIAS_FASE1_COMPLETA_12OUT2025.md
   ↳ FLUENTVALIDATION_IMPLEMENTACAO_14OUT2025.md
```

### 📚 Relatórios de Sprint (12-14 Outubro)
```
📁 Docs_Historico/Sprints_OUT_2025/
   ↳ RELATORIO_SPRINT1_COMPLETO_13OUT2025.md
   ↳ RELATORIO_SPRINT2_COMPLETO_12OUT2025.md
   ↳ RELATORIO_SPRINT2_PROGRESSO_INTERMEDIO_13OUT2025.md
   ↳ RELATORIO_TAREFAS_PENDENTES_12OUT2025.md
   ↳ TAREFAS_PENDENTES_ATUALIZADAS_12OUT2025.md
   ↳ TAREFAS_PENDENTES_SPRINTS_TERAPIAS_14OUT2025.md
   ↳ RELATORIO_GAPS_TERAPIAS_CODEX_13OUT2025.md
   ↳ SESSAO_14OUT2025_EVOLUCOES.md
   ↳ RELATORIO_MUDANCAS_14OUT2025.md
   ↳ ANALISE_UI_PENDENTE_14OUT2025.md
   ↳ AUDITORIA_BACKUP_RESTORE_14OUT2025.md
```

### 📚 Guias/Prompts (Mover)
```
📁 Docs_Historico/Prompts_Guias/
   ↳ PROMPT_AGENTE_CODIFICACAO_TAREFAS_RESTANTES.md
   ↳ PROMPT_AGENTE_SEED_DATA_CORE_COMPLETO.md
   ↳ PROMPT_CONTINUAR_SPRINT2_14OUT2025.md
   ↳ PROMPT_NOVO_CHAT_IMPLEMENTACAO.md
   ↳ GUIA_INSTALACAO_FERRAMENTAS.md
   ↳ GUIA_SIGNATURE_CANVAS.md
   ↳ GUIA_TESTE_DEBUG_PATHSERVICE.md
   ↳ GUIA_TESTE_IMPORTACAO_EXCEL.md
   ↳ INSTRUCOES_LIMPEZA.md
   ↳ SETUP_NOVO_PC.md
```

### 📚 Planos/Resumos Antigos
```
📁 Docs_Historico/Planos_Resumos/
   ↳ PLANO_IMPLEMENTACAO_TERAPIAS_COMPLETO.md
   ↳ PLANO_IMPLEMENTACAO_CORE_INFORMACIONAL_14OUT2025.md
   ↳ PROXIMOS_PASSOS_BANCO_CORE.md
   ↳ RESUMO_FICHEIROS_CORE_COMPLETO.md
   ↳ RESUMO_PASTAS_DOCUMENTAIS.md
   ↳ RESUMO_SESSAO_TERAPIAS_BIOENERGETICAS_12OUT2025.md
   ↳ RESUMO_SESSAO_VALIDACOES_TEMPO_REAL.md
   ↳ RESUMO_UX_MAPA_MELHORADO.md
   ↳ ORGANIZACAO_SCRIPTS_DEBUG.md
   ↳ SCRIPT_LIMPEZA_CACHE.md
   ↳ SEED_DATA_CORE_INFORMACIONAL.md
   ↳ RELATORIO_DIFICULDADES_SEED_15OUT2025.md
```

### 📚 Especificações Técnicas Antigas
```
📁 Docs_Historico/Especificacoes/
   ↳ ESPECIFICACAO_TERAPIAS_BIOENERGETICAS_TAB7.md
   ↳ CONFIGURACAO_PDF_PRESCRICAO.md
   ↳ PADROES_QUESTPDF.md
   ↳ SOLUCAO_ASSINATURAS_PDF_DEFINITIVA.md
   ↳ SOLUCOES_SQLITE3.md
   ↳ TRADUCAO_AUTOMATICA_PT.md
   ↳ TODO_IRISDIAGNOSTICO_E_OTIMIZACAO.md
   ↳ TESTE_MANUAL_PERSISTENCIA_ABAS.md
   ↳ TESTE_MANUAL_REAL_TIEPIE_12OUT2025.md
```

---

## 🟢 CATEGORIA 4: DOCUMENTAÇÃO ATIVA (MANTER NA RAIZ)

### 📚 Documentação Crítica Atual
```
✅ README.md                                 # Documentação principal projeto
✅ CHECKLIST_ANTI_ERRO_UI.md                 # Regras críticas UI
✅ CHECKLIST_AUDITORIA_COMPLETA.md           # Checklist auditorias
✅ CHECKLIST_INTEGRACAO_CORE.md              # Integração Banco Core
✅ CHECKLIST_TESTE_VALIDACOES.md             # Testes validações
✅ GESTAO_BASE_DADOS.md                      # Gestão BD SQLite
✅ REGRAS_CONSULTAS.md                       # Regras de negócio consultas
✅ REGRAS_CRITICAS_BD.md                     # ⚠️ CRÍTICO: Regras PathService
✅ SISTEMA_CONFIGURACOES.md                  # Sistema de configurações
✅ SISTEMA_PASTAS_DOCUMENTAIS.md             # Sistema de pastas
✅ SISTEMA_100_COMPLETO.md                   # Visão geral 100% completo
✅ PLANO_DESENVOLVIMENTO_RESTANTE.md         # Roadmap futuro
✅ O_QUE_FALTA_FAZER_SIMPLES.md              # TODO list simplificada
✅ WORKSPACE_LIMPO_TRANSFERENCIA.md          # Guia transferência projeto
```

### 📚 Documentação Recente (15 Outubro)
```
✅ CORRECAO_CRITICA_CONCORRENCIA_15OUT2025.md   # Correção DbContext (HOJE)
✅ IMPLEMENTACAO_BANCO_CORE_COMPLETA_15OUT2025.md  # Banco Core (HOJE)
✅ AUDITORIA_FICHEIROS_OBSOLETOS_15OUT2025.md   # Este ficheiro
```

---

## 🟢 CATEGORIA 5: BACKUPS OUTUBRO 2025 (MANTER TODOS)

### 📦 Backups da BD (Outubro)
```
✅ Backups/BioDeskBackup_20251014_222145.zip   # 14/out 22:21
✅ Backups/BioDeskBackup_20251014_222447.zip   # 14/out 22:24
✅ Backups/BioDeskBackup_20251014_225850.zip   # 14/out 22:58
✅ Backups/BioDeskBackup_20251015_131451.zip   # 15/out 13:14 ⭐ ANTES SEED CORE
✅ Backups/BioDeskBackup_20251015_132505.zip   # 15/out 13:25
✅ Backups/BioDeskBackup_20251015_143127.zip   # 15/out 14:31
✅ Backups/BioDeskBackup_20251015_165635.zip   # 15/out 16:56
✅ Backups/BioDeskBackup_20251015_172416.zip   # 15/out 17:24
✅ Backups/BioDeskBackup_20251015_173025.zip   # 15/out 17:30
✅ Backups/BioDeskBackup_20251015_173201.zip   # 15/out 17:32 ⭐ ÚLTIMO
✅ Backups/Backup_SPRINT2_COMPLETO_20251012_195027/  # 12/out Sprint 2
✅ Backups/MANUAL_ANTES_MIGRATION_CORE_20251015_112025.db  # 15/out PRÉ-CORE ⚠️
```
**Total**: 11 backups | ~50 MB
**Razão**: Preservar conforme solicitação do utilizador. Backups críticos de outubro.

---

## 📋 AÇÕES RECOMENDADAS

### ✅ PASSO 1: Executar Script de Limpeza Automática
```powershell
.\LimparFicheirosObsoletos_15OUT2025.ps1
```
**O que faz**:
- Remove ficheiros .txt de debug
- Remove scripts .csx temporários
- Remove JSON duplicados na raiz
- Remove ficheiros .backup no código
- Remove scripts .ps1 temporários
- **NÃO TOCA** em backups de outubro
- **NÃO TOCA** em documentação (move para Docs_Historico/)

### ✅ PASSO 2: Organizar Documentação Antiga
```powershell
.\OrganizarDocumentacaoHistorica_15OUT2025.ps1
```
**O que faz**:
- Cria estrutura `Docs_Historico/` com subpastas
- Move ~80 ficheiros .md antigos (SET-OUT semanas 1-2)
- Mantém na raiz apenas documentação ativa
- Preserva cronologia e contexto

### ✅ PASSO 3: Verificar Integridade
```powershell
# Build limpo
dotnet clean && dotnet build

# Testes
dotnet test

# Executar aplicação
dotnet run --project src/BioDesk.App
```

---

## 📊 RESULTADO ESPERADO

### Antes da Limpeza
```
BioDeskPro2/
├── 150+ ficheiros .md (raiz)
├── 15+ scripts .ps1 (raiz)
├── 8+ ficheiros debug/temp
└── Navegação confusa
```

### Depois da Limpeza
```
BioDeskPro2/
├── 20 ficheiros .md ATIVOS (raiz)
├── 3 scripts .ps1 principais (raiz)
├── Docs_Historico/ (80+ .md organizados)
├── Backups/ (11 backups OUT/2025) ✅
└── Navegação limpa e clara
```

**Espaço Libertado**: ~8 MB (ficheiros temp/debug)
**Documentação Organizada**: ~80 ficheiros movidos para histórico
**Backups Preservados**: 11 backups de outubro 2025 ✅

---

## ⚠️ AVISOS IMPORTANTES

1. **Git está configurado**: Todos os ficheiros .md estão tracked. Usar `git rm` ou adicionar ao `.gitignore`.
2. **Backups outubro**: Script verifica datas para NÃO apagar nada de outubro.
3. **Docs_Historico/**: Pasta já existe, script adiciona estrutura de subpastas.
4. **Reversão**: Git permite reverter qualquer remoção (`git checkout -- <ficheiro>`).

---

## 🎯 CONCLUSÃO

- ✅ **Seguro executar**: Scripts verificam datas e fazem backup antes de mover
- ✅ **Preserva backups OUT/2025**: 11 backups mantidos intactos
- ✅ **Organiza documentação**: 80+ ficheiros movidos para histórico estruturado
- ✅ **Remove obsoletos**: ~100 ficheiros temporários/debug eliminados
- ✅ **Build funcional**: Não afeta código-fonte funcional

**Recomendação**: Executar ambos os scripts e verificar integridade com build + testes.
