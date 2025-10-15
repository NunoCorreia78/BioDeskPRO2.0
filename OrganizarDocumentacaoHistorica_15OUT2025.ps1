# ========================================
# Script de Organização de Documentação Histórica
# Data: 15 de outubro de 2025
# Move ficheiros .md antigos para Docs_Historico/
# Mantém na raiz apenas documentação ativa
# ========================================

$ErrorActionPreference = "Stop"
$workspaceRoot = $PSScriptRoot
$docsHistorico = Join-Path $workspaceRoot "Docs_Historico"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  ORGANIZAÇÃO DOCUMENTAÇÃO HISTÓRICA" -ForegroundColor Cyan
Write-Host "  BioDeskPro2 - 15/OUT/2025" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Contador
$movidos = 0
$erros = 0

# Criar estrutura de pastas
Write-Host "Criando estrutura de pastas..." -ForegroundColor Yellow

$subpastas = @(
    "Sessoes_SET_OUT_2025",
    "Correcoes_OUT_2025",
    "Auditorias_OUT_2025",
    "Implementacoes_OUT_2025",
    "Sprints_OUT_2025",
    "Prompts_Guias",
    "Planos_Resumos",
    "Especificacoes"
)

foreach ($pasta in $subpastas) {
    $caminho = Join-Path $docsHistorico $pasta
    if (-not (Test-Path $caminho)) {
        New-Item -ItemType Directory -Path $caminho -Force | Out-Null
        Write-Host "  [✓] Criada: $pasta" -ForegroundColor Green
    }
}

Write-Host ""

# Função para mover ficheiro
function Move-DocFile {
    param(
        [string]$FileName,
        [string]$DestFolder,
        [string]$Descricao
    )

    $source = Join-Path $workspaceRoot $FileName
    $dest = Join-Path $docsHistorico "$DestFolder\$FileName"

    try {
        if (Test-Path $source) {
            Move-Item $source $dest -Force -ErrorAction Stop
            Write-Host "  [✓] $Descricao" -ForegroundColor Green
            $script:movidos++
            return $true
        } else {
            Write-Host "  [~] Já não existe: $FileName" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "  [✗] ERRO ao mover $FileName : $_" -ForegroundColor Red
        $script:erros++
        return $false
    }
}

# ========================================
# 1. SESSÕES ANTIGAS (SET-OUT)
# ========================================
Write-Host "1. Movendo resumos de sessões antigas..." -ForegroundColor Yellow

$sessoes = @(
    "RESUMO_SESSAO_01OUT2025.md",
    "RESUMO_SESSAO_04OUT2025.md",
    "RESUMO_SESSAO_05OUT2025.md",
    "RESUMO_SESSAO_06OUT2025.md",
    "RESUMO_SESSAO_07OUT2025.md",
    "RESUMO_SESSAO_09OUT2025.md",
    "RESUMO_SESSAO_10OUT2025.md",
    "RESUMO_SESSAO_12OUT2025.md",
    "REFACTORING_SESSAO_03OUT2025.md"
)

foreach ($doc in $sessoes) {
    Move-DocFile $doc "Sessoes_SET_OUT_2025" $doc
}

# ========================================
# 2. CORREÇÕES ANTIGAS
# ========================================
Write-Host ""
Write-Host "2. Movendo correções antigas..." -ForegroundColor Yellow

$correcoes = @(
    "CORRECOES_FINAIS_SESSAO_07OUT2025.md",
    "CORRECOES_SESSAO_07OUT2025_PARTE2.md",
    "CORRECOES_UX_COMPLETAS.md",
    "CORRECAO_STATICRESOURCE_EXCEPTION.md",
    "CORRECAO_PATHSERVICE_BD_ERRADA.md",
    "CORRECAO_CRITICA_VALIDACAO_OBRIGATORIA.md",
    "DIAGNOSTICO_PROBLEMA_EMAIL_07OUT2025.md",
    "SOLUCAO_COMPLETA_EMAIL_07OUT2025.md",
    "SOLUCAO_CROP_QUADRADO_IRIS_07OUT2025.md",
    "OTIMIZACAO_CANVAS_IRIS_07OUT2025.md"
)

foreach ($doc in $correcoes) {
    Move-DocFile $doc "Correcoes_OUT_2025" $doc
}

# ========================================
# 3. AUDITORIAS ANTIGAS
# ========================================
Write-Host ""
Write-Host "3. Movendo auditorias antigas..." -ForegroundColor Yellow

$auditorias = @(
    "AUDITORIA_WORKSPACE_E_PLANO_TEMPLATES_07OUT2025.md",
    "RESUMO_AUDITORIA_TEMPLATES_07OUT2025.md",
    "AUDITORIA_STATICRESOURCES_CRITICA_09OUT2025.md",
    "AUDITORIA_COMMANDPARAMETER.md",
    "AUDITORIA_IMAGENS_IRIS_CANVAS.md",
    "AUDITORIA_BINDINGS_COMPLETA.md",
    "AUDITORIA_OTIMIZACAO_COMPLETA.md",
    "AUDITORIA_LIMPEZA_WORKSPACE.md",
    "ANALISE_OTIMIZACAO_CANVAS_IRIS.md"
)

foreach ($doc in $auditorias) {
    Move-DocFile $doc "Auditorias_OUT_2025" $doc
}

# ========================================
# 4. IMPLEMENTAÇÕES ANTIGAS
# ========================================
Write-Host ""
Write-Host "4. Movendo implementações antigas..." -ForegroundColor Yellow

$implementacoes = @(
    "IMPLEMENTACAO_CONFIGURACOES_08OUT2025.md",
    "IMPLEMENTACAO_BIOFEEDBACK_TIEPIE.md",
    "FASE2_IRISDIAGNOSTICO_COMPLETA.md",
    "FASE3_IRISDIAGNOSTICO_COMPLETA.md",
    "FASE4_TIEPIE_DUMMY_COMPLETO_12OUT2025.md",
    "INVESTIGACAO_TERAPIA_QUANTICA_12OUT2025.md",
    "LIMPEZA_CODIGO_MORTO_12OUT2025.md",
    "NOVO_EXCEL_IMPORT_SERVICE_EXCELDATAREADER.md",
    "SESSAO_TERAPIAS_FASE1_COMPLETA_12OUT2025.md",
    "FLUENTVALIDATION_IMPLEMENTACAO_14OUT2025.md"
)

foreach ($doc in $implementacoes) {
    Move-DocFile $doc "Implementacoes_OUT_2025" $doc
}

# ========================================
# 5. RELATÓRIOS DE SPRINT
# ========================================
Write-Host ""
Write-Host "5. Movendo relatórios de sprint..." -ForegroundColor Yellow

$sprints = @(
    "RELATORIO_SPRINT1_COMPLETO_13OUT2025.md",
    "RELATORIO_SPRINT2_COMPLETO_12OUT2025.md",
    "RELATORIO_SPRINT2_PROGRESSO_INTERMEDIO_13OUT2025.md",
    "RELATORIO_TAREFAS_PENDENTES_12OUT2025.md",
    "TAREFAS_PENDENTES_ATUALIZADAS_12OUT2025.md",
    "TAREFAS_PENDENTES_SPRINTS_TERAPIAS_14OUT2025.md",
    "RELATORIO_GAPS_TERAPIAS_CODEX_13OUT2025.md",
    "SESSAO_14OUT2025_EVOLUCOES.md",
    "RELATORIO_MUDANCAS_14OUT2025.md",
    "ANALISE_UI_PENDENTE_14OUT2025.md",
    "AUDITORIA_BACKUP_RESTORE_14OUT2025.md"
)

foreach ($doc in $sprints) {
    Move-DocFile $doc "Sprints_OUT_2025" $doc
}

# ========================================
# 6. GUIAS E PROMPTS
# ========================================
Write-Host ""
Write-Host "6. Movendo guias e prompts..." -ForegroundColor Yellow

$guias = @(
    "PROMPT_AGENTE_CODIFICACAO_TAREFAS_RESTANTES.md",
    "PROMPT_AGENTE_SEED_DATA_CORE_COMPLETO.md",
    "PROMPT_CONTINUAR_SPRINT2_14OUT2025.md",
    "PROMPT_NOVO_CHAT_IMPLEMENTACAO.md",
    "GUIA_INSTALACAO_FERRAMENTAS.md",
    "GUIA_SIGNATURE_CANVAS.md",
    "GUIA_TESTE_DEBUG_PATHSERVICE.md",
    "GUIA_TESTE_IMPORTACAO_EXCEL.md",
    "INSTRUCOES_LIMPEZA.md",
    "SETUP_NOVO_PC.md"
)

foreach ($doc in $guias) {
    Move-DocFile $doc "Prompts_Guias" $doc
}

# ========================================
# 7. PLANOS E RESUMOS
# ========================================
Write-Host ""
Write-Host "7. Movendo planos e resumos antigos..." -ForegroundColor Yellow

$planos = @(
    "PLANO_IMPLEMENTACAO_TERAPIAS_COMPLETO.md",
    "PLANO_IMPLEMENTACAO_CORE_INFORMACIONAL_14OUT2025.md",
    "PROXIMOS_PASSOS_BANCO_CORE.md",
    "RESUMO_FICHEIROS_CORE_COMPLETO.md",
    "RESUMO_PASTAS_DOCUMENTAIS.md",
    "RESUMO_SESSAO_TERAPIAS_BIOENERGETICAS_12OUT2025.md",
    "RESUMO_SESSAO_VALIDACOES_TEMPO_REAL.md",
    "RESUMO_UX_MAPA_MELHORADO.md",
    "ORGANIZACAO_SCRIPTS_DEBUG.md",
    "SCRIPT_LIMPEZA_CACHE.md",
    "SEED_DATA_CORE_INFORMACIONAL.md",
    "RELATORIO_DIFICULDADES_SEED_15OUT2025.md"
)

foreach ($doc in $planos) {
    Move-DocFile $doc "Planos_Resumos" $doc
}

# ========================================
# 8. ESPECIFICAÇÕES TÉCNICAS
# ========================================
Write-Host ""
Write-Host "8. Movendo especificações técnicas antigas..." -ForegroundColor Yellow

$specs = @(
    "ESPECIFICACAO_TERAPIAS_BIOENERGETICAS_TAB7.md",
    "CONFIGURACAO_PDF_PRESCRICAO.md",
    "PADROES_QUESTPDF.md",
    "SOLUCAO_ASSINATURAS_PDF_DEFINITIVA.md",
    "SOLUCOES_SQLITE3.md",
    "TRADUCAO_AUTOMATICA_PT.md",
    "TODO_IRISDIAGNOSTICO_E_OTIMIZACAO.md",
    "TESTE_MANUAL_PERSISTENCIA_ABAS.md",
    "TESTE_MANUAL_REAL_TIEPIE_12OUT2025.md"
)

foreach ($doc in $specs) {
    Move-DocFile $doc "Especificacoes" $doc
}

# ========================================
# RESUMO FINAL
# ========================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RESUMO DA ORGANIZAÇÃO" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ficheiros movidos: $movidos" -ForegroundColor Green
Write-Host "  Erros encontrados: $erros" -ForegroundColor $(if ($erros -gt 0) { "Red" } else { "Green" })
Write-Host "  Estrutura criada: Docs_Historico/ ✅" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Ficheiros que PERMANECERAM na raiz:" -ForegroundColor Cyan
$raizAtivos = @(
    "README.md",
    "CHECKLIST_ANTI_ERRO_UI.md",
    "CHECKLIST_AUDITORIA_COMPLETA.md",
    "CHECKLIST_INTEGRACAO_CORE.md",
    "CHECKLIST_TESTE_VALIDACOES.md",
    "GESTAO_BASE_DADOS.md",
    "REGRAS_CONSULTAS.md",
    "REGRAS_CRITICAS_BD.md",
    "SISTEMA_CONFIGURACOES.md",
    "SISTEMA_PASTAS_DOCUMENTAIS.md",
    "SISTEMA_100_COMPLETO.md",
    "PLANO_DESENVOLVIMENTO_RESTANTE.md",
    "O_QUE_FALTA_FAZER_SIMPLES.md",
    "WORKSPACE_LIMPO_TRANSFERENCIA.md",
    "CORRECAO_CRITICA_CONCORRENCIA_15OUT2025.md",
    "IMPLEMENTACAO_BANCO_CORE_COMPLETA_15OUT2025.md",
    "AUDITORIA_FICHEIROS_OBSOLETOS_15OUT2025.md"
)

foreach ($doc in $raizAtivos) {
    if (Test-Path (Join-Path $workspaceRoot $doc)) {
        Write-Host "  ✓ $doc" -ForegroundColor Green
    }
}

Write-Host ""

if ($erros -eq 0) {
    Write-Host "✅ ORGANIZAÇÃO CONCLUÍDA COM SUCESSO!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Próximos passos:" -ForegroundColor Yellow
    Write-Host "  1. Verifique: Get-ChildItem Docs_Historico -Recurse" -ForegroundColor White
    Write-Host "  2. Teste: dotnet build && dotnet test" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "⚠️ ORGANIZAÇÃO CONCLUÍDA COM $erros ERRO(S)" -ForegroundColor Yellow
    Write-Host "   Verifique os erros acima antes de continuar." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
