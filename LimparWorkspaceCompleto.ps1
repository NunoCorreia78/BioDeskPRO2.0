# 🧹 LIMPEZA COMPLETA DE WORKSPACE - BioDeskPro2
# Data: 07 de Outubro de 2025
# Descrição: Remove ficheiros poluentes, organiza documentação e backups

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   🧹 LIMPEZA DE WORKSPACE - BioDeskPro2" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Confirmar com utilizador
Write-Host "⚠️  ATENÇÃO: Este script irá:" -ForegroundColor Yellow
Write-Host "   • Eliminar backups antigos da base de dados" -ForegroundColor White
Write-Host "   • Eliminar ficheiros de debug temporários" -ForegroundColor White
Write-Host "   • Mover documentos históricos para pasta Docs_Historico/" -ForegroundColor White
Write-Host "   • Eliminar scripts PowerShell duplicados" -ForegroundColor White
Write-Host ""

$confirmacao = Read-Host "Deseja continuar? (S/N)"
if ($confirmacao -ne "S" -and $confirmacao -ne "s") {
    Write-Host "❌ Operação cancelada." -ForegroundColor Red
    exit 0
}

Write-Host ""

# Contadores
$backupsEliminados = 0
$debugEliminados = 0
$docsMovidos = 0
$scriptsEliminados = 0

# 1. Criar pastas de organização
Write-Host "📁 A criar estrutura de pastas..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "Docs_Historico/2025-10" | Out-Null
New-Item -ItemType Directory -Force -Path "Scripts" | Out-Null
New-Item -ItemType Directory -Force -Path "Backups" | Out-Null
Write-Host "   ✅ Pastas criadas" -ForegroundColor Green

# 2. Eliminar backups antigos (manter apenas o mais recente)
Write-Host ""
Write-Host "🗑️  A eliminar backups antigos..." -ForegroundColor Yellow

if (Test-Path "biodesk_backup_20251007_112918.db") {
    Remove-Item "biodesk_backup_20251007_112918.db" -Force
    $backupsEliminados++
    Write-Host "   ✅ Eliminado: biodesk_backup_20251007_112918.db" -ForegroundColor Green
}

if (Test-Path "biodesk_backup_20251007_113656.db") {
    Remove-Item "biodesk_backup_20251007_113656.db" -Force
    $backupsEliminados++
    Write-Host "   ✅ Eliminado: biodesk_backup_20251007_113656.db" -ForegroundColor Green
}

# 3. Mover backup recente para pasta Backups/
Write-Host ""
Write-Host "📦 A organizar backups..." -ForegroundColor Yellow

if (Test-Path "biodesk_backup_iris_crop_20251007_194719.db") {
    Move-Item "biodesk_backup_iris_crop_20251007_194719.db" "Backups/" -Force
    Write-Host "   ✅ Movido: biodesk_backup_iris_crop_20251007_194719.db → Backups/" -ForegroundColor Green
}

# 4. Eliminar ficheiros de debug temporários
Write-Host ""
Write-Host "🗑️  A eliminar ficheiros de debug..." -ForegroundColor Yellow

$debugFiles = @(
    "DEBUG_DOCUMENTOS.txt",
    "DISPATCHER_EXCEPTION.txt",
    "LOGS_DEBUG.txt",
    "DropIrisTables.sql",
    "RECOVERY_IrisdiagnosticoUserControl.xaml"
)

foreach ($file in $debugFiles) {
    if (Test-Path $file) {
        Remove-Item $file -Force
        $debugEliminados++
        Write-Host "   ✅ Eliminado: $file" -ForegroundColor Green
    }
}

# 5. Mover documentos históricos para pasta
Write-Host ""
Write-Host "📚 A organizar documentos históricos..." -ForegroundColor Yellow

$historicos = @(
    "ANALISE_ARRASTO_DEBUG_COMPLETA.md",
    "ANALISE_CONEXOES_BD.md",
    "ANALISE_CONTROLE_TAMANHO_IRIS.md",
    "ANALISE_ESTICAMENTO_MAPA.md",
    "ANALISE_SEPARADORES_BD.md",
    "ANALISE_UX_MOVIMENTO_MAPA.md",
    "CORRECAO_BOTOES_GRID.md",
    "CORRECAO_ESTICAMENTO_IMPLEMENTADA.md",
    "CORRECAO_SCROLLBAR_SEPARADORES.md",
    "CORRECAO_STATUS_FALHADO_APOS_ENVIO.md",
    "CORRECOES_DECLARACAO_SAUDE.md",
    "CORRECOES_LOGGING_PERFORMANCE.md",
    "CORRECOES_LOGOS_ICONES_07OUT2025.md",
    "CORRECOES_MANUAIS_URGENTES.md",
    "CORRECOES_SISTEMA_EMAIL.md",
    "DIAGNOSTICO_MAPA_IRIDOLOGICO.md",
    "PROBLEMA_ASSINATURA_PDF.md",
    "CORRECAO_CRITICA_EMAILS_AGENDADOS.md",
    "CORRECAO_BLOQUEIO_POWERSHELL_07OUT2025.md",
    "CORRECOES_IMAGENS_IRIS_07OUT2025.md"
)

foreach ($doc in $historicos) {
    if (Test-Path $doc) {
        Move-Item $doc "Docs_Historico/2025-10/" -Force
        $docsMovidos++
        Write-Host "   ✅ Movido: $doc → Docs_Historico/2025-10/" -ForegroundColor Green
    }
}

# 6. Consolidar scripts PowerShell
Write-Host ""
Write-Host "📜 A consolidar scripts..." -ForegroundColor Yellow

# Mover scripts úteis para pasta Scripts/
if (Test-Path "ConfigurarEmail.ps1") {
    Move-Item "ConfigurarEmail.ps1" "Scripts/" -Force
    Write-Host "   ✅ Movido: ConfigurarEmail.ps1 → Scripts/" -ForegroundColor Green
}

if (Test-Path "LimparWorkspace.ps1") {
    Move-Item "LimparWorkspace.ps1" "Scripts/" -Force
    Write-Host "   ✅ Movido: LimparWorkspace.ps1 → Scripts/" -ForegroundColor Green
}

# Eliminar scripts duplicados
Write-Host ""
Write-Host "🗑️  A eliminar scripts duplicados..." -ForegroundColor Yellow

$scriptsDuplicados = @(
    "APAGAR_BACKUPS_ANTIGOS.ps1",
    "LIMPEZA_COMPLETA.ps1",
    "LIMPEZA_TOTAL.ps1",
    "CRIAR_BACKUP_LIMPO.ps1",
    "GIT_FRESH_START.ps1",
    "ORGANIZAR_DOCUMENTOS.ps1"
)

foreach ($script in $scriptsDuplicados) {
    if (Test-Path $script) {
        Remove-Item $script -Force
        $scriptsEliminados++
        Write-Host "   ✅ Eliminado: $script" -ForegroundColor Green
    }
}

# 7. Criar README em cada pasta nova
Write-Host ""
Write-Host "📝 A criar ficheiros README..." -ForegroundColor Yellow

# README em Docs_Historico/
$readmeHistorico = @"
# 📚 Documentos Históricos

Esta pasta contém documentos de análise, correções e diagnósticos de problemas já resolvidos.

## Organização

```
2025-10/  ← Outubro 2025
  ├── ANALISE_*.md
  ├── CORRECAO_*.md
  └── DIAGNOSTICO_*.md
```

## Propósito

- Manter histórico de problemas e soluções
- Referência futura para troubleshooting
- Auditoria de desenvolvimento

## Nota

Estes documentos são **apenas para consulta**. Problemas descritos já foram resolvidos e integrados no código.
"@

Set-Content -Path "Docs_Historico/README.md" -Value $readmeHistorico -Encoding UTF8
Write-Host "   ✅ Criado: Docs_Historico/README.md" -ForegroundColor Green

# README em Scripts/
$readmeScripts = @"
# 📜 Scripts PowerShell

Scripts úteis para gestão e manutenção do BioDeskPro2.

## Scripts Disponíveis

### ConfigurarEmail.ps1
Configuração interativa de credenciais SMTP para envio de emails.

**Uso:**
``````powershell
.\ConfigurarEmail.ps1
``````

### LimparWorkspace.ps1
Limpeza básica de workspace (cache, temporários, etc.)

**Uso:**
``````powershell
.\LimparWorkspace.ps1
``````

## Notas

- Executar sempre com permissões adequadas
- Fazer backup antes de scripts destrutivos
- Verificar código antes de executar
"@

Set-Content -Path "Scripts/README.md" -Value $readmeScripts -Encoding UTF8
Write-Host "   ✅ Criado: Scripts/README.md" -ForegroundColor Green

# README em Backups/
$readmeBackups = @"
# 💾 Backups da Base de Dados

Esta pasta contém backups timestamped da base de dados SQLite.

## Política de Backups

- **Automático**: Backup antes de operações críticas (migrations, bulk updates)
- **Manual**: Backup via script ou interface
- **Retenção**: Manter últimos 7 dias

## Formato de Nome

``````
biodesk_backup_[descrição]_AAAAMMDD_HHMMSS.db
``````

**Exemplo:**
``````
biodesk_backup_iris_crop_20251007_194719.db
``````

## Restaurar Backup

``````powershell
# Parar aplicação
# Substituir biodesk.db pelo backup desejado
Copy-Item "Backups\biodesk_backup_AAAAMMDD_HHMMSS.db" "biodesk.db" -Force
# Reiniciar aplicação
``````

## Nota

Backups não fazem parte do repositório Git (excluídos via .gitignore).
"@

Set-Content -Path "Backups/README.md" -Value $readmeBackups -Encoding UTF8
Write-Host "   ✅ Criado: Backups/README.md" -ForegroundColor Green

# 8. Resumo final
Write-Host ""
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   ✅ LIMPEZA CONCLUÍDA COM SUCESSO!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host "📊 Resumo:" -ForegroundColor Cyan
Write-Host "   • Backups antigos eliminados: $backupsEliminados" -ForegroundColor White
Write-Host "   • Ficheiros debug eliminados: $debugEliminados" -ForegroundColor White
Write-Host "   • Documentos históricos movidos: $docsMovidos" -ForegroundColor White
Write-Host "   • Scripts duplicados eliminados: $scriptsEliminados" -ForegroundColor White
Write-Host ""

Write-Host "📁 Nova estrutura:" -ForegroundColor Cyan
Write-Host "   • Docs_Historico/2025-10/  → Documentos antigos ($docsMovidos ficheiros)" -ForegroundColor White
Write-Host "   • Scripts/                 → Scripts consolidados (2 scripts)" -ForegroundColor White
Write-Host "   • Backups/                 → Backups organizados (1 backup)" -ForegroundColor White
Write-Host ""

Write-Host "🎯 Próximos Passos:" -ForegroundColor Cyan
Write-Host "   1. Verificar se aplicação continua a funcionar" -ForegroundColor White
Write-Host "   2. Fazer commit das alterações: git add -A && git commit -m 'Limpeza workspace'" -ForegroundColor White
Write-Host "   3. Push para GitHub: git push origin main" -ForegroundColor White
Write-Host ""
