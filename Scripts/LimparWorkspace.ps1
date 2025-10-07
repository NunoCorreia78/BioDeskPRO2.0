# 🧹 SCRIPT DE LIMPEZA SEGURA DO WORKSPACE - BioDeskPro2
# Data: 2 de outubro de 2025
# Versão: 1.0 - ULTRA SEGURO
#
# ⚠️ ESTE SCRIPT APENAS REMOVE FICHEIROS TEMPORÁRIOS/DEBUG
# ✅ NÃO TOCA EM NENHUM FICHEIRO CRÍTICO DA APLICAÇÃO

param(
    [switch]$RemoverBackupBD = $false,
    [switch]$DryRun = $true  # Por defeito, só mostra o que seria removido
)

Write-Host "🔍 AUDITORIA E LIMPEZA SEGURA DO WORKSPACE" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Verificar se estamos no diretório correto
if (-not (Test-Path "BioDeskPro2.sln")) {
    Write-Host "❌ ERRO: Execute este script na raiz do projeto BioDeskPro2!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Diretório correto: BioDeskPro2" -ForegroundColor Green
Write-Host ""

# ==========================================
# FASE 1: FICHEIROS SEGUROS PARA REMOVER
# ==========================================
$ficheirosParaRemover = @(
    # Scripts de debug duplicados na raiz
    "AbrirBD.ps1",
    "InvestigarPaciente.ps1",
    "VerBD_Simple.ps1",
    "VerificarEmails.ps1",
    
    # Logs temporários
    "debug_output.txt",
    "DISPATCHER_EXCEPTION.txt",
    "TASK_EXCEPTION.txt",
    
    # Ficheiros .backup no código-fonte
    "src\BioDesk.App\Views\Abas\DeclaracaoSaudeUserControl.xaml.cs.backup",
    "src\BioDesk.Services\BioDesk.Services.csproj.backup"
)

# Backup BD (opcional)
if ($RemoverBackupBD) {
    $ficheirosParaRemover += "biodesk.db.backup_20250930_220437"
}

Write-Host "📋 FICHEIROS A PROCESSAR:" -ForegroundColor Yellow
Write-Host "=========================" -ForegroundColor Yellow
Write-Host ""

$totalFicheiros = 0
$totalTamanho = 0
$ficheirosencontrados = @()

foreach ($ficheiro in $ficheirosParaRemover) {
    if (Test-Path $ficheiro) {
        $info = Get-Item $ficheiro
        $tamanhoKB = [math]::Round($info.Length / 1KB, 2)
        $totalTamanho += $info.Length
        $totalFicheiros++
        $ficheirosencontrados += $ficheiro
        
        Write-Host "  ✓ $ficheiro" -ForegroundColor Green
        Write-Host "    Tamanho: $tamanhoKB KB | Última modificação: $($info.LastWriteTime)" -ForegroundColor Gray
    } else {
        Write-Host "  ⚠ $ficheiro (não encontrado)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "📊 RESUMO:" -ForegroundColor Cyan
Write-Host "=========" -ForegroundColor Cyan
Write-Host "  Total de ficheiros: $totalFicheiros" -ForegroundColor White
Write-Host "  Espaço a liberar: $([math]::Round($totalTamanho / 1KB, 2)) KB" -ForegroundColor White
Write-Host ""

# ==========================================
# MODO DRY RUN vs EXECUÇÃO REAL
# ==========================================
if ($DryRun) {
    Write-Host "🔍 MODO DRY RUN (Simulação)" -ForegroundColor Yellow
    Write-Host "=============================" -ForegroundColor Yellow
    Write-Host "ℹ️  Nenhum ficheiro foi removido (apenas simulação)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "💡 Para executar a remoção real:" -ForegroundColor Cyan
    Write-Host "   .\LimparWorkspace.ps1 -DryRun:`$false" -ForegroundColor White
    Write-Host ""
    
    if (-not $RemoverBackupBD) {
        Write-Host "💡 Para incluir backup da BD:" -ForegroundColor Cyan
        Write-Host "   .\LimparWorkspace.ps1 -DryRun:`$false -RemoverBackupBD" -ForegroundColor White
        Write-Host ""
    }
} else {
    Write-Host "⚠️  MODO EXECUÇÃO REAL" -ForegroundColor Red
    Write-Host "=====================" -ForegroundColor Red
    Write-Host ""
    Write-Host "❓ Confirma a remoção de $totalFicheiros ficheiros?" -ForegroundColor Yellow
    Write-Host "   (S para confirmar, qualquer outra tecla para cancelar)" -ForegroundColor Yellow
    $confirmacao = Read-Host
    
    if ($confirmacao -eq "S" -or $confirmacao -eq "s") {
        Write-Host ""
        Write-Host "🧹 REMOVENDO FICHEIROS..." -ForegroundColor Cyan
        Write-Host ""
        
        $removidos = 0
        $erros = 0
        
        foreach ($ficheiro in $ficheirosencontrados) {
            try {
                Remove-Item $ficheiro -Force -ErrorAction Stop
                Write-Host "  ✓ Removido: $ficheiro" -ForegroundColor Green
                $removidos++
            } catch {
                Write-Host "  ✗ ERRO ao remover: $ficheiro" -ForegroundColor Red
                Write-Host "    $($_.Exception.Message)" -ForegroundColor Red
                $erros++
            }
        }
        
        Write-Host ""
        Write-Host "✅ LIMPEZA CONCLUÍDA!" -ForegroundColor Green
        Write-Host "====================" -ForegroundColor Green
        Write-Host "  Ficheiros removidos: $removidos" -ForegroundColor White
        Write-Host "  Erros: $erros" -ForegroundColor White
        Write-Host "  Espaço liberado: $([math]::Round($totalTamanho / 1KB, 2)) KB" -ForegroundColor White
        Write-Host ""
        
        # Verificar build após limpeza
        Write-Host "🔧 VERIFICANDO BUILD..." -ForegroundColor Cyan
        Write-Host ""
        
        $buildResult = dotnet build --no-incremental 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ BUILD OK - Nenhum ficheiro crítico foi afetado!" -ForegroundColor Green
        } else {
            Write-Host "❌ BUILD FALHOU - Algo está errado!" -ForegroundColor Red
            Write-Host "⚠️  RECOMENDAÇÃO: Reverter commit ou restaurar backups" -ForegroundColor Yellow
        }
    } else {
        Write-Host ""
        Write-Host "❌ OPERAÇÃO CANCELADA pelo utilizador" -ForegroundColor Yellow
        Write-Host ""
    }
}

# ==========================================
# FICHEIROS CRÍTICOS - VERIFICAÇÃO
# ==========================================
Write-Host ""
Write-Host "🔒 VERIFICAÇÃO DE FICHEIROS CRÍTICOS:" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

$ficheirosCriticos = @(
    "BioDeskPro2.sln",
    "global.json",
    "omnisharp.json",
    ".editorconfig",
    "biodesk.db",
    "src\BioDesk.App\BioDesk.App.csproj",
    "src\BioDesk.ViewModels\BioDesk.ViewModels.csproj",
    "src\BioDesk.Services\BioDesk.Services.csproj",
    "src\BioDesk.Domain\BioDesk.Domain.csproj",
    "src\BioDesk.Data\BioDesk.Data.csproj"
)

$todosCriticosOK = $true
foreach ($ficheiro in $ficheirosCriticos) {
    if (Test-Path $ficheiro) {
        Write-Host "  ✓ $ficheiro" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $ficheiro (NÃO ENCONTRADO!)" -ForegroundColor Red
        $todosCriticosOK = $false
    }
}

Write-Host ""
if ($todosCriticosOK) {
    Write-Host "✅ TODOS OS FICHEIROS CRÍTICOS ESTÃO INTACTOS!" -ForegroundColor Green
} else {
    Write-Host "❌ ALGUNS FICHEIROS CRÍTICOS ESTÃO EM FALTA!" -ForegroundColor Red
}

Write-Host ""
Write-Host "🎯 FIM DO SCRIPT" -ForegroundColor Cyan
Write-Host "================" -ForegroundColor Cyan
