# ========================================
# Script de Limpeza de Ficheiros Obsoletos
# Data: 15 de outubro de 2025
# Preserva: Backups de outubro/2025
# Remove: Ficheiros debug/temp/backup
# ========================================

$ErrorActionPreference = "Stop"
$workspaceRoot = $PSScriptRoot

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  LIMPEZA DE FICHEIROS OBSOLETOS" -ForegroundColor Cyan
Write-Host "  BioDeskPro2 - 15/OUT/2025" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Contador de ficheiros removidos
$removidos = 0
$erros = 0

# Função para remover ficheiro com segurança
function Remove-SafeFile {
    param(
        [string]$FilePath,
        [string]$Descricao
    )
    
    try {
        if (Test-Path $FilePath) {
            Remove-Item $FilePath -Force -ErrorAction Stop
            Write-Host "  [✓] $Descricao" -ForegroundColor Green
            $script:removidos++
            return $true
        } else {
            Write-Host "  [~] Já não existe: $Descricao" -ForegroundColor Yellow
            return $false
        }
    }
    catch {
        Write-Host "  [✗] ERRO ao remover $Descricao : $_" -ForegroundColor Red
        $script:erros++
        return $false
    }
}

# ========================================
# 1. FICHEIROS .TXT DE DEBUG
# ========================================
Write-Host ""
Write-Host "1. Removendo ficheiros .txt de debug..." -ForegroundColor Yellow

Remove-SafeFile "$workspaceRoot\DEBUG_DOCUMENTOS.txt" "DEBUG_DOCUMENTOS.txt"
Remove-SafeFile "$workspaceRoot\CRASH_LOG_DISPATCHER.txt" "CRASH_LOG_DISPATCHER.txt"
Remove-SafeFile "$workspaceRoot\seed_dummy.txt" "seed_dummy.txt"
Remove-SafeFile "$workspaceRoot\Logs\DISPATCHER_EXCEPTION.txt" "Logs\DISPATCHER_EXCEPTION.txt"

# ========================================
# 2. SCRIPTS .CSX (C# Script)
# ========================================
Write-Host ""
Write-Host "2. Removendo scripts .csx temporários..." -ForegroundColor Yellow

Remove-SafeFile "$workspaceRoot\TesteLastActiveTab.csx" "TesteLastActiveTab.csx"
Remove-SafeFile "$workspaceRoot\VerificarSeedBancoCore.csx" "VerificarSeedBancoCore.csx"

# ========================================
# 3. JSON DUPLICADOS NA RAIZ
# ========================================
Write-Host ""
Write-Host "3. Removendo JSON duplicados na raiz..." -ForegroundColor Yellow

Remove-SafeFile "$workspaceRoot\iris_drt.json" "iris_drt.json (duplicado)"
Remove-SafeFile "$workspaceRoot\iris_esq.json" "iris_esq.json (duplicado)"

# ========================================
# 4. FICHEIROS .BACKUP NO CÓDIGO
# ========================================
Write-Host ""
Write-Host "4. Removendo ficheiros .backup no código-fonte..." -ForegroundColor Yellow

Remove-SafeFile "$workspaceRoot\src\BioDesk.App\Views\Abas\DeclaracaoSaudeUserControl.xaml.cs.backup" "DeclaracaoSaudeUserControl.xaml.cs.backup"
Remove-SafeFile "$workspaceRoot\src\BioDesk.Services\BioDesk.Services.csproj.backup" "BioDesk.Services.csproj.backup"
Remove-SafeFile "$workspaceRoot\src\BioDesk.Services\Excel\ExcelImportService_ORIGINAL_BUG.txt" "ExcelImportService_ORIGINAL_BUG.txt"

# ========================================
# 5. SCRIPTS .PS1 TEMPORÁRIOS
# ========================================
Write-Host ""
Write-Host "5. Removendo scripts .ps1 temporários..." -ForegroundColor Yellow

Remove-SafeFile "$workspaceRoot\tmp.ps1" "tmp.ps1"
Remove-SafeFile "$workspaceRoot\TesteLastActiveTab.ps1" "TesteLastActiveTab.ps1"
Remove-SafeFile "$workspaceRoot\TestarImportacaoExcel.ps1" "TestarImportacaoExcel.ps1"
Remove-SafeFile "$workspaceRoot\SeedItemBancoCore.ps1" "SeedItemBancoCore.ps1"
Remove-SafeFile "$workspaceRoot\VerificarSeedBancoCore.ps1" "VerificarSeedBancoCore.ps1"

# ========================================
# 6. VERIFICAR BACKUPS (NÃO TOCAR)
# ========================================
Write-Host ""
Write-Host "6. Verificando backups de outubro/2025..." -ForegroundColor Cyan

$backupsPath = "$workspaceRoot\Backups"
if (Test-Path $backupsPath) {
    $backups = Get-ChildItem -Path $backupsPath -File -Recurse | Where-Object { 
        $_.Name -like "BioDeskBackup_*.zip" -or 
        $_.Name -like "*.db" -or
        $_.Name -like "Backup_*"
    }
    
    Write-Host "  [✓] Backups preservados: $($backups.Count) ficheiros" -ForegroundColor Green
    
    foreach ($backup in $backups | Sort-Object Name) {
        $sizeMB = [math]::Round($backup.Length / 1MB, 2)
        Write-Host "      - $($backup.Name) ($sizeMB MB)" -ForegroundColor Gray
    }
} else {
    Write-Host "  [!] Pasta Backups/ não encontrada" -ForegroundColor Yellow
}

# ========================================
# RESUMO FINAL
# ========================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RESUMO DA LIMPEZA" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Ficheiros removidos: $removidos" -ForegroundColor Green
Write-Host "  Erros encontrados: $erros" -ForegroundColor $(if ($erros -gt 0) { "Red" } else { "Green" })
Write-Host "  Backups preservados: TODOS de OUT/2025 ✅" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($erros -eq 0) {
    Write-Host "✅ LIMPEZA CONCLUÍDA COM SUCESSO!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Próximos passos:" -ForegroundColor Yellow
    Write-Host "  1. Execute: .\OrganizarDocumentacaoHistorica_15OUT2025.ps1" -ForegroundColor White
    Write-Host "  2. Teste: dotnet build && dotnet test" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "⚠️ LIMPEZA CONCLUÍDA COM $erros ERRO(S)" -ForegroundColor Yellow
    Write-Host "   Verifique os erros acima antes de continuar." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
