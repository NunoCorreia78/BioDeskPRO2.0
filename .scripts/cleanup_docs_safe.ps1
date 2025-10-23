# Script conservador para arquivar documentação histórica e backups
# NÃO ejecutar sem revisão manual. Este script MOVE ficheiros .md do root e logs para pastas de arquivo.
# Uso: Review e depois executar em PowerShell: .\.scripts\cleanup_docs_safe.ps1

param(
    [switch]$WhatIfMode = $true
)

$root = Split-Path -Parent $MyInvocation.MyCommand.Definition
$docsArchive = Join-Path $root "Docs_Historico\2025-10"
$backupsArchive = Join-Path $root "Backups\2025-10"
$inventoryFile = Join-Path $root "cleanup_inventory_2025-10.txt"

Write-Output "Root: $root"
Write-Output "Docs archive: $docsArchive"
Write-Output "Backups archive: $backupsArchive"
Write-Output "Inventory: $inventoryFile"

# Ensure directories exist (or create)
if (-not (Test-Path $docsArchive)) { New-Item -Path $docsArchive -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $backupsArchive)) { New-Item -Path $backupsArchive -ItemType Directory -Force | Out-Null }

# Helper to record inventory
function Record($line) {
    Add-Content -Path $inventoryFile -Value $line
}

# Clear previous inventory
if (Test-Path $inventoryFile) { Remove-Item $inventoryFile -Force }
Record "Cleanup inventory generated on: $(Get-Date -Format o)"

# Conservative rules:
# 1. Move .md files from root (not in .github, src, .vscode) except README.md, LICENSE* and files marked as critical in ORGANIZAR scripts
# 2. Move large backup .db files and files with backup timestamps to Backups
# 3. Move obvious debug logs *.txt that contain keywords (DEBUG, CRASH, LOG, DISPATCHER) to Backups
# 4. DO NOT touch src/ or .github/ or .vscode/ or files listed in .github/copilot-instructions.md as protected

# 1) Move .md files in repository root
Get-ChildItem -Path $root -File -Filter *.md | ForEach-Object {
    $f = $_.FullName
    $name = $_.Name
    # Keep README.md and essential files
    $keep = @('README.md','global.json','BioDeskPro2.sln')
    if ($name -in $keep) {
        Record "SKIP (essential): $name"
        return
    }
    # Files we should not move by default (explicit list)
    $protected = @('CHECKLIST_ANTI_ERRO_UI.md','CHECKLIST_AUDITORIA_COMPLETA.md','REGRAS_CRITICAS_BD.md','REGRAS_CRITICAS_EMAIL.md')
    if ($name -in $protected) {
        Record "SKIP (protected): $name"
        return
    }
    $dest = Join-Path $docsArchive $name
    Record "MOVE: $f -> $dest"
    if (-not $WhatIfMode) { Move-Item -Path $f -Destination $dest -Force }
}

# 2) Move backup database files and large .db in root
Get-ChildItem -Path $root -File -Include *.db,*.bak,*.zip | ForEach-Object {
    $f = $_.FullName
    $name = $_.Name
    # Avoid moving actual project build artifacts in src/bin
    if ($f -like "*\\src\\*") { Record "SKIP (in src): $name"; return }
    $dest = Join-Path $backupsArchive $name
    Record "MOVE-BACKUP: $f -> $dest"
    if (-not $WhatIfMode) { Move-Item -Path $f -Destination $dest -Force }
}

# 3) Move debug/log txt files from root that match keywords
$txtPatterns = @('DEBUG','CRASH','LOG','DISPATCHER','ERROR','TASK_EXCEPTION')
Get-ChildItem -Path $root -File -Filter *.txt | ForEach-Object {
    $f = $_.FullName
    $content = Get-Content -Path $f -Raw -ErrorAction SilentlyContinue
    foreach ($p in $txtPatterns) {
        if ($content -and $content.ToUpper().Contains($p)) {
            $dest = Join-Path $backupsArchive $_.Name
            Record "MOVE-TXT: $f -> $dest (matched: $p)"
            if (-not $WhatIfMode) { Move-Item -Path $f -Destination $dest -Force }
            break
        }
    }
}

# 4) Copy OrganizarDocumentacaoHistorica script's listed files (if present) to Docs_Historico (log only)
$organizarScript = Join-Path $root 'OrganizarDocumentacaoHistorica_15OUT2025.ps1'
if (Test-Path $organizarScript) {
    Record "Found organizar script: $organizarScript"
    $lines = Get-Content $organizarScript | Where-Object { $_ -match '".*\.md"' }
    foreach ($l in $lines) {
        if ($l -match '"([^"\\]+\.md)"') {
            $mdName = $matches[1]
            $src = Join-Path $root $mdName
            if (Test-Path $src) {
                $dest = Join-Path $docsArchive $mdName
                Record "MOVE-LISTED: $src -> $dest"
                if (-not $WhatIfMode) { Move-Item -Path $src -Destination $dest -Force }
            }
        }
    }
}

Record "--- End of inventory ---"

Write-Output "Inventory written to: $inventoryFile"
if ($WhatIfMode) { Write-Output "WhatIfMode enabled - no files were actually moved. To apply changes, run with -WhatIfMode:$false" }
else { Write-Output "Changes applied." }
