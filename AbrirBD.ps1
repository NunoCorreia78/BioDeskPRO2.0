# Atalho para Abrir BD no DB Browser for SQLite
# BioDeskPro2 - Abre a base de dados diretamente no DB Browser

$bdPath = Join-Path $PSScriptRoot "src\BioDesk.App\biodesk.db"

if (-not (Test-Path $bdPath)) {
    Write-Host "[ERRO] Base de dados nao encontrada em:" -ForegroundColor Red
    Write-Host "   $bdPath" -ForegroundColor Yellow
    exit 1
}

Write-Host "`n[DB BROWSER] Abrindo base de dados..." -ForegroundColor Cyan
Write-Host "[INFO] Localizacao: $bdPath" -ForegroundColor Gray

# Tentar abrir com DB Browser
$dbBrowserPaths = @(
    "C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe",
    "C:\Program Files (x86)\DB Browser for SQLite\DB Browser for SQLite.exe",
    "$env:LOCALAPPDATA\Programs\DB Browser for SQLite\DB Browser for SQLite.exe"
)

$found = $false
foreach ($path in $dbBrowserPaths) {
    if (Test-Path $path) {
        Write-Host "[OK] DB Browser encontrado: $path" -ForegroundColor Green
        Start-Process -FilePath $path -ArgumentList "`"$bdPath`""
        $found = $true
        Write-Host "[OK] Base de dados aberta no DB Browser!" -ForegroundColor Green
        break
    }
}

if (-not $found) {
    Write-Host "`n[INFO] DB Browser nao encontrado automaticamente" -ForegroundColor Yellow
    Write-Host "[INSTRUCOES] Abrir manualmente:" -ForegroundColor Cyan
    Write-Host "   1. Menu Iniciar > Pesquisar 'DB Browser'" -ForegroundColor White
    Write-Host "   2. File > Open Database" -ForegroundColor White
    Write-Host "   3. Selecionar: $bdPath" -ForegroundColor Yellow

    # Abrir explorador na pasta da BD
    Write-Host "`n[INFO] Abrindo explorador na pasta da BD..." -ForegroundColor Cyan
    Start-Process explorer.exe -ArgumentList "/select,`"$bdPath`""
}

Write-Host ""
