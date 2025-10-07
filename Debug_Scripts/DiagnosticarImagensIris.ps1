# SCRIPT DE DIAGNOSTICO: Verificar Base de Dados SQLite

Write-Host "DIAGNOSTICO DA BASE DE DADOS - IrisImagens" -ForegroundColor Cyan
Write-Host "============================================================"

$dbPath = ".\biodesk.db"

if (-Not (Test-Path $dbPath)) {
    Write-Host "[ERRO] Base de dados nao encontrada: $dbPath" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Base de dados encontrada: $dbPath" -ForegroundColor Green

# Verificar se sqlite3 esta disponivel
$sqliteCmd = Get-Command sqlite3 -ErrorAction SilentlyContinue

if ($null -eq $sqliteCmd) {
    Write-Host ""
    Write-Host "[AVISO] SQLite3 nao encontrado no PATH" -ForegroundColor Yellow
    Write-Host "QUERIES MANUAIS (executar em DB Browser for SQLite):" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "-- 1. Contar todas as imagens de iris:"
    Write-Host "SELECT COUNT(*) as Total FROM IrisImagens;" -ForegroundColor White
    Write-Host ""
    Write-Host "-- 2. Ver todas as imagens:"
    Write-Host "SELECT Id, PacienteId, Olho, DataCaptura, CaminhoImagem FROM IrisImagens;" -ForegroundColor White
    Write-Host ""
    Write-Host "-- 3. Ver imagens por paciente:"
    Write-Host "SELECT p.NomeCompleto, COUNT(i.Id) as TotalImagens" -ForegroundColor White
    Write-Host "FROM Pacientes p" -ForegroundColor White
    Write-Host "LEFT JOIN IrisImagens i ON p.Id = i.PacienteId" -ForegroundColor White
    Write-Host "GROUP BY p.Id, p.NomeCompleto;" -ForegroundColor White
    Write-Host ""
    Write-Host "DOWNLOAD: https://sqlitebrowser.org/" -ForegroundColor Green
    exit 0
}

Write-Host ""
Write-Host "[OK] SQLite3 encontrado! Executando queries..." -ForegroundColor Green
Write-Host ""

# Query 1: Total de imagens
Write-Host "TOTAL DE IMAGENS DE IRIS:" -ForegroundColor Yellow
$total = & sqlite3 $dbPath "SELECT COUNT(*) FROM IrisImagens;"
Write-Host "   Total: $total imagens" -ForegroundColor $(if ($total -eq 0) { "Red" } else { "Green" })
Write-Host ""

# Query 2: Listar todas as imagens
if ($total -gt 0) {
    Write-Host "LISTA DE IMAGENS:" -ForegroundColor Yellow
    & sqlite3 -header -column $dbPath "SELECT Id, PacienteId, Olho, DataCaptura, substr(CaminhoImagem, -50) as Caminho FROM IrisImagens;"
    Write-Host ""
}

# Query 3: Imagens por paciente
Write-Host "IMAGENS POR PACIENTE:" -ForegroundColor Yellow
& sqlite3 -header -column $dbPath @"
SELECT
    p.Id as PacienteId,
    p.NomeCompleto,
    COUNT(i.Id) as TotalImagens
FROM Pacientes p
LEFT JOIN IrisImagens i ON p.Id = i.PacienteId
GROUP BY p.Id, p.NomeCompleto
ORDER BY p.Id;
"@
Write-Host ""

# Diagnostico
if ($total -eq 0) {
    Write-Host "[PROBLEMA] SEM IMAGENS NA BASE DE DADOS" -ForegroundColor Red
    Write-Host ""
    Write-Host "[SOLUCAO]:" -ForegroundColor Green
    Write-Host "   1. Abra a aplicacao BioDeskPro2"
    Write-Host "   2. Navegue para FichaPaciente -> Tab 'Iris'"
    Write-Host "   3. Clique no botao de Adicionar para importar uma imagem"
    Write-Host "   4. OU clique no botao de Capturar para tirar foto da camera"
    Write-Host ""
    Write-Host "[DICA] Use uma imagem de teste PNG/JPG qualquer para testar" -ForegroundColor Cyan
} else {
    Write-Host "[OK] Existem $total imagens na base de dados" -ForegroundColor Green
    Write-Host ""
    Write-Host "[VERIFICAR]:" -ForegroundColor Yellow
    Write-Host "   1. O paciente ativo tem imagens associadas?"
    Write-Host "   2. Os caminhos das imagens estao corretos?"
    Write-Host "   3. Os ficheiros existem no disco?"
}

Write-Host ""
Write-Host "============================================================"
Write-Host "[OK] Diagnostico completo!" -ForegroundColor Green
