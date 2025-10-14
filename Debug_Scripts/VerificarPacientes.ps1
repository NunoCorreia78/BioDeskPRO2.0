#!/usr/bin/env pwsh
# Script para verificar pacientes na base de dados SQLite

$dbPath = "biodesk.db"

if (-Not (Test-Path $dbPath)) {
    Write-Host "❌ Base de dados não encontrada!" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Base de dados encontrada: $dbPath" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan

# Usar SQLite via .NET
Add-Type -Path "C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.0\System.Data.Common.dll" -ErrorAction SilentlyContinue

try {
    # Tentar usar sqlite3.exe se estiver instalado
    $sqliteExe = Get-Command sqlite3 -ErrorAction SilentlyContinue

    if ($sqliteExe) {
        Write-Host "`n📊 CONTAGEM DE REGISTOS:" -ForegroundColor Yellow

        $query = @"
SELECT 'Pacientes' as Tabela, COUNT(*) as Total FROM Pacientes
UNION ALL
SELECT 'Sessoes', COUNT(*) FROM Sessoes
UNION ALL
SELECT 'Contactos', COUNT(*) FROM Contactos
UNION ALL
SELECT 'IrisImagens', COUNT(*) FROM IrisImagens
UNION ALL
SELECT 'IrisMarcas', COUNT(*) FROM IrisMarcas;
"@

        $result = & sqlite3 $dbPath $query
        Write-Host $result

        Write-Host "`n👤 PACIENTES:" -ForegroundColor Yellow
        $queryPacientes = "SELECT Id, NomeCompleto, DataNascimento FROM Pacientes ORDER BY Id;"
        $pacientes = & sqlite3 $dbPath $queryPacientes
        Write-Host $pacientes

    } else {
        Write-Host "⚠️ sqlite3.exe não encontrado. Instale com: winget install SQLite.SQLite" -ForegroundColor Yellow

        # Método alternativo: verificar tamanho do ficheiro
        $fileInfo = Get-Item $dbPath
        Write-Host "`n📁 Tamanho da base de dados: $($fileInfo.Length) bytes" -ForegroundColor Cyan

        if ($fileInfo.Length -lt 10000) {
            Write-Host "🚨 ALERTA: Base de dados muito pequena! Pode estar vazia ou corrompida." -ForegroundColor Red
        }
    }

} catch {
    Write-Host "❌ Erro ao verificar base de dados: $_" -ForegroundColor Red
}

Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
