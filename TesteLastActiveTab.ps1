# Script de Teste - Persistência Estado Abas
# Verifica se coluna LastActiveTab existe e mostra valores atuais

Write-Host "`n🧪 TESTE: Persistência Estado Abas - Sprint 2" -ForegroundColor Cyan
Write-Host "=" * 60 -ForegroundColor Cyan

$dbPath = "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db"

if (-not (Test-Path $dbPath)) {
    Write-Host "❌ Base de dados não encontrada: $dbPath" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Base de dados encontrada: $dbPath" -ForegroundColor Green
$dbSize = (Get-Item $dbPath).Length / 1KB
Write-Host "📊 Tamanho: $([math]::Round($dbSize, 2)) KB" -ForegroundColor Gray

# Usar System.Data.SQLite do .NET
Add-Type -Path "C:\Users\nfjpc\.nuget\packages\system.data.sqlite.core\1.0.118\lib\netstandard2.1\System.Data.SQLite.dll" -ErrorAction SilentlyContinue

try {
    $connectionString = "Data Source=$dbPath;Version=3;Read Only=True;"
    $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
    $connection.Open()

    Write-Host "`n📋 ESTRUTURA TABELA PACIENTES:" -ForegroundColor Yellow
    $cmd = $connection.CreateCommand()
    $cmd.CommandText = "PRAGMA table_info(Pacientes);"
    $reader = $cmd.ExecuteReader()

    $hasLastActiveTab = $false
    while ($reader.Read()) {
        $colName = $reader["name"]
        $colType = $reader["type"]
        $colDefault = $reader["dflt_value"]

        if ($colName -eq "LastActiveTab") {
            $hasLastActiveTab = $true
            Write-Host "   ✅ LastActiveTab | $colType | Default: $colDefault" -ForegroundColor Green
        }
    }
    $reader.Close()

    if (-not $hasLastActiveTab) {
        Write-Host "   ❌ Coluna LastActiveTab NÃO encontrada!" -ForegroundColor Red
        $connection.Close()
        exit 1
    }

    Write-Host "`n📊 VALORES ATUAIS (Top 5 pacientes):" -ForegroundColor Yellow
    $cmd = $connection.CreateCommand()
    $cmd.CommandText = "SELECT Id, NomeCompleto, LastActiveTab FROM Pacientes LIMIT 5;"
    $reader = $cmd.ExecuteReader()

    $count = 0
    while ($reader.Read()) {
        $id = $reader["Id"]
        $nome = $reader["NomeCompleto"]
        $aba = $reader["LastActiveTab"]

        $abaName = switch ($aba) {
            1 { "👤 Dados" }
            2 { "📋 Saúde" }
            3 { "✅ Consentimentos" }
            4 { "🩺 Consultas" }
            5 { "📊 Irisdiagnóstico" }
            6 { "💬 Comunicação" }
            7 { "📁 Documentos" }
            8 { "🌿 Terapias" }
            default { "⚠️ Inválida" }
        }

        Write-Host "   [$id] $nome" -ForegroundColor White -NoNewline
        Write-Host " → Aba $aba $abaName" -ForegroundColor Cyan
        $count++
    }
    $reader.Close()

    Write-Host "`n✅ TESTE CONCLUÍDO: Coluna criada com sucesso!" -ForegroundColor Green
    Write-Host "📝 Total pacientes analisados: $count" -ForegroundColor Gray

    $connection.Close()

    Write-Host "`n📱 INSTRUÇÕES TESTE MANUAL:" -ForegroundColor Yellow
    Write-Host "1. Abrir ficha de paciente na aplicação" -ForegroundColor White
    Write-Host "2. Navegar para Aba 5 (📊 Irisdiagnóstico)" -ForegroundColor White
    Write-Host "3. Fechar ficha (voltar ao Dashboard)" -ForegroundColor White
    Write-Host "4. Reabrir o mesmo paciente" -ForegroundColor White
    Write-Host "5. ✅ Deve abrir diretamente na Aba 5!" -ForegroundColor Green

} catch {
    Write-Host "❌ ERRO: $_" -ForegroundColor Red
    exit 1
}
