# Script para verificar emails na BD
$dbPath = Join-Path $PSScriptRoot "biodesk.db"

Write-Host "=== VERIFICAÇÃO DE EMAILS ===" -ForegroundColor Cyan
Write-Host "Base de dados: $dbPath" -ForegroundColor Yellow
Write-Host ""

# Carregar SQLite
Add-Type -Path "C:\Program Files\dotnet\shared\Microsoft.NETCore.App\8.0.11\System.Data.SQLite.dll" -ErrorAction SilentlyContinue

try {
    $connection = New-Object -TypeName System.Data.SQLite.SQLiteConnection
    $connection.ConnectionString = "Data Source=$dbPath"
    $connection.Open()

    $query = @"
SELECT
    Id,
    datetime(DataCriacao, 'localtime') as Data,
    Assunto,
    Status,
    IsEnviado,
    TentativasEnvio,
    datetime(ProximaTentativa, 'localtime') as ProximaTentativa,
    UltimoErro
FROM Comunicacoes
ORDER BY DataCriacao DESC
LIMIT 15
"@

    $command = $connection.CreateCommand()
    $command.CommandText = $query
    $reader = $command.ExecuteReader()

    $results = @()
    while ($reader.Read()) {
        $results += [PSCustomObject]@{
            Id = $reader["Id"]
            Data = $reader["Data"]
            Assunto = $reader["Assunto"]
            Status = $reader["Status"]
            IsEnviado = $reader["IsEnviado"]
            Tentativas = $reader["TentativasEnvio"]
            ProximaTentativa = $reader["ProximaTentativa"]
            UltimoErro = if ($reader["UltimoErro"] -eq [DBNull]::Value) { "" } else { $reader["UltimoErro"] }
        }
    }

    $results | Format-Table -AutoSize

    $reader.Close()
    $connection.Close()

    Write-Host "`n=== ANÁLISE ===" -ForegroundColor Cyan
    $agendados = $results | Where-Object { $_.Status -eq 0 }
    $enviados = $results | Where-Object { $_.Status -eq 1 }
    $falhados = $results | Where-Object { $_.Status -eq 2 }

    Write-Host "Agendados: $($agendados.Count)" -ForegroundColor Yellow
    Write-Host "Enviados: $($enviados.Count)" -ForegroundColor Green
    Write-Host "Falhados: $($falhados.Count)" -ForegroundColor Red

} catch {
    Write-Host "ERRO: $_" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
}
