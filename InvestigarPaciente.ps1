# Investigar paciente "Nuno Filipe Correia" na base de dados
$dbPath = "biodesk.db"

Add-Type -Path "C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Data.SQLite\v4.0_1.0.118.0__db937bc2d44ff139\System.Data.SQLite.dll" -ErrorAction SilentlyContinue

try {
    $connectionString = "Data Source=$dbPath;Version=3;"
    $connection = New-Object System.Data.SQLite.SQLiteConnection($connectionString)
    $connection.Open()

    Write-Host "=== TODOS OS PACIENTES ===" -ForegroundColor Cyan
    $command = $connection.CreateCommand()
    $command.CommandText = "SELECT Id, Nome, Email, DataNascimento FROM Pacientes ORDER BY Nome"
    $reader = $command.ExecuteReader()

    $count = 0
    while ($reader.Read()) {
        $count++
        $id = $reader["Id"]
        $nome = $reader["Nome"]
        $email = if ($reader["Email"] -eq [DBNull]::Value) { "(sem email)" } else { $reader["Email"] }
        $dataNasc = if ($reader["DataNascimento"] -eq [DBNull]::Value) { "(sem data)" } else { [DateTime]$reader["DataNascimento"] }

        Write-Host "$count. ID: $id | Nome: $nome | Email: $email | Nascimento: $dataNasc"

        if ($nome -like "*Nuno*" -or $nome -like "*Correia*") {
            Write-Host "   ^^^ ENCONTRADO MATCH PARA 'NUNO' OU 'CORREIA' ^^^" -ForegroundColor Green
        }
    }
    $reader.Close()

    Write-Host "`nTotal de pacientes: $count" -ForegroundColor Yellow

    $connection.Close()
}
catch {
    Write-Host "ERRO: $_" -ForegroundColor Red
    Write-Host "Tentando usar método alternativo com dotnet..." -ForegroundColor Yellow
}
