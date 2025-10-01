param([string]$Tabela = "Pacientes")

Write-Host "`n[BD VIEWER] BioDeskPro2`n" -ForegroundColor Cyan

$bdPath = ".\src\BioDesk.App\biodesk.db"
if (-not (Test-Path $bdPath)) {
    Write-Host "[ERRO] BD nao encontrada" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] BD encontrada" -ForegroundColor Green

try {
    $dll = Get-ChildItem "$env:USERPROFILE\.nuget\packages\microsoft.data.sqlite.core" -Recurse -Filter "Microsoft.Data.Sqlite.dll" | Where-Object { $_.FullName -like "*net8.0*" } | Select-Object -First 1
    
    if ($null -eq $dll) {
        Write-Host "[ERRO] DLL nao encontrada. Execute: dotnet restore" -ForegroundColor Red
        exit 1
    }

    Add-Type -Path $dll.FullName
    $conn = New-Object Microsoft.Data.Sqlite.SqliteConnection("Data Source=$bdPath")
    $conn.Open()

    $cmd = $conn.CreateCommand()
    $cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    $reader = $cmd.ExecuteReader()
    
    Write-Host "`n[TABELAS]" -ForegroundColor Cyan
    $tabelas = @()
    while ($reader.Read()) {
        $nome = $reader["name"]
        $tabelas += $nome
        Write-Host "  * $nome" -ForegroundColor White
    }
    $reader.Close()

    if ($tabelas -contains $Tabela) {
        $cmdCount = $conn.CreateCommand()
        $cmdCount.CommandText = "SELECT COUNT(*) FROM $Tabela"
        $count = $cmdCount.ExecuteScalar()
        
        Write-Host "`n[DADOS] $Tabela - Total: $count" -ForegroundColor Cyan
        
        if ($count -gt 0) {
            $cmdData = $conn.CreateCommand()
            $cmdData.CommandText = "SELECT * FROM $Tabela LIMIT 10"
            $readerData = $cmdData.ExecuteReader()
            
            $colunas = @()
            for ($i = 0; $i -lt $readerData.FieldCount; $i++) {
                $colunas += $readerData.GetName($i)
            }
            Write-Host ($colunas -join " | ") -ForegroundColor Yellow
            
            while ($readerData.Read()) {
                $valores = @()
                foreach ($col in $colunas) {
                    $val = $readerData[$col]
                    if ($null -eq $val) { $val = "(null)" }
                    $valores += $val.ToString()
                }
                Write-Host ($valores -join " | ") -ForegroundColor White
            }
            $readerData.Close()
        }
    }

    $conn.Close()
    Write-Host "`n[OK] Conexao fechada`n" -ForegroundColor Green

} catch {
    Write-Host "`n[ERRO] $_`n" -ForegroundColor Red
}
