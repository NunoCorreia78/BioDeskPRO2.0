# Script para forçar execução da aplicação BioDeskPro2
Write-Host "Terminando processos dotnet..."
taskkill /F /IM dotnet.exe 2>$null
taskkill /F /IM BioDesk.App.exe 2>$null

Write-Host "Aguardando 2 segundos..."
Start-Sleep -Seconds 2

Write-Host "Tentando limpar pastas obj/bin..."
Get-ChildItem -Path "src" -Recurse -Directory -Name "obj" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -Path "src\$_" -Recurse -Force -ErrorAction SilentlyContinue
}
Get-ChildItem -Path "src" -Recurse -Directory -Name "bin" -ErrorAction SilentlyContinue | ForEach-Object {
    Remove-Item -Path "src\$_" -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Executando restore..."
dotnet restore

Write-Host "Executando build..."
dotnet build

if ($LASTEXITCODE -eq 0) {
    Write-Host "Build bem-sucedido. Executando aplicação..."
    dotnet run --project src/BioDesk.App
} else {
    Write-Host "Build falhou com código: $LASTEXITCODE"
}
