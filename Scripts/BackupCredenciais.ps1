# Script de Backup de Credenciais - BioDeskPro2
# Cria backup encriptado das credenciais de User Secrets
# Data: 21 de Outubro de 2025

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\Backups\credentials_backup.json.enc"
)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "💾 BACKUP DE CREDENCIAIS - BioDeskPro2" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Verificar se está na pasta raiz do projeto
if (-not (Test-Path "BioDeskPro2.sln")) {
    Write-Host "❌ ERRO: Execute este script a partir da pasta raiz do projeto" -ForegroundColor Red
    exit 1
}

# Criar pasta de backups se não existir
$backupDir = Split-Path $OutputPath -Parent
if (-not (Test-Path $backupDir)) {
    New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
    Write-Host "✅ Pasta de backups criada: $backupDir`n" -ForegroundColor Green
}

# Navegar para a pasta do projeto App
Push-Location "src\BioDesk.App"

try {
    Write-Host "📖 Lendo User Secrets..." -ForegroundColor Yellow
    
    # Obter lista de secrets
    $secretsList = dotnet user-secrets list 2>&1
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ ERRO: Não foi possível ler User Secrets" -ForegroundColor Red
        Write-Host $secretsList -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    # Verificar se há secrets configurados
    if ($secretsList -match "No secrets configured") {
        Write-Host "⚠️  Não há User Secrets configurados para fazer backup" -ForegroundColor Yellow
        Pop-Location
        exit 0
    }
    
    # Criar objeto JSON com os secrets
    $secrets = @{}
    
    # Parse da output do dotnet user-secrets list
    $secretsList | ForEach-Object {
        if ($_ -match "^(.+?)\s*=\s*(.+)$") {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $secrets[$key] = $value
        }
    }
    
    if ($secrets.Count -eq 0) {
        Write-Host "⚠️  Não foi possível extrair credenciais" -ForegroundColor Yellow
        Pop-Location
        exit 0
    }
    
    Write-Host "✅ Encontrados $($secrets.Count) secrets`n" -ForegroundColor Green
    
    # Converter para JSON
    $jsonContent = $secrets | ConvertTo-Json -Depth 10
    
    # Pedir senha de encriptação
    Write-Host "🔐 Para proteger o backup, defina uma senha:" -ForegroundColor Yellow
    $securePassword = Read-Host "Senha" -AsSecureString
    $confirmPassword = Read-Host "Confirmar senha" -AsSecureString
    
    # Converter SecureString para texto para comparação
    $pwd1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword))
    $pwd2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword))
    
    if ($pwd1 -ne $pwd2) {
        Write-Host "❌ ERRO: Senhas não coincidem" -ForegroundColor Red
        Pop-Location
        exit 1
    }
    
    Write-Host "`n🔒 Encriptando backup..." -ForegroundColor Yellow
    
    # Encriptar usando AES (simplificado - em produção, usar biblioteca dedicada)
    # Aqui usamos uma abordagem básica com ConvertTo-SecureString
    $encryptedContent = $jsonContent | ConvertTo-SecureString -AsPlainText -Force | 
        ConvertFrom-SecureString -SecureKey (
            [System.Text.Encoding]::UTF8.GetBytes($pwd1.PadRight(32).Substring(0, 32))
        )
    
    # Voltar para a pasta raiz
    Pop-Location
    
    # Gravar ficheiro encriptado
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputFileName = "credentials_backup_$timestamp.enc"
    $outputFullPath = Join-Path $backupDir $outputFileName
    
    $encryptedContent | Out-File -FilePath $outputFullPath -Encoding UTF8
    
    Write-Host "✅ Backup criado com sucesso!" -ForegroundColor Green
    Write-Host "   Localização: $outputFullPath`n" -ForegroundColor Gray
    
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "✅ BACKUP CONCLUÍDO!" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    Write-Host "⚠️  IMPORTANTE:" -ForegroundColor Yellow
    Write-Host "• Guarde a senha do backup em local seguro" -ForegroundColor White
    Write-Host "• NÃO faça commit deste ficheiro para o Git" -ForegroundColor White
    Write-Host "• Para restaurar: use RestaurarCredenciais.ps1`n" -ForegroundColor White
    
} catch {
    Write-Host "`n❌ ERRO ao criar backup: $_" -ForegroundColor Red
    Pop-Location
    exit 1
}
