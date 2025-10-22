# Script de Migração de Credenciais - BioDeskPro2
# Migra credenciais do appsettings.json para User Secrets
# Data: 21 de Outubro de 2025

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "🔒 MIGRAÇÃO DE CREDENCIAIS - BioDeskPro2" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

# Verificar se está na pasta raiz do projeto
if (-not (Test-Path "BioDeskPro2.sln")) {
    Write-Host "❌ ERRO: Execute este script a partir da pasta raiz do projeto (onde está BioDeskPro2.sln)" -ForegroundColor Red
    exit 1
}

# Caminho para o appsettings.json
$appSettingsPath = "src\BioDesk.App\appsettings.json"

if (-not (Test-Path $appSettingsPath)) {
    Write-Host "❌ ERRO: Ficheiro appsettings.json não encontrado em $appSettingsPath" -ForegroundColor Red
    exit 1
}

Write-Host "📖 Lendo credenciais de $appSettingsPath..." -ForegroundColor Yellow

try {
    # Ler o ficheiro JSON
    $appSettings = Get-Content $appSettingsPath -Raw | ConvertFrom-Json
    
    # Extrair credenciais de email
    $emailSender = $appSettings.Email.Sender
    $emailPassword = $appSettings.Email.Password
    $emailFromEmail = $appSettings.Email.FromEmail
    $emailFromName = $appSettings.Email.FromName
    
    # Verificar se há credenciais para migrar
    if ([string]::IsNullOrWhiteSpace($emailPassword)) {
        Write-Host "ℹ️ Não há credenciais para migrar (campo Password está vazio)" -ForegroundColor Yellow
        Write-Host "`nPara configurar manualmente:" -ForegroundColor Cyan
        Write-Host "  1. cd src\BioDesk.App" -ForegroundColor Gray
        Write-Host "  2. dotnet user-secrets set `"Email:Sender`" `"seu-email@gmail.com`"" -ForegroundColor Gray
        Write-Host "  3. dotnet user-secrets set `"Email:Password`" `"sua-app-password`"" -ForegroundColor Gray
        Write-Host "  4. dotnet user-secrets set `"Email:FromEmail`" `"seu-email@gmail.com`"" -ForegroundColor Gray
        Write-Host "  5. dotnet user-secrets set `"Email:FromName`" `"Seu Nome`"" -ForegroundColor Gray
        exit 0
    }
    
    Write-Host "✅ Credenciais encontradas:" -ForegroundColor Green
    Write-Host "   Email: $emailSender" -ForegroundColor Gray
    Write-Host "   Password: $('*' * $emailPassword.Length) (oculto)" -ForegroundColor Gray
    Write-Host "   FromName: $emailFromName`n" -ForegroundColor Gray
    
    # Confirmar migração
    $confirmacao = Read-Host "Deseja migrar estas credenciais para User Secrets? (S/N)"
    
    if ($confirmacao -ne "S" -and $confirmacao -ne "s") {
        Write-Host "❌ Migração cancelada pelo utilizador" -ForegroundColor Red
        exit 0
    }
    
    # Navegar para a pasta do projeto App
    Push-Location "src\BioDesk.App"
    
    Write-Host "`n🔧 Configurando User Secrets..." -ForegroundColor Yellow
    
    # Configurar cada valor
    dotnet user-secrets set "Email:Sender" $emailSender
    dotnet user-secrets set "Email:Password" $emailPassword
    dotnet user-secrets set "Email:FromEmail" $emailFromEmail
    dotnet user-secrets set "Email:FromName" $emailFromName
    
    # Voltar para a pasta raiz
    Pop-Location
    
    Write-Host "`n✅ User Secrets configurados com sucesso!" -ForegroundColor Green
    
    # Listar os secrets configurados (sem mostrar valores)
    Write-Host "`n📋 Verificando configuração..." -ForegroundColor Yellow
    Push-Location "src\BioDesk.App"
    dotnet user-secrets list
    Pop-Location
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "✅ MIGRAÇÃO CONCLUÍDA COM SUCESSO!" -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    Write-Host "⚠️  PRÓXIMOS PASSOS IMPORTANTES:" -ForegroundColor Yellow
    Write-Host "1. As credenciais agora estão em User Secrets (fora do projeto)" -ForegroundColor White
    Write-Host "2. NUNCA faça commit do ficheiro appsettings.json com passwords" -ForegroundColor White
    Write-Host "3. Outros desenvolvedores precisarão configurar seus próprios User Secrets" -ForegroundColor White
    Write-Host "4. Consultar CONFIGURACAO_SEGURA_EMAIL.md para mais informações`n" -ForegroundColor White
    
    Write-Host "📖 Documentação: CONFIGURACAO_SEGURA_EMAIL.md" -ForegroundColor Cyan
    
} catch {
    Write-Host "`n❌ ERRO ao processar appsettings.json: $_" -ForegroundColor Red
    exit 1
}
