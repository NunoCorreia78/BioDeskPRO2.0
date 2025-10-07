# 📧 CONFIGURAR CREDENCIAIS DE EMAIL - BioDeskPro2
# Este script configura as credenciais SMTP para envio de emails

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   📧 CONFIGURAÇÃO DE EMAIL - BioDeskPro2" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# Verificar se está na pasta correta
if (-not (Test-Path "src/BioDesk.App/BioDesk.App.csproj")) {
    Write-Host "❌ ERRO: Execute este script na pasta raiz do projeto!" -ForegroundColor Red
    Write-Host "   (Deve conter src/BioDesk.App/)" -ForegroundColor Yellow
    exit 1
}

Write-Host "ℹ️  IMPORTANTE: Para Gmail, use uma App Password, não a password normal!" -ForegroundColor Yellow
Write-Host "   Como obter: https://myaccount.google.com/apppasswords" -ForegroundColor Gray
Write-Host ""

# Solicitar email
$email = Read-Host "📧 Email do remetente (ex: seu-email@gmail.com)"
if ([string]::IsNullOrWhiteSpace($email)) {
    Write-Host "❌ Email não pode estar vazio!" -ForegroundColor Red
    exit 1
}

# Solicitar App Password
$password = Read-Host "🔑 App Password do Gmail (16 caracteres, sem espaços)" -AsSecureString
$passwordPlainText = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
)

if ([string]::IsNullOrWhiteSpace($passwordPlainText)) {
    Write-Host "❌ Password não pode estar vazia!" -ForegroundColor Red
    exit 1
}

# Remover espaços da password (caso utilizador tenha copiado com espaços)
$passwordPlainText = $passwordPlainText.Replace(" ", "")

# Solicitar nome (opcional)
$nome = Read-Host "👤 Nome do remetente (opcional, pressione Enter para usar 'BioDeskPro')"
if ([string]::IsNullOrWhiteSpace($nome)) {
    $nome = "BioDeskPro - Terapias Naturais"
}

Write-Host ""
Write-Host "───────────────────────────────────────────────────────" -ForegroundColor Gray
Write-Host "📝 Resumo da configuração:" -ForegroundColor Cyan
Write-Host "   Email:    $email" -ForegroundColor White
Write-Host "   Password: **************** (oculta)" -ForegroundColor White
Write-Host "   Nome:     $nome" -ForegroundColor White
Write-Host "───────────────────────────────────────────────────────" -ForegroundColor Gray
Write-Host ""

$confirmacao = Read-Host "Confirma a configuração? (S/N)"
if ($confirmacao -ne "S" -and $confirmacao -ne "s") {
    Write-Host "❌ Configuração cancelada." -ForegroundColor Yellow
    exit 0
}

Write-Host ""
Write-Host "🔧 A configurar User Secrets..." -ForegroundColor Cyan

# Configurar secrets
try {
    dotnet user-secrets set "Email:Sender" "$email" --project src/BioDesk.App
    dotnet user-secrets set "Email:Password" "$passwordPlainText" --project src/BioDesk.App
    dotnet user-secrets set "Email:SenderName" "$nome" --project src/BioDesk.App
    
    Write-Host ""
    Write-Host "✅ Configuração concluída com sucesso!" -ForegroundColor Green
    Write-Host ""
    Write-Host "───────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host "🧪 PRÓXIMOS PASSOS:" -ForegroundColor Cyan
    Write-Host "   1. Execute a aplicação: dotnet run --project src/BioDesk.App" -ForegroundColor White
    Write-Host "   2. Vá a Configurações (⚙️)" -ForegroundColor White
    Write-Host "   3. Clique em '🧪 Testar Conexão'" -ForegroundColor White
    Write-Host "   4. Verifique se recebe o email de teste" -ForegroundColor White
    Write-Host "───────────────────────────────────────────────────────" -ForegroundColor Gray
    Write-Host ""
    Write-Host "📋 Para ver as configurações:" -ForegroundColor Gray
    Write-Host "   dotnet user-secrets list --project src/BioDesk.App" -ForegroundColor DarkGray
    Write-Host ""
}
catch {
    Write-Host "❌ ERRO ao configurar secrets: $_" -ForegroundColor Red
    exit 1
}

# Limpar variável da password da memória
Remove-Variable passwordPlainText
