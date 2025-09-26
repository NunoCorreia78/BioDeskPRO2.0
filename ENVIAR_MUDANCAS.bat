@echo off
echo 📤 BioDeskPro2 - Enviar Mudancas para GitHub
echo =============================================

echo.
echo 📊 Verificando mudancas locais...
git status

echo.
echo ➕ Adicionando todas as mudancas...
git add .

echo.
echo 📝 Fazendo commit das mudancas...
set /p commit_msg="💬 Digite a mensagem do commit: "
if "%commit_msg%"=="" set commit_msg=Trabalho do dia %date%

git commit -m "%commit_msg%"

if errorlevel 1 (
    echo ⚠️  Nenhuma mudanca para commit ou erro no commit
    pause
    exit /b 1
)

echo.
echo 📤 Enviando para GitHub...
git push origin main

if errorlevel 1 (
    echo ❌ ERRO: Push para GitHub falhou!
    echo 🔍 Verifique conexao internet e credentials
    pause
    exit /b 1
)

echo.
echo ✅ SUCESSO! Mudancas enviadas para GitHub!
echo 🔄 Agora pode sincronizar no outro PC!

pause