@echo off
echo 🔄 BioDeskPro2 - Sincronizacao PC Atual
echo =========================================

echo.
echo 📥 Baixando mudancas do repositorio GitHub...
git fetch origin

echo.
echo 📊 Verificando se ha atualizacoes...
git status

echo.
echo 🔽 Puxando mudancas do GitHub...
git pull origin main

if errorlevel 1 (
    echo.
    echo ⚠️  CONFLITO DETECTADO!
    echo 🛠️  Execute manualmente:
    echo     git status
    echo     git merge
    echo     Resolva conflitos no VS Code
    echo     git add . && git commit
    pause
    exit /b 1
)

echo.
echo 🔧 Testando build apos sincronizacao...
dotnet build

if errorlevel 1 (
    echo ❌ ERRO: Build falhou apos sincronizacao!
    echo 🔍 Verifique os logs acima
    pause
    exit /b 1
)

echo.
echo ✅ SUCESSO! PC atual sincronizado com novo PC!
echo 🩺 Sistema medico atualizado e funcionando!

pause