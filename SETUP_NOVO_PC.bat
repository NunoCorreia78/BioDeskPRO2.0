@echo off
echo 🚀 BioDeskPro2 - Setup Automatico no Novo PC
echo ================================================

echo.
echo ⚡ 1/4 - Verificando .NET 8...
dotnet --version
if errorlevel 1 (
    echo ❌ ERRO: .NET 8 nao encontrado!
    echo 📥 Baixe em: https://dotnet.microsoft.com/download/dotnet/8.0
    pause
    exit /b 1
)

echo.
echo ⚡ 2/4 - Restaurando dependencias...
dotnet restore
if errorlevel 1 (
    echo ❌ ERRO: dotnet restore falhou!
    pause
    exit /b 1
)

echo.
echo ⚡ 3/4 - Compilando projeto...
dotnet build
if errorlevel 1 (
    echo ❌ ERRO: dotnet build falhou!
    pause
    exit /b 1
)

echo.
echo ⚡ 4/4 - Executando sistema medico...
echo 🩺 O BioDeskPro2 vai abrir com 11 expanders medicos!
dotnet run --project src/BioDesk.App

echo.
echo ✅ SUCESSO! Sistema medico funcionando no novo PC!
pause