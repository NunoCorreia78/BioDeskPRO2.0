# 🚀 COMANDOS EXATOS - NOVO PC
# ===================================
# COPIAR E COLAR ESTES COMANDOS NO NOVO PC

# ============================
# 1️⃣ INSTALAR SOFTWARE
# ============================

# BAIXAR E INSTALAR:
# - .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0
# - VS Code: https://code.visualstudio.com/
# - No VS Code: Ctrl+Shift+X → instalar "C# Dev Kit"

# ============================
# 2️⃣ CONFIGURAR GIT
# ============================

git config --global user.name "Nuno Correia"
git config --global user.email "teu.email@gmail.com"

# Verificar configuração:
git config --global --list

# ============================
# 3️⃣ CLONAR PROJETO
# ============================

# Navegar para pasta de trabalho:
cd "C:\Users\%USERNAME%\Documents"

# Clonar repositório GitHub:
git clone https://github.com/NunoCorreia78/BioDeskPRO2.0.git

# Entrar na pasta:
cd BioDeskPRO2.0

# ============================
# 4️⃣ SETUP AUTOMÁTICO
# ============================

# Executar script automático:
.\SETUP_NOVO_PC.bat

# OU comandos manuais:
dotnet restore
dotnet build
dotnet run --project src/BioDesk.App

# ============================
# 5️⃣ VERIFICAÇÃO FINAL
# ============================

# DEVE APARECER:
# ✅ Dashboard abre automaticamente
# ✅ Clicar "➕ Novo Paciente" funciona
# ✅ TAB 2: "📋 Declaração & Anamnese" existe
# ✅ 11 EXPANDERS médicos aparecem
# ✅ Chips clicáveis + sliders funcionam

# 🎉 SUCESSO! Sistema médico completo funcionando!

# ============================
# 🆘 TROUBLESHOOTING
# ============================

# Se erro de compilação:
dotnet clean
dotnet restore
dotnet build

# Se erro de runtime:
# Verificar que .NET 8 está instalado:
dotnet --version

# Se problemas de Git:
# Verificar configuração:
git remote -v
git status

# ============================
# 📞 SUPORTE
# ============================

# Se algo falhar:
# 1. Verificar que .NET 8 SDK está instalado
# 2. Verificar que C# Dev Kit está no VS Code  
# 3. Executar comandos um por vez
# 4. Verificar erros no terminal

echo "Setup completo! Sistema médico pronto!"