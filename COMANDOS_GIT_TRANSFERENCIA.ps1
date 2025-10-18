# ========================================
# COMANDOS GIT - PREPARAÇÃO TRANSFERÊNCIA
# ========================================
# Data: 18/10/2025
# Executar LINHA A LINHA no PC ANTIGO

# ========================================
# PASSO 1: Pull commits remotos
# ========================================
git pull origin copilot/vscode1760742399628

# ========================================
# PASSO 2: Adicionar ficheiros ao staging
# ========================================

# Ficheiros modificados
git add DEBUG_DOCUMENTOS.txt
git add src/BioDesk.App/BioDesk.App.csproj
git add src/BioDesk.App/Views/Terapia/EmissaoConfiguracaoUserControl.xaml
git add src/BioDesk.App/Views/Terapia/ProgramasView.xaml.cs
git add src/BioDesk.Services/Audio/FrequencyEmissionService.cs
git add src/BioDesk.Services/Hardware/TiePie/HS3Native.cs
git add src/BioDesk.Services/Hardware/TiePie/TiePieHS3Service.cs
git add src/BioDesk.ViewModels/UserControls/Terapia/EmissaoConfiguracaoViewModel.cs

# Ficheiros novos
git add Debug_Scripts/ListarExports_HS3.ps1
git add GUIA_TRANSFERENCIA_PC_18OUT2025.md
git add CHECKLIST_TRANSFERENCIA_PC_18OUT2025.md
git add Scripts/SetupPCNovo.ps1

# Ficheiro deletado
git rm src/BioDesk.ViewModels/Debug/TesteHS3ViewModel.cs

# ========================================
# PASSO 3: Commit
# ========================================
git commit -m "✨ Preparação para transferência PC - Integração TiePie HS3 completa

- ✅ 150 testes passaram
- ✅ Build sem erros (0 errors)
- ✅ Backup criado: backup_20251018_120523.zip (149 MB)
- 🔧 Ajustes finais integração HS3Native
- 📝 Documentação completa de transferência
  • CHECKLIST_TRANSFERENCIA_PC_18OUT2025.md
  • GUIA_TRANSFERENCIA_PC_18OUT2025.md
  • SetupPCNovo.ps1 (script automático PC novo)
- 🗑️ Remoção TesteHS3ViewModel (componente debug)
- 🔍 Debug script ListarExports_HS3.ps1"

# ========================================
# PASSO 4: Push para GitHub
# ========================================
git push origin copilot/vscode1760742399628

# ========================================
# PASSO 5: Verificar no GitHub
# ========================================
# Abrir: https://github.com/NunoCorreia78/BioDeskPRO2.0/tree/copilot/vscode1760742399628
# Verificar que o commit apareceu

# ========================================
# ✅ PRONTO PARA TRANSFERIR!
# ========================================
