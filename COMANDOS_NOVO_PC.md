# 🚀 COMANDOS COMPLETOS PARA O NOVO PC

## 🎯 TUDO O QUE PRECISAS FAZER NO NOVO PC:

### **1️⃣ INSTALAR SOFTWARE (15 minutos)**

```bash
# 1. Baixar e instalar .NET 8 SDK:
# https://dotnet.microsoft.com/download/dotnet/8.0
# Escolher: ".NET 8.0 SDK" (não Runtime!)

# 2. Baixar e instalar VS Code:
# https://code.visualstudio.com/
# Depois: Ctrl+Shift+X → pesquisar "C# Dev Kit" → Install

# 3. Verificar instalações:
dotnet --version  # Deve mostrar 8.0.x
code --version    # Deve mostrar versão VS Code
```

### **2️⃣ CONFIGURAR GIT (2 minutos)**

```bash
# Configurar identidade Git:
git config --global user.name "Nuno Correia"
git config --global user.email "teu.email@gmail.com"

# Verificar configuração:
git config --global --list
```

### **3️⃣ CRIAR REPOSITÓRIO GITHUB (3 minutos)**

```
1. Ir a: https://github.com
2. Clicar: "New repository" (botão verde +)
3. Nome: BioDeskPro2-Medical-System
4. ✅ Marcar "Private" (código médico sensível)
5. ❌ NÃO marcar "Add README" (já existe)
6. Clicar: "Create repository"
7. COPIAR a URL que aparece (exemplo: https://github.com/teu-username/BioDeskPro2-Medical-System.git)
```

### **4️⃣ COMANDOS NO PC ATUAL (AGORA!)**

```bash
# Execute AGORA no teu PC atual:
git remote add origin https://github.com/SEU_USERNAME/BioDeskPro2-Medical-System.git
git branch -M main  
git push -u origin main
```

**⚠️ SUBSTITUIR "SEU_USERNAME" pela tua conta GitHub!**

### **5️⃣ COMANDOS NO NOVO PC (depois do push)**

```bash
# Navegar para pasta de trabalho:
cd "C:\Users\SEU_USER\Documents"

# Clonar repositório (substituir SEU_USERNAME):
git clone https://github.com/SEU_USERNAME/BioDeskPro2-Medical-System.git

# Entrar na pasta:
cd BioDeskPro2-Medical-System

# Setup automático:
.\SETUP_NOVO_PC.bat

# OU manualmente:
dotnet restore
dotnet build  
dotnet run --project src/BioDesk.App
```

### **6️⃣ VERIFICAÇÃO FINAL**

✅ **DEVE APARECER:**
- Dashboard abre automaticamente
- Clique "➕ Novo Paciente"
- TAB 2: "📋 Declaração & Anamnese"  
- 11 EXPANDERS médicos funcionais
- Chips clicáveis + sliders

---

## 📋 RESUMO ULTRA-RÁPIDO:

### **NO PC ATUAL (AGORA):**
```bash
# Só substituir SEU_USERNAME:
git remote add origin https://github.com/SEU_USERNAME/BioDeskPro2-Medical-System.git
git push -u origin main
```

### **NO NOVO PC:**
```bash
# 1. Instalar: .NET 8 + VS Code + C# Dev Kit
# 2. Git config user.name e user.email  
# 3. git clone https://github.com/SEU_USERNAME/BioDeskPro2-Medical-System.git
# 4. cd BioDeskPro2-Medical-System
# 5. .\SETUP_NOVO_PC.bat
```

## 🎉 RESULTADO: 
**Sistema médico completo funcionando no novo PC em ~25 minutos!** 🩺✨