# 🚀 Setup Rápido - Novo PC

## ⚡ Quick Start (5 minutos)

### 1️⃣ Clone Repositório
```bash
git clone https://github.com/NunoCorreia78/BioDeskPRO2.0.git
cd BioDeskPro2
```

### 2️⃣ Verificar Pré-requisitos
```bash
# .NET 8 SDK (obrigatório)
dotnet --version
# Resultado esperado: 8.0.x

# Se não tiver, instalar:
# https://dotnet.microsoft.com/download/dotnet/8.0
```

### 3️⃣ Build & Run
```bash
# Limpar + Restaurar + Build
dotnet clean
dotnet restore
dotnet build --no-incremental

# Executar aplicação
dotnet run --project src/BioDesk.App
```

**Resultado Esperado**:
- ✅ Build: 0 Errors
- ⚠️ Build: 37 Warnings (normais - AForge compatibility)
- 🚀 App abre no Dashboard

---

## 📋 Último Estado (06/10/2025)

### ✅ Commits Recentes
- **`5fa0608`** - docs: Resumo sessão 06/10/2025
- **`771d80e`** - fix: Movimento mapa iridológico ⭐ **ÚLTIMAS CORREÇÕES**
- **`30f0640`** - feat: Ferramenta de desenho

### 🐛 Bugs Corrigidos (771d80e)
1. ✅ Movimento vertical invertido
2. ✅ Movimento jerky (solavancos)

### 🧪 Testar Prioridade
1. **Irisdiagnóstico** → Carregar imagem → Mover mapa
   - Mouse CIMA → Mapa CIMA ✅
   - Movimento FLUIDO (sem saltos) ✅

---

## 🔧 VS Code Setup

### Abrir Projecto
```bash
code .
```

### Extensões Recomendadas (auto-install)
- C# Dev Kit (ms-dotnettools.csdevkit)
- C# (ms-dotnettools.csharp)
- NuGet Package Manager

### Configurações Importantes
- **`.vscode/settings.json`** - IntelliSense C# otimizado
- **`omnisharp.json`** - Roslyn analyzers habilitados
- **`.editorconfig`** - 88 regras CA configuradas

---

## 📂 Estrutura do Projecto

```
BioDeskPro2/
├── src/
│   ├── BioDesk.App/          # 🖥️ WPF UI (Views, Controls, Dialogs)
│   ├── BioDesk.ViewModels/   # 🎯 MVVM ViewModels + Commands
│   ├── BioDesk.Domain/       # 📦 Entidades (Paciente, Consulta...)
│   ├── BioDesk.Data/         # 💾 EF Core + SQLite
│   ├── BioDesk.Services/     # ⚙️ Serviços (Navegação, Email, Camera)
│   └── BioDesk.Tests/        # ✅ Testes unitários
├── biodesk.db               # 📊 Base de dados SQLite
├── global.json              # 🔒 SDK fixo (.NET 8)
└── RESUMO_SESSAO_*.md       # 📝 Histórico de sessões
```

---

## 🎯 Funcionalidades Principais

### ✅ Completamente Funcionais
1. **Dashboard** - Visão geral, estatísticas
2. **Gestão Pacientes** - CRUD completo, pesquisa
3. **Ficha Clínica** - 5 tabs (Biográficos, Saúde, Consentimentos, Registo, Comunicação)
4. **Irisdiagnóstico** - ⭐ Análise iris + overlay + desenho + calibração
5. **Sistema E-mails** - Templates, envios agendados, histórico
6. **Configurações** - SMTP, pastas documentais, preferências

### 🚧 Em Desenvolvimento
- Tab 3 - Medicina Complementar (roadmap definido)

---

## 🆘 Troubleshooting

### Erro: "InitializeComponent não existe"
```bash
# Solução:
dotnet clean
dotnet restore
dotnet build --no-incremental
```

### Erro: Base de dados não encontrada
- **Localização**: `BioDeskPro2/biodesk.db`
- Será criada automaticamente no primeiro arranque
- Seed de 3 pacientes incluído

### Warnings AForge (NU1701)
- ✅ **Normal**: Packages .NET Framework no .NET 8
- ✅ **Funcionam perfeitamente**: Compatibilidade testada

### IntelliSense com 170+ Erros mas Build OK
**Sintoma:** Problems Panel mostra 170+ erros mas `dotnet build` = 0 erros

**Causa:** Cache do OmniSharp (C# Language Server) desatualizado após `dotnet clean`

**Solução Rápida (10 segundos):**
1. `Ctrl+Shift+P` → "Restart C# Language Server"
2. Aguardar 10 segundos para reanálise completa
3. Problems Panel deve mostrar 0 erros

**Solução Alternativa:**
- `Ctrl+Shift+P` → "Reload Window"

**Prevenção:** Sempre reiniciar OmniSharp após `dotnet clean + build`

---

## 📖 Documentação Adicional

### Guias Técnicos
- **`RESUMO_SESSAO_06OUT2025.md`** - Sessão mais recente (LEIA PRIMEIRO!)
- **`.github/copilot-instructions.md`** - Arquitectura + regras de desenvolvimento
- **`PLANO_DESENVOLVIMENTO_RESTANTE.md`** - Roadmap futuro

### Análises Específicas
- **`ANALISE_CONTROLE_TAMANHO_IRIS.md`** - Sistema zoom/transform
- **`FASE3_IRISDIAGNOSTICO_COMPLETA.md`** - Drawing tool
- **`CHECKLIST_ANTI_ERRO_UI.md`** - Troubleshooting UI/binding

---

## 🎓 Arquitectura Rápida

### MVVM Pattern
- **Views** (XAML) → **ViewModels** (C#) → **Services** → **Data**
- **CommunityToolkit.Mvvm**: `[ObservableProperty]`, `[RelayCommand]`
- **FluentValidation**: Validação robusta

### Navegação
```csharp
INavigationService
├── NavigateTo("Dashboard")
├── NavigateTo("ListaPacientes")
├── NavigateTo("FichaPaciente")  // Requer SetPacienteAtivo()
└── NavigateTo("NovoPaciente")
```

### Base de Dados
- **SQLite** (Entity Framework Core)
- **Migrations**: Auto-aplicadas no arranque
- **Seed**: 3 pacientes de exemplo

---

## ✅ Checklist Inicial

### Antes de Começar
- [ ] .NET 8 SDK instalado
- [ ] Git configurado (user.name, user.email)
- [ ] VS Code instalado
- [ ] Repositório clonado

### Primeiro Build
- [ ] `dotnet clean` executado
- [ ] `dotnet restore` sem erros
- [ ] `dotnet build` → 0 Errors, 37 Warnings
- [ ] `dotnet run` → App abre no Dashboard

### Validação Funcional
- [ ] Dashboard abre correctamente
- [ ] Lista pacientes mostra 3 pacientes seed
- [ ] Abrir ficha de paciente
- [ ] Tab Irisdiagnóstico funciona
- [ ] Movimento mapa fluido e correcto ⭐

---

## 🚨 IMPORTANTE: Últimas Alterações

### Commit `771d80e` (06/10/2025)
**Ficheiro Modificado**: `IrisdiagnosticoUserControl.xaml.cs`

**Mudanças Críticas**:
1. Removida linha `if (scaleY < 0) { deltaY = -deltaY; }`
2. Alterado `throttle: true` → `throttle: false`

**Impacto**:
- ✅ Movimento vertical agora correcto
- ✅ Movimento fluido (sem jerky)

**Testar Obrigatoriamente** após clone!

---

## 📞 Suporte

**Repositório**: https://github.com/NunoCorreia78/BioDeskPRO2.0
**Branch**: main
**Última Sincronização**: 06/10/2025, ~23:00
**Hash Actual**: `5fa0608`

---

**🎉 WORKSPACE 100% PRONTO! BOA CODIFICAÇÃO! 🚀**
