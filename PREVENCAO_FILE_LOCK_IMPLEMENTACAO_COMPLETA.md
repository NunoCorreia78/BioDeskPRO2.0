# BioDeskPro2 - Prevenção de File Lock Errors

## 🎯 Problema Resolvido

**File Lock Error** acontece quando:
- Aplicação BioDeskPro2 está em execução (processo WPF)
- `dotnet build` tenta substituir o executável `BioDesk.App.exe`
- Windows bloqueia o ficheiro para proteger o processo ativo
- Build falha após 10 tentativas de retry

## ✅ Soluções Implementadas

### 1. **Tasks VS Code Inteligentes**
Novas tasks disponíveis no Command Palette (`Ctrl+Shift+P` → "Tasks"):

- **`Smart Build BioDeskPro2`** - Para processos automaticamente antes de build
- **`Smart Run BioDeskPro2`** - Para, faz build e executa
- **`Hot Reload BioDeskPro2`** - Desenvolvimento contínuo (recompila automaticamente)
- **`Stop All BioDesk Processes`** - Para todos os processos manualmente
- **`PowerShell Smart Build`** - Usa script avançado PowerShell
- **`PowerShell Smart Run`** - Script PowerShell + execução

### 2. **Script PowerShell Avançado**
**Localização**: `scripts/smart-build.ps1`

**Funcionalidades**:
- ✅ Detecta processos BioDesk automaticamente
- ✅ Para processos com informação detalhada (PID, nome)
- ✅ Verifica se ficheiro está bloqueado
- ✅ Força desbloqueio de processos .NET ocultos
- ✅ Executa build/restore/test/run conforme parâmetros
- ✅ Feedback colorido no terminal

**Uso**:
```powershell
# Build básico
powershell -ExecutionPolicy Bypass -File scripts/smart-build.ps1

# Build + Run
powershell -ExecutionPolicy Bypass -File scripts/smart-build.ps1 -Run

# Build + Test
powershell -ExecutionPolicy Bypass -File scripts/smart-build.ps1 -Test

# Limpeza completa + Build
powershell -ExecutionPolicy Bypass -File scripts/smart-build.ps1 -Clean
```

### 3. **Launch Configurations (Debug)**
**Localização**: `.vscode/launch.json`

**Configurações**:
- **`BioDesk.App (Smart Debug)`** - Para processos antes de debugger
- **`BioDesk.App (Original)`** - Configuração original mantida
- **`Hot Reload Development`** - Debugging com hot reload

### 4. **Prevenção de Múltiplas Instâncias**
**Localização**: `src/BioDesk.App/App.xaml.cs`

**Implementação**:
- ✅ Mutex global `BioDeskPro2_SingleInstance_Mutex`
- ✅ Verifica se já existe instância ao iniciar
- ✅ Mostra aviso friendly se tentar abrir segunda instância
- ✅ Liberta mutex automaticamente ao fechar aplicação

**Código**:
```csharp
private static Mutex? _mutex;

protected override async void OnStartup(StartupEventArgs e)
{
    const string mutexName = "BioDeskPro2_SingleInstance_Mutex";
    _mutex = new Mutex(true, mutexName, out bool createdNew);

    if (!createdNew)
    {
        MessageBox.Show("BioDeskPro2 já está em execução!");
        Current.Shutdown();
        return;
    }
    // ... resto do startup
}
```

## 🔧 Workflows Recomendados

### **Para Desenvolvimento Ativo (Recomendado)**
```bash
# 1. Usar Hot Reload para desenvolvimento contínuo
Task: "Hot Reload BioDeskPro2"
# Vantagens: Recompila automaticamente, nunca bloqueia ficheiros
```

### **Para Build/Test Ocasional**
```bash
# 2. Usar Smart Build quando precisar de build manual
Task: "Smart Build BioDeskPro2"
# Vantagens: Para processos automaticamente, build sempre funciona
```

### **Para Debugging**
```bash
# 3. Usar Smart Debug configuration
F5 → Selecionar "BioDesk.App (Smart Debug)"
# Vantagens: Para processos antes de attach debugger
```

### **Para Resolução Manual**
```bash
# 4. Task manual para emergências
Task: "Stop All BioDesk Processes"
# Uso: Quando algo fica "preso" e precisa parar manualmente
```

## 📊 Tipos de Processos que São Detectados

1. **Processo Principal**: `BioDesk.App.exe` (aplicação WPF)
2. **Processos .NET**: `dotnet.exe` executando BioDeskPro2
3. **Processos Temporários**: Processos de debugging/build
4. **Processos Órfãos**: Processos que ficaram "pendurados"

## ⚡ Benefícios da Implementação

### **Prevenção Automática**
- ✅ **Zero file lock errors** - Nunca mais falhas de build
- ✅ **Feedback claro** - Informa qual processo foi parado
- ✅ **Detecção inteligente** - Identifica processos relacionados

### **Melhoria do Workflow**
- ✅ **Hot reload** - Desenvolvimento mais rápido
- ✅ **Tasks inteligentes** - Um clique resolve tudo
- ✅ **Debug seguro** - Debugger nunca bloqueia

### **Robustez**
- ✅ **Múltiplas camadas** - Tasks, script, mutex, launch configs
- ✅ **Fallback automático** - Se uma solução falha, tenta outra
- ✅ **Compatibilidade** - Mantém tasks originais funcionais

## 🎮 Como Usar

### **Dia-a-dia (Mais Comum)**
1. Abrir VS Code
2. `Ctrl+Shift+P` → "Tasks: Run Task"
3. Escolher **"Hot Reload BioDeskPro2"**
4. Desenvolver normalmente - recompila automaticamente

### **Build Esporádico**
1. `Ctrl+Shift+P` → "Tasks: Run Task"
2. Escolher **"Smart Build BioDeskPro2"**
3. Build sempre funciona - para processos automaticamente

### **Debugging**
1. `F5`
2. Escolher **"BioDesk.App (Smart Debug)"**
3. Debug funciona - para processos antes de attach

### **Emergência**
1. `Ctrl+Shift+P` → "Tasks: Run Task"
2. Escolher **"Stop All BioDesk Processes"**
3. Para tudo manualmente

## 📝 Log de Exemplo

```
BioDeskPro2 Smart Build
Timestamp: 2025-10-29 11:01:26

Verificando processos BioDesk em execucao...
Encontrados 1 processo(s) BioDesk:
  - PID 2916: BioDesk.App
    Processo 2916 terminado com sucesso

Restaurando pacotes...
[... warnings AForge normais ...]

Compilando projeto...
[... build success ...]

Operacao concluida com sucesso!
```

## 🚀 Resultado Final

**NUNCA MAIS FILE LOCK ERRORS!**

O sistema agora é à prova de falhas - detecta, para e resolve automaticamente qualquer conflito de processos antes que cause problemas de build.
