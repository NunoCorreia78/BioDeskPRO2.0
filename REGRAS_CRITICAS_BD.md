# 🚨 REGRAS CRÍTICAS - BASE DE DADOS

**Data:** 14 de Outubro de 2025 22:30
**Motivo:** Perda de dados por alteração incorreta do PathService

---

## ⛔ **NUNCA, EM NENHUMA CIRCUNSTÂNCIA:**

### 1. ❌ **NUNCA ALTERAR PathService.cs**
- **Ficheiro:** `src/BioDesk.Services/PathService.cs`
- **Razão:** Qualquer alteração muda a localização da BD e causa perda de dados
- **Status:** ✅ **BLOQUEADO - NÃO TOCAR**

```csharp
// ✅ ESTE CÓDIGO ESTÁ CORRETO E NÃO PODE SER ALTERADO
private static readonly bool IsDebugMode = Debugger.IsAttached ||
    AppContext.BaseDirectory.Contains("BioDeskPro2", StringComparison.OrdinalIgnoreCase);
```

### 2. ❌ **NUNCA ALTERAR DatabasePath**
```csharp
// ✅ CORRETO - NÃO ALTERAR
public static string DatabasePath => Path.Combine(AppDataPath, "biodesk.db");
```

### 3. ❌ **NUNCA ALTERAR App.xaml.cs - Linha DbContext**
```csharp
// ✅ CORRETO - NÃO ALTERAR
services.AddDbContext<BioDeskDbContext>(options =>
    options.UseSqlite($"Data Source={PathService.DatabasePath}"));
```

---

## ✅ **LOCALIZAÇÕES DA BASE DE DADOS**

### **Modo Debug (Desenvolvimento no VS Code):**
```
# Exemplo: defina $ProjectPath para o local do projecto. Por exemplo:
#   $ProjectPath = "D:\\BioDeskPro2"  # disco externo
#   $ProjectPath = "C:\\Users\\<USERNAME>\\OneDrive\\Documentos\\BioDeskPro2"  # OneDrive
$ProjectPath\biodesk.db
```

### **Modo Release (Aplicação Instalada):**
```
C:\ProgramData\BioDeskPro2\biodesk.db
```

### **⚠️ CRÍTICO:**
- **AMBAS** as BDs têm de ser **SEMPRE IGUAIS**
- **QUALQUER** alteração de código deve copiar BD entre as duas localizações
- **BACKUP AUTOMÁTICO** funciona - usar SEMPRE quando necessário

---

## 🔒 **PROCEDIMENTO OBRIGATÓRIO ANTES DE QUALQUER ALTERAÇÃO**

### **ANTES de alterar QUALQUER código:**

1. ✅ **Fazer backup manual:**
    ```powershell
    # Defina $ProjectPath para o local do projecto antes de executar
    Copy-Item "$ProjectPath\biodesk.db" `
                 "$ProjectPath\Backups\MANUAL_$(Get-Date -Format 'yyyyMMdd_HHmmss').db"
    ```

2. ✅ **Verificar tamanho da BD:**
   ```powershell
   Get-Item "$ProjectPath\biodesk.db" |
       Select-Object @{Name='Size(KB)';Expression={[math]::Round($_.Length/1KB,2)}}
   ```

3. ✅ **Se > 700 KB → TEM DADOS IMPORTANTES**

---

## 🛡️ **SISTEMA DE BACKUP AUTOMÁTICO**

### **Backup ao fechar aplicação:**
### ✅ **Funciona automaticamente** em `App.xaml.cs` → `OnExit()`
### ✅ **Localização:** `$ProjectPath\Backups\` (ou `C:\ProgramData\BioDeskPro2\Backups` em Release)
### ✅ **Formato:** `BioDeskBackup_YYYYMMDD_HHmmss.zip`
### ✅ **Mantém últimos 10 backups** automaticamente

### **Restore de Backup (pela App):**
1. ✅ Menu Configurações → Backup/Restore
2. ✅ Selecionar backup `.zip`
3. ✅ Restaurar automaticamente
4. ✅ **FUNCIONA NA PERFEIÇÃO** ✅

---

## 📋 **CHECKLIST DE SEGURANÇA**

Antes de qualquer commit de código:

- [ ] PathService.cs foi alterado? **SE SIM → REVERTER IMEDIATAMENTE**
- [ ] DatabasePath foi alterado? **SE SIM → REVERTER IMEDIATAMENTE**
- [ ] App.xaml.cs DbContext foi alterado? **SE SIM → REVERTER IMEDIATAMENTE**
- [ ] Backup manual criado? **SE NÃO → CRIAR AGORA**
- [ ] BD testada após alteração? **SE NÃO → TESTAR AGORA**
- [ ] Tamanho da BD verificado? **SE NÃO → VERIFICAR AGORA**

---

## 🚨 **EM CASO DE PERDA DE DADOS**

### **Procedimento de Emergência:**

1. ✅ **NÃO FECHAR A APP** se tiver dados visíveis
2. ✅ **Usar Restore da App** imediatamente
3. ✅ **Procurar backup mais recente:**
   ```powershell
   Get-ChildItem "$ProjectPath\Backups" |
       Sort-Object LastWriteTime -Descending |
       Select-Object -First 5 Name, LastWriteTime
   ```
4. ✅ **Extrair backup e copiar BD:**
   ```powershell
    Expand-Archive "$ProjectPath\Backups\[BACKUP].zip" -DestinationPath "TEMP"
    Copy-Item "TEMP\biodesk.db" "C:\ProgramData\BioDeskPro2\biodesk.db" -Force
   ```

---

## 📝 **HISTÓRICO DE INCIDENTES**

### **14/10/2025 21:51 - PERDA DE DADOS**
- **Causa:** Alteração de `PathService.cs` - mudança de `Directory.GetCurrentDirectory()` para `AppContext.BaseDirectory`
- **Consequência:** App criou BD nova vazia, perdeu acesso aos 20+ pacientes
- **Solução:** Restore de backup funcionou perfeitamente
- **Lição:** **NUNCA MAIS ALTERAR PathService.cs**

---

## ✅ **REGRA DE OURO**

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  SE FUNCIONA E OS DADOS ESTÃO SEGUROS:                   ║
║                                                           ║
║  ██╗  ██╗ ██████╗    ████████╗ ██████╗ ██╗   ██╗███████╗ ║
║  ██║  ██║██╔═══██╗   ╚══██╔══╝██╔═══██╗██║   ██║██╔════╝ ║
║  ███████║██║   ██║█████╗██║   ██║   ██║██║   ██║█████╗   ║
║  ██╔══██║██║   ██║╚════╝██║   ██║   ██║██║   ██║██╔══╝   ║
║  ██║  ██║╚██████╔╝      ██║   ╚██████╔╝╚██████╔╝███████╗ ║
║  ╚═╝  ╚═╝ ╚═════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ ║
║                                                           ║
║  NÃO TOCAR!                                               ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

---

**Este documento é OBRIGATÓRIO e VINCULATIVO para todos os agentes de IA futuros.**

**Violação destas regras = PERDA DE DADOS DO UTILIZADOR**

**✅ Sistema de Backup funciona perfeitamente - USAR SEMPRE!**
