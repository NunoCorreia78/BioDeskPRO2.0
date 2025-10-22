# 🎯 GUIA RAPIDO - Re-captura COMPLETA

## ⚠️ PROBLEMA com logs anteriores:

Os arquivos `Logfile.CSV` e `Logfile2.CSV` só capturaram:
- ❌ **2 eventos** cada (Load Image de hs3.dll)
- ❌ **Filtros muito restritivos** (só Operation="Load Image" + Path="hs3.dll")

**Resultado**: Não capturamos as operações que REALMENTE importam:
- Registry USB (VID:PID)
- CreateFile (dispositivos)
- DeviceIoControl (comunicação USB)

---

## ✅ SOLUÇÃO: Re-capturar com filtro SIMPLES

### 1️⃣ **Reconfigurar Process Monitor (2 minutos)**

No **Process Monitor**:

1. **Filter** → **Filter...**
2. **Reset** (botão no canto inferior esquerdo)
3. Adicionar **APENAS 1 FILTRO**:
   ```
   [Process Name] [is] [InergetixCoRe.exe] [Include] [Add]
   ```
4. **Apply** → **OK**

**Resultado**: Agora vai capturar **TUDO** que o CoRe faz!

---

### 2️⃣ **TESTE 1: COM Equipamento** (5 minutos)

**Preparação**:
- [x] HS3 **conectado** ao USB ✅
- [x] InergetixCoRe **fechado**
- [x] Process Monitor **aberto** (com filtro único)

**Procedimento**:
```
1. Process Monitor: Edit → Clear Display (Ctrl+X)
2. Process Monitor: Ctrl+E (lupa VERDE - iniciar captura)
3. Lançar InergetixCoRe.exe
4. Aguardar mensagem "HS3 Conectado" (~15 segundos)
5. Process Monitor: Ctrl+E (lupa CINZA - parar)
6. File → Save...
   - Events displayed using current filter: ✅
   - Format: CSV
   - Nome: LogComEquipamento.csv
   - Local: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts\
   - Save
7. Fechar CoRe
```

**✅ Verificação**: Arquivo deve ter **centenas/milhares de linhas** (não só 2!)

---

### 3️⃣ **TESTE 2: SEM Equipamento** (5 minutos)

**Preparação**:
- [x] InergetixCoRe **fechado**
- [x] HS3 **desconectado** do USB ❌
- [x] Process Monitor **aberto**

**Procedimento**:
```
1. DESCONECTAR HS3 do USB 🔌❌
2. Process Monitor: Edit → Clear Display (Ctrl+X)
3. Process Monitor: Ctrl+E (lupa VERDE - iniciar captura)
4. Lançar InergetixCoRe.exe
5. Observar erro/aviso (~15 segundos)
6. Process Monitor: Ctrl+E (lupa CINZA - parar)
7. File → Save...
   - Format: CSV
   - Nome: LogSemEquipamento.csv
   - Local: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts\
   - Save
8. Fechar CoRe
```

**✅ Verificação**: Arquivo deve ter **centenas/milhares de linhas**

---

### 4️⃣ **Análise Automática** (1 minuto)

No PowerShell:
```powershell
cd "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts"
.\09_AnalyzeExpandedLogs.ps1
```

**O script vai**:
- ✅ Comparar os 2 logs automaticamente
- ✅ Identificar VID:PID do HS3
- ✅ Detectar operações exclusivas
- ✅ Gerar relatório completo
- ✅ Indicar método de validação

---

## 📊 O que esperamos descobrir:

### Cenário Ideal:
```
[DESCOBERTA CRITICA] VID:PID detectados:
  - VID_14EB&PID_0102 (TiePie HS3)

[METODO]: CoRe usa USB Device Enumeration
```

### Implementação no BioDeskPro2:
```csharp
public class UsbDeviceDetector
{
    private const string HS3_VID = "14EB"; // Descoberto!
    private const string HS3_PID = "0102"; // Descoberto!

    public bool IsHS3Connected()
    {
        // Enumerar dispositivos USB
        // Procurar VID:PID específico
        return found;
    }
}
```

---

## ⏱️ Tempo Total:

- Reconfigurar filtros: 2 min
- Teste 1 (COM): 5 min
- Teste 2 (SEM): 5 min
- Análise automática: 1 min
- **TOTAL: ~13 minutos**

---

## 🎯 PRÓXIMO PASSO:

**Responda quando terminar**:
- "Terminei! Tenho LogComEquipamento.csv e LogSemEquipamento.csv"

E eu executo: `.\09_AnalyzeExpandedLogs.ps1`

---

**IMPORTANTE**: Os novos logs devem ser **MUITO maiores** que os anteriores!
- ❌ Logfile.CSV: ~1 KB (2 eventos)
- ✅ LogComEquipamento.csv: **50-500 KB** (centenas/milhares de eventos)

Se continuar com ~1 KB, algo está errado nos filtros!
