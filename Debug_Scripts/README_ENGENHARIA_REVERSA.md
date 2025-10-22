# 🔍 Engenharia Reversa - Inergetix CoRe

## 📋 Scripts de Automação

Esta pasta contém scripts PowerShell para automatizar a investigação do Inergetix CoRe e descobrir como ele interage com o TiePie HS3.

### 🚀 Ordem de Execução

Execute os scripts **nesta ordem**:

```powershell
# 1. Baixar e instalar Process Monitor
.\01_DownloadProcessMonitor.ps1

# 2. Localizar instalação do Inergetix CoRe
.\02_FindInergetixCore.ps1

# 3. (Opcional) Analisar hs3.dll com Dependency Walker
.\03_AnalyzeHS3_DependencyWalker.ps1

# 4. Configurar e lançar Process Monitor
.\04_ConfigureProcessMonitor.ps1

# 5. Após capturar logs, analisar eventos
.\05_AnalyzeProcMonLogs.ps1

# 6. Comparar logs de diferentes cenários
.\06_CompareLogs.ps1

# 7. Gerar relatório final
.\07_GenerateReport.ps1
```

---

## 📊 Cenários de Teste

### Teste 1: Hardware Conectado ✅
**Objetivo**: Capturar como CoRe detecta HS3 presente

**Procedimento**:
1. Conectar HS3 ao USB
2. Executar `.\04_ConfigureProcessMonitor.ps1`
3. No Process Monitor: Iniciar captura (Ctrl+E)
4. Lançar Inergetix CoRe
5. Aguardar detecção de hardware
6. Parar captura (Ctrl+E)
7. File → Save → CSV → `ProcMon_CoRe_Conectado.csv`

### Teste 2: Hardware Desconectado ❌
**Objetivo**: Ver diferença quando hardware ausente

**Procedimento**:
1. Fechar CoRe
2. Desconectar HS3 do USB
3. No Process Monitor: Edit → Clear Display (Ctrl+X)
4. Iniciar captura (Ctrl+E)
5. Lançar Inergetix CoRe
6. Observar erro/aviso
7. Parar captura (Ctrl+E)
8. File → Save → CSV → `ProcMon_CoRe_Desconectado.csv`

### Teste 3: Emissão de Frequência ⚡
**Objetivo**: Descobrir API de emissão

**Procedimento**:
1. HS3 conectado, CoRe aberto
2. Edit → Clear Display (Ctrl+X)
3. Iniciar captura (Ctrl+E)
4. No CoRe: Configurar emissão (ex: 1 Hz, 10V)
5. Iniciar emissão
6. Aguardar 5 segundos
7. Parar emissão
8. Parar captura (Ctrl+E)
9. File → Save → CSV → `ProcMon_CoRe_Emissao.csv`

---

## 🎯 O Que Procuramos

### 1. Método de Validação de Hardware
- **Registry keys USB** (ex: `HKLM\SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&PID_yyyy`)
- **Funções de hs3.dll** chamadas apenas quando conectado
- **CreateFile/DeviceIoControl** com SUCCESS vs FAILURE

### 2. API de Emissão
- Sequência de funções para emissão contínua
- Parâmetros de frequência e amplitude
- Start/Stop patterns

### 3. VID:PID do TiePie HS3
- Identificador USB único do hardware
- Usado para enumeração de dispositivos

---

## 📝 Análise de Resultados

### Após Executar Scripts

1. **Revisar descobertas em `05_AnalyzeProcMonLogs.ps1`**:
   - DLLs carregadas
   - Registry access
   - File operations
   - Sequência temporal

2. **Comparar cenários com `06_CompareLogs.ps1`**:
   - Diferenças críticas entre conectado/desconectado
   - Operações exclusivas
   - VID:PID detectados

3. **Gerar relatório com `07_GenerateReport.ps1`**:
   - Resumo executivo
   - Recomendações de implementação

---

## 🔧 Implementação no BioDeskPro2

### Cenário 1: Descobrimos Função de Validação

Se encontrarmos função tipo `HS3_CheckConnection()`:

```csharp
[DllImport("hs3.dll", CallingConvention = CallingConvention.Cdecl)]
private static extern int HS3_CheckConnection();

public async Task<bool> ValidateHardwareAsync()
{
    int status = HS3_CheckConnection();
    return status == 1; // ou código descoberto
}
```

### Cenário 2: Validação via USB Enumeration

Se CoRe usa VID:PID para detectar:

```csharp
public class UsbDeviceDetector
{
    private const string HS3_VID = "xxxx"; // Descoberto nos logs
    private const string HS3_PID = "yyyy"; // Descoberto nos logs

    public bool IsHS3Connected()
    {
        // Implementar SetupAPI enumeration
    }
}
```

### Cenário 3: API de Emissão Diferente

Se descobrirmos funções alternativas:

```csharp
[DllImport("hs3.dll")]
private static extern int HS3_StartEmission(double freq, double amp);

[DllImport("hs3.dll")]
private static extern int HS3_StopEmission();
```

---

## 🚨 Notas Importantes

### ⚠️ Segurança

- **NÃO modificar** ficheiros do Inergetix CoRe
- **Apenas observar**, não alterar
- **Fazer backup** antes de testes

### 📂 Localização de Ficheiros

- **Process Monitor**: `C:\Users\[USER]\Documents\SysinternalsTools\Procmon.exe`
- **Logs CSV**: `BioDeskPro2\Logs\ProcessMonitor\*.csv`
- **Configuração CoRe**: `Debug_Scripts\InergetixCoreConfig.json`

### 🕒 Estimativa de Tempo

| Etapa | Duração |
|-------|---------|
| Instalação ferramentas | 10 min |
| Teste 1 (Conectado) | 10 min |
| Teste 2 (Desconectado) | 10 min |
| Teste 3 (Emissão) | 10 min |
| Análise logs | 20 min |
| Comparação | 15 min |
| **TOTAL** | **~1h 15min** |

---

## ✅ Checklist de Progresso

### FASE 1: Process Monitor ✅ COMPLETA
- [x] 01 - Process Monitor instalado
- [x] 02 - Inergetix CoRe localizado
- [x] 04 - Process Monitor configurado
- [x] 05 - Teste 1: Hardware Conectado executado (52,924 eventos)
- [x] 06 - Teste 2: Hardware Desconectado executado (50,747 eventos)
- [x] 08 - Re-captura com filtros expandidos
- [x] 09 - Análise automatizada completa
- [x] 10 - Análise manual verificada
- [x] 11 - Relatório gerado
- [x] **CONCLUSÃO**: Validação não é OS-level, é DLL-internal ❌

### FASE 2: API Monitor 🔄 ATUAL
- [ ] 10 - API Monitor instalado (`.\10_DownloadAPIMonitor.ps1`)
- [ ] 11 - API Monitor configurado + hook hs3.dll (`.\11_ConfigureAPIMonitor.ps1`)
- [ ] 12 - Teste 1: Captura COM equipamento (apimonitor_com.csv)
- [ ] 13 - Teste 2: Captura SEM equipamento (apimonitor_sem.csv)
- [ ] 14 - Análise resultados (`.\12_AnalyzeAPIMonitorResults.ps1`)
- [ ] 15 - Funções exclusivas identificadas?
- [ ] 16 - Return values diferentes descobertos?
- [ ] 17 - Implementação no BioDeskPro2 OU Opção A (UX Defensiva)

---

## 🚀 PRÓXIMO PASSO: EXECUTAR AGORA

```powershell
cd "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts"

# Passo 1: Baixar API Monitor (5 min)
.\10_DownloadAPIMonitor.ps1

# Passo 2: Configurar API Monitor (10 min)
.\11_ConfigureAPIMonitor.ps1
# Seguir instruções na tela OU consultar GUIA_API_MONITOR.md

# Passo 3: Após capturar .csv, analisar (15 min)
.\12_AnalyzeAPIMonitorResults.ps1 -ComCsvPath "ApiMonitor_COM.csv" -SemCsvPath "ApiMonitor_SEM.csv"
```

**Guia Visual Completo**: `GUIA_API_MONITOR.md`

---

## 📞 Suporte

Em caso de dúvidas ou problemas:

1. Verificar logs de erro dos scripts
2. **FASE 1 (Process Monitor)**: Consultar `GUIA_VISUAL_PROCESS_MONITOR.md`
3. **FASE 2 (API Monitor)**: Consultar `GUIA_API_MONITOR.md`
4. Revisar `GUIA_ENGENHARIA_REVERSA_CORE.md`

---

**Última atualização**: 19/10/2025 23:15 - FASE 2 (API Monitor) iniciada
