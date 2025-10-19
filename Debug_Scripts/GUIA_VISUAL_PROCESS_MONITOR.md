# 🔍 GUIA RÁPIDO - Process Monitor

## ⚡ INICIO RÁPIDO (3 minutos)

### 1️⃣ Configurar Filtros (AGORA na janela Process Monitor)

**Na janela do Process Monitor que acabou de abrir**:

1. Clicar: **Filter** (menu superior) → **Filter...**
2. Adicionar TRÊS filtros:

```
Filtro 1:
  [Process Name] [is] [InergetixCoRe.exe] [Include] → [Add]

Filtro 2:
  [Path] [contains] [hs3.dll] [Include] → [Add]

Filtro 3:
  [Operation] [is] [Load Image] [Include] → [Add]
```

3. Clicar: **Apply** → **OK**

---

### 2️⃣ TESTE 1: Hardware Conectado (10 minutos)

#### Preparação:
- [x] HS3 **conectado** ao USB
- [x] Process Monitor aberto com filtros
- [x] CoRe **fechado**

#### Procedimento:
```
1. Process Monitor: Iniciar captura
   → Ctrl+E (ou menu Capture → Capture Events)
   → Ícone de lupa fica VERDE

2. Lançar Inergetix CoRe
   → C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\InergetixCoRe.exe
   → OU atalho no desktop/menu iniciar

3. Aguardar CoRe detectar HS3
   → Observar mensagem "HS3 Conectado" ou similar
   → Esperar 10-15 segundos após detecção

4. Parar captura no Process Monitor
   → Ctrl+E novamente (lupa fica CINZA)

5. Salvar log:
   → File → Save...
   → Events displayed using current filter: SELECIONAR
   → Format: CSV (Comma-Separated Values)
   → Nome: ProcMon_CoRe_Conectado.csv
   → Local: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\ProcessMonitor\
   → Save

6. Fechar CoRe
```

#### ✅ Confirmação:
- Arquivo criado: `ProcMon_CoRe_Conectado.csv`
- Tamanho > 0 KB
- Contém eventos (abrir no Notepad para verificar)

---

### 3️⃣ TESTE 2: Hardware Desconectado (10 minutos)

#### Preparação:
- [x] **Fechar** Inergetix CoRe
- [x] **Desconectar** HS3 do USB 🔌❌
- [x] Process Monitor ainda aberto

#### Procedimento:
```
1. Limpar eventos anteriores
   → Edit → Clear Display (Ctrl+X)
   → Confirmar: Yes

2. Iniciar nova captura
   → Ctrl+E (lupa VERDE)

3. Lançar Inergetix CoRe
   → Executar normalmente

4. Observar ERRO ou AVISO
   → "Hardware não detectado" ou similar
   → Esperar 10-15 segundos

5. Parar captura
   → Ctrl+E (lupa CINZA)

6. Salvar log:
   → File → Save...
   → Format: CSV
   → Nome: ProcMon_CoRe_Desconectado.csv
   → Local: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\ProcessMonitor\
   → Save

7. Fechar CoRe
```

#### ✅ Confirmação:
- Arquivo criado: `ProcMon_CoRe_Desconectado.csv`
- Tamanho > 0 KB

---

### 4️⃣ TESTE 3: Emissão de Frequência (10 minutos) - OPCIONAL MAS VALIOSO

#### Preparação:
- [x] **Reconectar** HS3 ao USB ✅
- [x] Lançar CoRe e aguardar detecção

#### Procedimento:
```
1. CoRe aberto e HS3 detectado
   → Navegar até tela de emissão/terapia

2. Process Monitor: Limpar
   → Edit → Clear Display (Ctrl+X)

3. Iniciar captura
   → Ctrl+E (lupa VERDE)

4. No CoRe: Configurar emissão
   → Frequência: 1 Hz
   → Amplitude: 10V (ou valor seguro)

5. Iniciar emissão
   → Clicar botão "Start" ou similar

6. Aguardar 5 segundos
   → Deixar emitir

7. Parar emissão no CoRe
   → Clicar botão "Stop"

8. Parar captura Process Monitor
   → Ctrl+E (lupa CINZA)

9. Salvar log:
   → File → Save...
   → Format: CSV
   → Nome: ProcMon_CoRe_Emissao.csv
   → Local: C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\ProcessMonitor\
   → Save
```

#### ✅ Confirmação:
- Arquivo criado: `ProcMon_CoRe_Emissao.csv`
- Tamanho provavelmente maior (mais eventos)

---

## 📊 APÓS CAPTURAR LOGS

### Verificar Arquivos:
```powershell
cd "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Logs\ProcessMonitor"
dir *.csv
```

### Executar Análise Automática:
```powershell
cd "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts"
.\05_AnalyzeProcMonLogs.ps1
```

### Comparar Logs:
```powershell
.\06_CompareLogs.ps1
```

---

## 🚨 TROUBLESHOOTING

### Process Monitor não mostra eventos?
- Verificar filtros: Filter → Filter... → Reset
- Re-adicionar filtros manualmente

### CoRe não detecta HS3 mesmo conectado?
- Verificar Device Manager: Dispositivos USB
- Reiniciar computador se necessário

### Arquivo CSV vazio?
- Verificar se captura estava ativa (lupa VERDE)
- Re-executar teste

---

## 🎯 OBJETIVO

**Estamos procurando**:
- Como CoRe valida conexão USB
- Funções específicas de `hs3.dll` chamadas
- Registry keys USB acessadas
- VID:PID do TiePie HS3

**Após análise**:
- Implementar mesmo método no BioDeskPro2
- Resolver problema de falsa detecção ✅

---

## ⏱️ Tempo Total Estimado

- Teste 1: ~10 min
- Teste 2: ~10 min
- Teste 3: ~10 min (opcional)
- **TOTAL**: 20-30 minutos

**Você está MUITO perto de descobrir o segredo!** 🔓
