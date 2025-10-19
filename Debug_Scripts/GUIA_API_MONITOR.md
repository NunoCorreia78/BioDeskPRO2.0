# 🔍 GUIA VISUAL - API Monitor

## 🎯 O QUE É API MONITOR?

Ferramenta que **captura chamadas de funções DLL** mostrando:
- ✅ Qual função foi chamada
- ✅ Parâmetros passados
- ✅ Return value (valor retornado)
- ✅ Ordem de execução

**Diferença do Process Monitor**:
- ❌ Process Monitor: Operações de SO (Registry, Files, Processes)
- ✅ API Monitor: **Chamadas de funções dentro da DLL**

---

## 🚀 INSTALAÇÃO (5 minutos)

### Opção A: Script Automático
```powershell
cd "C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\Debug_Scripts"
.\10_DownloadAPIMonitor.ps1
```

### Opção B: Download Manual
1. Abrir: http://www.rohitab.com/apimonitor
2. Baixar: **API Monitor v2 (32-bit + 64-bit)**
3. Extrair para: `C:\Users\nfjpc\Documents\APIMonitor\`
4. **IMPORTANTE**: Executar: `apimonitor-x86.exe` (32-bit, não x64!)
   - **Inergetix CoRe é 32-bit** → precisa do API Monitor 32-bit!

---

## ⚙️ CONFIGURAÇÃO (10 minutos)

### 1️⃣ Lançar e Preparar

⚠️ **CRÍTICO**: Abrir **apimonitor-x86.exe** (32-bit, NÃO x64!)
- Inergetix CoRe está em `Program Files (x86)` = aplicação 32-bit
- API Monitor 64-bit NÃO consegue monitorizar processos 32-bit!

### 2️⃣ Configurar Processo a Monitorizar

**Monitor** → **Monitor New Process...**
- **Browse** → Selecionar:
  ```
  C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\InergetixCoRe.exe
  ```
- **NÃO CLICAR OK AINDA!**

### 3️⃣ Configurar Filtros de API (IMPORTANTE!)

No **painel esquerdo** (API Filter):

⚠️ **ATENÇÃO**: A lista tem **SCROLL VERTICAL**! Precisa rolar para cima/baixo para ver todas as categorias!

1. **Desmarcar TUDO**:
   - `Ctrl+A` (selecionar tudo)
   - Clicar em **qualquer checkbox** para desmarcar todos

2. **Marcar APENAS estas 3 categorias** (precisa fazer SCROLL!):

   📁 **File Management** (SCROLL UP - está no **TOPO** da lista)
   ```
   [x] File Management
       [x] CreateFile
       [x] ReadFile
       [x] WriteFile
       [x] CloseHandle
   ```

   🔌 **Devices** (está no **MEIO** da lista - ver na sua imagem!)
   ```
   [x] Devices
       [x] DeviceIoControl
   ```

   📚 **Library Management** (SCROLL DOWN - está **ABAIXO** de "Internet", "Microsoft .NET", etc.)
   ```
   [x] Library Management
       [x] LoadLibrary
       [x] LoadLibraryEx
       [x] GetProcAddress
       [x] FreeLibrary
   ```

**COMO ENCONTRAR "Library Management"**:
1. No painel API Filter (esquerdo)
2. **SCROLL DOWN** (rolar para baixo)
3. Passar por: Internet → Microsoft .NET → NT Native → Netscape...
4. **Library Management** aparece DEPOIS de várias categorias!

**Resultado**: Vai capturar apenas operações relevantes (não milhões de eventos)### 4️⃣ Adicionar Hook para hs3.dll (CRÍTICO!)

Isso permite capturar funções **específicas** da hs3.dll:

1. **Options** → **Edit API Definitions...**
2. **File** → **New** → **Module Definition**
3. Preencher:
   ```
   Name: hs3
   Module: hs3.dll
   Path: C:\Program Files (x86)\Inergetix\Inergetix-CoRe 5.0\hs3.dll
   ```
4. **Add Functions** (adicionar uma por uma):
   ```
   Function Name: InitInstrument
   Return Type: int

   Function Name: SetFuncGenFrequency
   Return Type: int
   Parameters: double frequency

   Function Name: SetFuncGenAmplitude
   Return Type: int
   Parameters: double amplitude

   Function Name: EmitFrequency
   Return Type: int
   Parameters: double frequency

   Function Name: CloseInstrument
   Return Type: int
   ```

5. **Save** → Fechar janela

6. **Voltar ao API Filter** (painel esquerdo):
   - Procurar **hs3** na lista
   - Marcar **[x] hs3**
   - Expandir e marcar todas as funções

### 5️⃣ Iniciar Monitorização

**Agora sim**, na janela **Monitor New Process**:
- Clicar **OK**

O CoRe vai **lançar automaticamente** sob monitorização!

---

## 📊 TESTE 1: COM Equipamento (10 minutos)

### Preparação:
- [x] HS3 **conectado** ao USB ✅
- [x] API Monitor configurado
- [x] CoRe vai iniciar automaticamente

### Procedimento:
```
1. API Monitor lançou o CoRe automaticamente
2. No CoRe: Navegar até tela de seleção de dispositivo
3. Observar API Monitor capturando eventos em tempo real
4. Aguardar CoRe detectar HS3 (~15 segundos)
5. Ver mensagem "HS3 Conectado" no CoRe
6. No API Monitor: F5 (Stop Monitoring)
7. File → Save → Nome: ApiMonitor_COM_Equipamento.apm
8. Fechar CoRe
```

---

## 📊 TESTE 2: SEM Equipamento (10 minutos)

### Preparação:
- [x] **Fechar CoRe** completamente
- [x] **Desconectar HS3** do USB ❌
- [x] API Monitor ainda aberto

### Procedimento:
```
1. No API Monitor: Edit → Clear All (limpar eventos)
2. Monitor → Monitor New Process...
   - Mesmo executável (já preenchido)
   - OK
3. CoRe lança automaticamente
4. Aguardar erro/aviso (~15 segundos)
5. No API Monitor: F5 (Stop Monitoring)
6. File → Save → Nome: ApiMonitor_SEM_Equipamento.apm
7. Fechar CoRe
```

---

## 🔍 ANÁLISE DOS RESULTADOS

### No painel **Summary** do API Monitor:

#### 1️⃣ Procurar Funções de hs3.dll

Expandir categoria **hs3** e ver:

**COM Equipamento - Exemplo esperado:**
```
InitInstrument() → Return: 3136 (handle)
SetFuncGenFrequency(100.0) → Return: 3136
SetFuncGenAmplitude(10.0) → Return: 3136
[POSSÍVEL] ValidateConnection() → Return: 1 ✅
```

**SEM Equipamento - Exemplo esperado:**
```
InitInstrument() → Return: 8596 (handle diferente)
SetFuncGenFrequency(100.0) → Return: 8596
SetFuncGenAmplitude(10.0) → Return: 8596
[POSSÍVEL] ValidateConnection() → Return: 0 ❌
```

#### 2️⃣ Comparar MANUALMENTE

Abrir os 2 arquivos `.apm` lado a lado:
- ApiMonitor_COM_Equipamento.apm
- ApiMonitor_SEM_Equipamento.apm

**Procurar**:
- ✅ **Funções exclusivas** em COM
- ✅ **Return values diferentes**
- ✅ **Sequência diferente**
- ✅ **Parâmetros diferentes**

#### 3️⃣ Exportar para Análise

**ANTES de exportar**, aplicar filtros para ter APENAS informação relevante:

**No painel Summary** (onde aparecem os eventos):

1. **Clicar com botão direito** no cabeçalho de coluna
2. **View** → **Filters** → **Enable Filters**
3. **Na coluna "API"**, clicar na setinha do filtro e marcar APENAS:
   ```
   [x] LoadLibrary
   [x] LoadLibraryEx
   [x] GetProcAddress
   [x] CreateFile (só se tiver hs3.dll no Path)
   [x] DeviceIoControl
   [x] FreeLibrary

   [IMPORTANTE] Se houver funções da hs3.dll (InitInstrument, SetFuncGen...), marcar TODAS!
   ```

4. **DESMARCAR** tudo o resto (RegOpenKey, RegQueryValue, etc.)

**Agora sim, exportar**:

**File** → **Export** → **CSV**
- Guardar como: `ApiMonitor_COM_Equipamento.csv`
- Repetir processo para SEM equipamento: `ApiMonitor_SEM_Equipamento.csv`

**Os CSVs terão apenas ~50-200 linhas relevantes** (em vez de milhares!)

Depois executar:
```powershell
.\12_AnalyzeAPIMonitorResults.ps1
```

---

## 🎯 DESCOBERTAS ESPERADAS

### Cenário Ideal:
```
[DESCOBERTA] Função exclusiva COM equipamento:
  HS3_ValidateConnection() → Return 1 (SUCCESS)

[SEM equipamento]:
  HS3_ValidateConnection() → Return 0 (FAILURE)

[IMPLEMENTAÇÃO]:
[DllImport("hs3.dll")]
private static extern int HS3_ValidateConnection();
```

### Cenário Alternativo:
```
[DESCOBERTA] Return value diferente:
  InitInstrument()
    COM: Return 3136 + Chama SetConfig()
    SEM: Return 8596 + NÃO chama SetConfig()
```

---

## ⏱️ Tempo Total

- Download/Instalação: 5 min
- Configuração: 10 min
- Teste 1 (COM): 10 min
- Teste 2 (SEM): 10 min
- Análise: 15 min
- **TOTAL: ~50 minutos**

---

## 🚨 TROUBLESHOOTING

### API Monitor não captura nada?
- Verificar filtros API (painel esquerdo)
- Garantir que **[x] hs3** está marcado
- Re-adicionar hook da DLL

### CoRe não lança?
- Fechar CoRe manualmente antes
- Verificar caminho do executável
- Executar API Monitor como **Administrador**

### Muitos eventos?
- Desmarcar APIs desnecessárias
- Manter APENAS: File Management, Device I/O, Library Management, hs3

---

## 💬 Quando Terminar

**Diga**: "Terminei! Tenho ApiMonitor_COM_Equipamento.apm e ApiMonitor_SEM_Equipamento.apm"

E você pode:
- **Analisar manualmente** (comparar lado a lado)
- **Exportar CSVs** e executar `.\12_AnalyzeAPIMonitorResults.ps1`
- **Relatar descobertas** para implementação

---

**Esta é nossa ÚLTIMA tentativa técnica de engenharia reversa!** 🔍🚀

Se não revelar nada: **Opção B (UX Defensiva)** será a solução pragmática final.
