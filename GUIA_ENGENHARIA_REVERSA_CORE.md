# 🔍 Guia de Engenharia Reversa - Inergetix CoRe

## Objetivo
Observar como o Inergetix CoRe interage com `hs3.dll` para descobrir:
1. **Método de validação de hardware**
2. **API de emissão de frequências**
3. **Gestão de "shocks" (choques elétricos)**
4. **Sequências de inicialização corretas**

---

## 🛠️ Ferramentas Necessárias

### 1. Process Monitor (Sysinternals)
**Download**: https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

**Capacidades**:
- Monitoriza DLL loading em tempo real
- Captura File I/O, Registry, Network
- Filtra por processo específico
- Exporta logs para análise

### 2. API Monitor (Opcional - Mais Avançado)
**Download**: http://www.rohitab.com/apimonitor

**Capacidades**:
- Rastreia chamadas Win32 API
- Mostra parâmetros e return values
- Suporta hooking de funções custom

### 3. Dependency Walker (Para Análise Estática)
**Download**: https://www.dependencywalker.com/

**Capacidades**:
- Lista todas as funções exportadas por `hs3.dll`
- Mostra dependências de outras DLLs
- Identifica funções não documentadas

---

## 📝 Procedimento Passo-a-Passo

### Fase 1: Análise Estática (5 minutos)

#### 1.1 Analisar `hs3.dll` com Dependency Walker

```powershell
# Abrir Dependency Walker
# File → Open → Navegar para hs3.dll (provavelmente em C:\Program Files\Inergetix\CoRe\)

# Observar:
# - Lista de funções exportadas (Export Functions)
# - Procurar por funções relacionadas com:
#   * "Connect", "Disconnect", "IsConnected"
#   * "Validate", "Check", "Status"
#   * "Emit", "Shock", "Pulse", "Frequency"
```

**O que procurar**:
- Funções que NÃO testámos ainda
- Padrões de nomenclatura (ex: `HS3_xxx`, `TiePie_xxx`)
- Funções com nomes sugestivos de validação

---

### Fase 2: Monitorização em Tempo Real (20-30 minutos)

#### 2.1 Configurar Process Monitor

1. **Executar Process Monitor como Administrador**
2. **Criar filtro para Inergetix CoRe**:
   ```
   Process Name → is → CoRe.exe (ou nome do executável do CoRe)
   ```
3. **Adicionar filtros adicionais**:
   ```
   Operation → is → Load Image (captura DLL loading)
   Path → contains → hs3.dll
   Operation → is → Process Create
   ```
4. **Habilitar captura de stack traces**:
   - Options → Enable Boot Logging (se necessário)
   - Options → Select Columns → Mostrar "Thread ID", "Call Stack"

#### 2.2 Cenário de Teste 1: Deteção de Hardware

**Objetivo**: Descobrir como CoRe valida conexão do HS3

**Procedimento**:
```
1. Iniciar captura no Process Monitor
2. Conectar HS3 ao USB (se ainda não estiver)
3. Lançar Inergetix CoRe
4. Observar interface do CoRe até mostrar "HS3 Conectado" ou equivalente
5. Parar captura no Process Monitor
6. Analisar sequência de eventos
```

**O que procurar nos logs**:
- Ordem de chamadas de funções após Load Image de `hs3.dll`
- Registry reads (pode ler configuração USB de registry)
- File operations (pode ler arquivo de configuração)
- CreateFile operations (pode abrir handle USB via DeviceIoControl)

#### 2.3 Cenário de Teste 2: Falha de Deteção

**Objetivo**: Ver diferença quando hardware AUSENTE

**Procedimento**:
```
1. Fechar CoRe
2. Desconectar HS3 do USB
3. Limpar captura anterior (Edit → Clear Display)
4. Iniciar nova captura no Process Monitor
5. Lançar Inergetix CoRe
6. Observar mensagem de erro ou aviso
7. Parar captura
8. COMPARAR com captura anterior (Teste 1)
```

**Comparação crítica**:
- Funções chamadas APENAS quando hardware presente
- Diferenças em return values (se API Monitor estiver a capturar)
- Sequências que faltam quando hardware ausente

#### 2.4 Cenário de Teste 3: Emissão de Frequência

**Objetivo**: Descobrir API de emissão

**Procedimento**:
```
1. HS3 conectado
2. CoRe aberto e hardware detectado
3. Limpar captura Process Monitor
4. Iniciar captura
5. No CoRe: Configurar emissão de frequência (ex: 1 Hz, 10V)
6. Iniciar emissão
7. Aguardar 5 segundos
8. Parar emissão
9. Parar captura Process Monitor
```

**O que procurar**:
- Chamadas repetidas (emissão contínua vs pulsos)
- Funções com nomes tipo `Emit`, `Start`, `Stop`, `SetFrequency`
- Parâmetros passados (valores hexadecimais que correspondam a 1 Hz, 10V)

#### 2.5 Cenário de Teste 4: "Shocks" (Choques)

**Objetivo**: Descobrir API de pulsos elétricos

**Procedimento**:
```
1. HS3 conectado
2. CoRe aberto
3. Limpar captura
4. Iniciar captura
5. No CoRe: Configurar "shock" ou pulso (se interface permitir)
6. Executar shock
7. Parar captura
```

**O que procurar**:
- Funções diferentes das de emissão contínua
- Parâmetros de duração/intensidade de pulso
- Sequência: Configurar → Armar → Disparar → Desarmar

---

### Fase 3: Análise Avançada (Se Necessário)

#### 3.1 API Monitor (Hooking de Funções)

Se Process Monitor não capturar detalhes suficientes:

1. **Executar API Monitor como Administrador**
2. **Criar definição custom para hs3.dll**:
   - File → New API Definition
   - Adicionar funções conhecidas:
     ```xml
     <Function Name="InitInstrument" />
     <Function Name="SetFuncGenFrequency" />
     <Function Name="SetFuncGenAmplitude" />
     <Function Name="EmitFrequency" />
     <!-- Adicionar outras descobertas -->
     ```
3. **Attach ao processo CoRe.exe**
4. **Repetir cenários de teste**
5. **Observar parâmetros e return values em tempo real**

---

## 📊 Análise de Resultados

### Exportar Logs Process Monitor

```powershell
# No Process Monitor:
# File → Save → Selecionar formato:
# - CSV (para análise em Excel/Python)
# - XML (para parsing automático)
# - Native PMC (para reabrir no ProcMon)
```

### Análise em PowerShell

```powershell
# Exemplo: Extrair chamadas de DLL específicas
$logPath = "C:\Users\nfjpc\Documents\ProcMon_CoRe_Conectado.CSV"
Import-Csv $logPath |
    Where-Object { $_.Path -like "*hs3.dll*" -or $_.Operation -eq "Load Image" } |
    Select-Object Time, Operation, Path, Result, Detail |
    Out-GridView

# Procurar padrões
Import-Csv $logPath |
    Where-Object { $_.Detail -match "hs3" } |
    Group-Object Operation |
    Sort-Object Count -Descending
```

---

## 🎯 O Que Esperamos Descobrir

### Cenário Otimista ✅

1. **Função de validação explícita**:
   - Ex: `HS3_CheckConnection()` → return 1 se conectado, 0 se ausente
   - Ex: `TiePie_GetDeviceList()` → retorna array de devices

2. **Sequência de inicialização correta**:
   ```
   InitInstrument() → ValidateConnection() → ConfigureDevice() → Ready
   ```

3. **API de emissão documentável**:
   ```
   SetFrequency(1.0) → SetAmplitude(10.0) → StartEmission() → [esperar] → StopEmission()
   ```

4. **API de shocks**:
   ```
   ConfigurePulse(duration, intensity) → ArmPulse() → TriggerPulse()
   ```

### Cenário Realista 🤔

1. **Validação via USB Device Enumeration**:
   - CoRe usa Windows API (`SetupDiGetClassDevs`, `CM_Get_Device_ID`)
   - Procura VID:PID específico do HS3
   - `hs3.dll` não tem função de validação própria

2. **Inicialização com retry logic**:
   - CoRe tenta `InitInstrument()` múltiplas vezes
   - Verifica registry/file para confirmar presença
   - Timeout se não responder

3. **Emissão com wrapper custom**:
   - CoRe tem camada própria sobre `hs3.dll`
   - Usa funções que não documentamos ainda
   - Possível DLL intermediária (`CoRe_HS3_Wrapper.dll`)

---

## 🚨 Notas de Segurança

### ⚠️ IMPORTANTE:

1. **NÃO modificar ficheiros do Inergetix CoRe**
   - Apenas observar, não alterar
   - Fazer backup antes de qualquer teste

2. **Validar com hardware desconectado primeiro**
   - Evitar comandos de emissão sem saber parâmetros seguros
   - Testar validação antes de emissão

3. **Documentar tudo**
   - Timestamps de cada teste
   - Screenshots de configurações
   - Logs exportados com nomes descritivos

4. **Isolar testes**
   - Fechar BioDeskPro2 durante testes do CoRe
   - Evitar conflitos de acesso ao hardware

---

## 📝 Template de Documentação

Após cada cenário de teste, preencher:

```markdown
### Teste: [Nome do Cenário]
**Data/Hora**: [timestamp]
**Hardware Estado**: [Conectado/Desconectado]
**Configuração CoRe**: [Frequência, Amplitude, etc]

#### Observações Process Monitor:
- **DLLs carregadas**: [lista]
- **Funções chamadas** (ordem):
  1. [Função1] → Result: [valor]
  2. [Função2] → Result: [valor]
  ...
- **Registry reads**: [chaves lidas]
- **File operations**: [ficheiros acedidos]

#### Descobertas:
- [O que aprendemos]

#### Hipóteses:
- [Teorias para testar]

#### Próximos Passos:
- [ ] [Ação 1]
- [ ] [Ação 2]
```

---

## 🔄 Plano de Implementação no BioDeskPro2

Após descobrir método de validação do CoRe:

### Se descobrirmos função de validação:
```csharp
// Exemplo hipotético
[DllImport("hs3.dll", CallingConvention = CallingConvention.Cdecl)]
private static extern int HS3_CheckConnection(); // Descoberta!

public async Task<bool> ValidateHardwareAsync()
{
    try
    {
        int status = HS3_CheckConnection();
        _logger.LogInformation("[HS3] CheckConnection returned: {Status}", status);
        return status == 1; // ou qualquer que seja o código de sucesso
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "[HS3] Validation failed");
        return false;
    }
}
```

### Se validação for via USB enumeration:
- Implementar **Opção A** do plano anterior
- Usar VID:PID descoberto nos logs do CoRe
- Criar `UsbDeviceDetector.cs`

### Se descobrirmos API de emissão diferente:
```csharp
// Substituir EmitFrequency por método descoberto
[DllImport("hs3.dll", CallingConvention = CallingConvention.Cdecl)]
private static extern int HS3_StartContinuousEmission(double freq, double amp);

[DllImport("hs3.dll", CallingConvention = CallingConvention.Cdecl)]
private static extern int HS3_StopEmission();
```

---

## 📊 Estimativa de Tempo

| Fase | Duração | Complexidade |
|------|---------|--------------|
| Instalar ferramentas | 10 min | ⭐ Fácil |
| Análise estática (Dependency Walker) | 5 min | ⭐ Fácil |
| Testes Process Monitor (4 cenários) | 30 min | ⭐⭐ Média |
| Análise de logs | 20 min | ⭐⭐ Média |
| Implementação descobertas | 1-2h | ⭐⭐⭐ Depende |
| **TOTAL** | **~2-3 horas** | |

---

## ✅ Vantagens desta Abordagem

1. ✅ **Não invasiva** - Apenas observamos, não modificamos CoRe
2. ✅ **Baixo risco** - Sem risco de danificar instalação do CoRe
3. ✅ **Informação definitiva** - Vemos exatamente o que funciona
4. ✅ **Reproduzível** - Podemos repetir testes
5. ✅ **Documentável** - Logs exportáveis como prova
6. ✅ **Pode resolver múltiplos problemas** - Validação + Emissão + Shocks

---

## 🎯 Decisão Final

**Esta abordagem é SUPERIOR à Opção C original porque**:
- Não requer "adivinhar" - vemos o que realmente acontece
- Descobrimos não só validação, mas TODA a API funcional
- Tempo investido (~2-3h) vs incerteza da tentativa-erro (horas/dias)
- Ganho de conhecimento: Entendemos o sistema completo

**Recomendação**:
1. **Fazer esta investigação PRIMEIRO**
2. Depois implementar descobertas no BioDeskPro2
3. Se não descobrirmos nada útil, voltar à Opção B (UX Defensiva)

---

## 📞 Próximo Passo

**Você precisa**:
1. Confirmar se tem Inergetix CoRe instalado
2. Verificar caminho de instalação (onde está `hs3.dll` do CoRe)
3. Baixar Process Monitor
4. Decidir se quer fazer isso AGORA ou implementar Opção B primeiro

**Responda**:
- "Tenho CoRe instalado - vamos investigar!"
- "Não tenho CoRe - fazer Opção B"
- "Preciso de ajuda a instalar ferramentas"
