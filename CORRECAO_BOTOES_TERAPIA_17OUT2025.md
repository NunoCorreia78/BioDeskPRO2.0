# 🔧 CORREÇÃO: Botões de Iniciar Terapia Não Funcionavam (17 OUT 2025)

## 🎯 Problema Identificado

**Sintoma**: Ao clicar em "Iniciar" nos módulos de terapia (Ressonantes, Biofeedback, Programas), aparecia erro:
```
"O comando de terapia não pode ser executado neste momento."
```

**Causa Raiz**: `[RelayCommand]` com parâmetros do CommunityToolkit.Mvvm **não gera `CanExecute` padrão**.
Sem método `CanExecute` explícito, o comando retorna sempre `false`, bloqueando a execução.

## ✅ Solução Implementada

### Alterações nos ViewModels

Adicionado método `CanExecute` para cada comando de terapia nos 3 ViewModels:

#### 1. RessonantesViewModel.cs
```csharp
// ANTES (❌ NÃO FUNCIONAVA)
[RelayCommand]
private async Task IniciarTerapiaLocalAsync(TerapiaParametros parametros)
{
    // ... implementação ...
}

// DEPOIS (✅ FUNCIONA)
private bool CanIniciarTerapiaLocal(TerapiaParametros? parametros)
{
    return !TerapiaEmAndamento; // Permite execução quando idle
}

[RelayCommand(CanExecute = nameof(CanIniciarTerapiaLocal))]
private async Task IniciarTerapiaLocalAsync(TerapiaParametros parametros)
{
    // ... implementação inalterada ...
}
```

#### 2. BiofeedbackViewModel.cs
```csharp
private bool CanIniciarSessao(TerapiaParametros? parametros)
{
    return !SessaoEmAndamento; // Permite execução quando idle
}

[RelayCommand(CanExecute = nameof(CanIniciarSessao))]
private async Task IniciarSessaoAsync(TerapiaParametros parametros)
{
    // ... implementação inalterada ...
}
```

#### 3. ProgramasViewModel.cs
```csharp
private bool CanIniciarTerapiaLocal(TerapiaParametros? parametros)
{
    return !TerapiaEmAndamento; // Permite execução quando idle
}

[RelayCommand(CanExecute = nameof(CanIniciarTerapiaLocal))]
private async Task IniciarTerapiaLocalAsync(TerapiaParametros parametros)
{
    // ... implementação inalterada ...
}
```

## 🧪 Como Testar

### 1. Executar Aplicação
```powershell
dotnet run --project src/BioDesk.App
```

### 2. Testar Ressonantes
1. Navegar para **Dashboard** → **Configurações** → **Banco Core & Terapias**
2. Clicar aba **"Ressonantes"**
3. Clicar **"SCAN"** (deve aparecer pelo menos uma frequência)
4. Selecionar uma linha na grelha de resultados
5. Clicar **"Iniciar"** (botão verde)

**✅ Esperado**:
- Sem erro
- Logs no Debug Output (VS Code):
  ```
  🟢 TerapiaControlosUserControl: IniciarButton_Click DISPARADO
  🔵 RessonantesView: TerapiaControlos_IniciarClick DISPARADO
  ✅ RessonantesView: ViewModel OK, SelectedItems.Count = 1
  📝 RessonantesView: Parâmetros criados - V=5.0, Duração=30min, Tempo/Freq=10s
  🔍 RessonantesView: CanExecute = True
  ▶️ RessonantesView: Executando comando...
  🚀 RessonantesViewModel: IniciarTerapiaLocalAsync CHAMADO
  ```
- Contador deve começar (visível nos logs com "TempoRestanteSegundos")

❌ **Se aparecer erro**: Copiar logs do Debug Output e reportar.

### 3. Testar Biofeedback
1. Navegar para **Banco Core & Terapias** → **"Biofeedback"**
2. Ajustar parâmetros (Voltagem, Duração, Cycles)
3. Clicar **"Iniciar"**

**✅ Esperado**: Sessão deve iniciar, logs similares aos de Ressonantes.

### 4. Testar Programas
1. Navegar para **Banco Core & Terapias** → **"Programas"**
2. Selecionar um programa (e.g., "AGRESSIVIDADE")
3. Clicar **"Adicionar à Fila"** (opcional)
4. Clicar **"Iniciar"**

**✅ Esperado**: Terapia deve iniciar com frequências do programa.

## 📊 Debug Logs (Onde Ver)

Os logs com emojis aparecem no **Debug Output** do VS Code:

1. **Menu**: View → Output
2. **Dropdown**: Selecionar "Debug Console" (ou similar)
3. Procurar por emojis: 🟢 🔵 🚀 ✅ ❌

**Exemplo de execução bem-sucedida**:
```
🟢 TerapiaControlosUserControl: IniciarButton_Click DISPARADO
📊 Valores: V=5.0, Duração=30min, Tempo/Freq=10s, Ajuste=0Hz
🔗 IniciarClick subscribers: 1
✅ TerapiaControlosUserControl: Evento IniciarClick invocado

🔵 RessonantesView: TerapiaControlos_IniciarClick DISPARADO
✅ RessonantesView: ViewModel OK, SelectedItems.Count = 1
📝 RessonantesView: Parâmetros criados - V=5.0, Duração=30min, Tempo/Freq=10s
🔍 RessonantesView: CanExecute = True
▶️ RessonantesView: Executando comando...
✅ RessonantesView: Comando executado

🚀 RessonantesViewModel: IniciarTerapiaLocalAsync CHAMADO
[... contagem decrescente de TempoRestanteSegundos ...]
```

## 🔧 Build Status

```
Build succeeded.
0 Error(s)
24 Warning(s) (apenas AForge compatibility - normal)
```

## 📋 Checklist Pós-Teste

- [ ] Botão "Iniciar" em **Ressonantes** funciona sem erro
- [ ] Botão "Iniciar" em **Biofeedback** funciona sem erro
- [ ] Botão "Iniciar" em **Programas** funciona sem erro
- [ ] Logs aparecem no Debug Output com sequência completa
- [ ] Contadores decrescem corretamente (visível nos logs)

## 🚀 Próximos Passos (Após Confirmação)

1. **Adicionar UI para progresso**:
   - Vincular `FrequenciaAtual` a TextBlock
   - Vincular `TempoRestanteSegundos` a TextBlock
   - Vincular `ProgressoPercentual` a ProgressBar

2. **Remover logs de debug** (ou comentar para debug futuro)

3. **Integrar hardware real**:
   - Substituir `await Task.Delay(1000)` por `await _emissionDevice.EmitFrequencyAsync(...)`

4. **Implementar botão "Parar"**:
   - Adicionar CancellationTokenSource
   - Permitir cancelamento de terapia em andamento

## 📖 Lição Aprendida

**Regra de Ouro CommunityToolkit.Mvvm**:
> `[RelayCommand]` com parâmetros **sempre** precisa de método `CanExecute` explícito.

**Pattern Obrigatório**:
```csharp
private bool CanXxx(TipoParametro? parametro)
{
    return condicaoQuePermiteExecucao;
}

[RelayCommand(CanExecute = nameof(CanXxx))]
private async Task XxxAsync(TipoParametro parametro)
{
    // ... implementação ...
}
```

## 🔗 Documentação Relacionada

- **DEBUG_BOTOES_TERAPIA_17OUT2025.md**: Guia de debug com cenários de falha
- **SISTEMA_TERAPIAS_CORE_INERGETIX.md**: Arquitetura completa do sistema
- **copilot-instructions.md**: Regras MVVM obrigatórias do projeto

---

**Status**: ✅ Correção implementada e compilada com sucesso.
**Aguardando**: Teste funcional pelo usuário.
