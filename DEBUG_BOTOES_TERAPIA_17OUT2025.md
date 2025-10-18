# 🔍 DEBUG: Botões de Terapia Não Funcionam
**Data**: 17 de outubro de 2025
**Problema**: Nenhum dos botões que deveriam iniciar a terapia funciona

## 📋 Status Atual

### ✅ Já Implementado (Ontem - 16/OUT/2025)
- **Opção A**: Remoção de modais (BiofeedbackSessionWindow, TerapiaLocalWindow)
- **Execução Direta**: Terapias executam diretamente nos ViewModels
- **Countdown Timers**: Propriedades de progresso adicionadas:
  - `TerapiaEmAndamento / SessaoEmAndamento`
  - `FrequenciaAtual / ProgramaAtual / CicloAtual`
  - `TempoRestanteSegundos`
  - `ProgressoPercentual`
- **TerapiaParametros**: Record criado para transferir configurações
- **Build**: ✅ Passou sem erros (apenas warnings AForge esperados)

### 🐛 Problema Identificado
Os botões **não disparam** a execução da terapia quando clicados.

## 🔬 Logs de Debug Adicionados

Adicionei logs em toda a cadeia de execução:

### 1️⃣ **TerapiaControlosUserControl.xaml.cs**
```csharp
IniciarButton_Click():
- 🟢 TerapiaControlosUserControl: IniciarButton_Click DISPARADO
- 📊 Valores: V=5.0, Duração=30min, Tempo/Freq=10s, Ajuste=0Hz
- 🔗 IniciarClick subscribers: X
- ✅ TerapiaControlosUserControl: Evento IniciarClick invocado
```

### 2️⃣ **RessonantesView.xaml.cs**
```csharp
TerapiaControlos_IniciarClick():
- 🔵 RessonantesView: TerapiaControlos_IniciarClick DISPARADO
- ✅ RessonantesView: ViewModel OK, SelectedItems.Count = X
- 📝 RessonantesView: Parâmetros criados - V=5.0, Duração=30min, Tempo/Freq=10s
- 🔍 RessonantesView: CanExecute = true/false
- ▶️ RessonantesView: Executando comando...
- ✅ RessonantesView: Comando executado
```

### 3️⃣ **RessonantesViewModel.cs**
```csharp
IniciarTerapiaLocalAsync():
- 🚀 RessonantesViewModel: IniciarTerapiaLocalAsync CHAMADO
- 📦 Parâmetros recebidos: V=5.0, Duração=30min, Tempo/Freq=10s
```

## 🧪 Instruções de Teste

### Passo 1: Abrir Debug Output
1. No VS Code, ir a **View → Output**
2. No dropdown à direita, selecionar **Debug Console** ou **Output**
3. Filtrar por "TerapiaControlos", "RessonantesView" ou "RessonantesViewModel"

### Passo 2: Executar Teste de Ressonantes
1. Abrir aplicação (`dotnet run --project src/BioDesk.App`)
2. Navegar para **Terapia → Ressonantes**
3. Executar sweep (se necessário)
4. **SELECIONAR** pelo menos 1 frequência (Ctrl+Click)
5. Clicar no botão **"Iniciar Ressonantes"** (ou similar)

### Passo 3: Analisar Logs

#### ✅ **Cenário Esperado (Funciona)**
```
🟢 TerapiaControlosUserControl: IniciarButton_Click DISPARADO
📊 Valores: V=5.0, Duração=30min, Tempo/Freq=10s, Ajuste=0Hz
🔗 IniciarClick subscribers: 1
✅ TerapiaControlosUserControl: Evento IniciarClick invocado
🔵 RessonantesView: TerapiaControlos_IniciarClick DISPARADO
✅ RessonantesView: ViewModel OK, SelectedItems.Count = 3
📝 RessonantesView: Parâmetros criados - V=5.0, Duração=30min, Tempo/Freq=10s
🔍 RessonantesView: CanExecute = True
▶️ RessonantesView: Executando comando...
🚀 RessonantesViewModel: IniciarTerapiaLocalAsync CHAMADO
📦 Parâmetros recebidos: V=5.0, Duração=30min, Tempo/Freq=10s
```

#### ❌ **Possíveis Cenários de Falha**

##### A) Botão não clica (nenhum log aparece)
**Diagnóstico**: Evento XAML não está ligado
**Solução**: Verificar `<Button Click="IniciarButton_Click"` no TerapiaControlosUserControl.xaml

##### B) Logs param em "IniciarClick subscribers: 0"
**Diagnóstico**: Event handler não está subscrito na View
**Solução**: Verificar `IniciarClick="TerapiaControlos_IniciarClick"` no XAML da View

##### C) Logs param em "CanExecute = False"
**Diagnóstico**: Comando não pode executar (validação falhou)
**Possíveis causas**:
- `TerapiaEmAndamento == true` (já há terapia em curso)
- `SelectedPoints.Count == 0` (nenhuma frequência selecionada no ViewModel)
- Comando está desabilitado por outra razão

**Solução**:
1. Verificar sincronização `ResultadosDataGrid_SelectionChanged` → `vm.SelectedPoints`
2. Verificar se `CanExecute` do `RelayCommand` tem lógica adicional

##### D) Logs chegam ao ViewModel mas nada acontece
**Diagnóstico**: Método async não está a executar loop
**Solução**: Verificar se há `await` correto no while loop

##### E) MessageBox "ViewModel não disponível"
**Diagnóstico**: DataContext não está definido
**Solução**: Verificar Dependency Injection no TerapiaView

## 🎯 Próximos Passos (Após Debug)

### Se o problema for no `CanExecute`:
1. Adicionar log no `CanExecute` do comando
2. Verificar condições no ViewModel

### Se o problema for seleção:
1. Verificar se `ResultadosDataGrid_SelectionChanged` dispara
2. Adicionar logs em `vm.SelectedPoints.Add()`

### Se tudo funcionar mas UI não atualiza:
1. Adicionar bindings XAML para propriedades de progresso:
```xaml
<TextBlock Text="{Binding FrequenciaAtual}" />
<TextBlock Text="{Binding TempoRestanteSegundos, StringFormat='{}Tempo: {0}s'}" />
<ProgressBar Value="{Binding ProgressoPercentual}" Maximum="100" />
```

## 📁 Ficheiros Modificados (Hoje)

1. ✅ `src/BioDesk.App/Controls/TerapiaControlosUserControl.xaml.cs`
2. ✅ `src/BioDesk.App/Views/Terapia/RessonantesView.xaml.cs`
3. ✅ `src/BioDesk.ViewModels/UserControls/Terapia/RessonantesViewModel.cs`

## 🔗 Referências

- **Implementação Ontem**: Commit branch `copilot/vscode1760482146684`
- **Documentação**: SISTEMA_TERAPIAS_CORE_INERGETIX.md
- **Arquitetura**: ARQUITETURA_TERAPIAS_REDESIGN.md

---

**⚠️ IMPORTANTE**: NÃO REMOVER os logs de debug até confirmar que tudo funciona!
Estes logs são essenciais para diagnóstico.
