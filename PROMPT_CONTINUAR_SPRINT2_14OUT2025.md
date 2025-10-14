# 🚀 Prompt para Continuar Sprint 2 - Terapias Bioenergéticas

**Data:** 14 de outubro de 2025
**Sessão Anterior:** Correções críticas UI/UX completadas
**Status Build:** ✅ 0 Errors, 31 Warnings (AForge - harmless)

---

## 📊 CONTEXTO ATUAL DO PROJETO

### Build Status
```bash
dotnet build
# ✅ 0 Errors
# ⚠️ 31 Warnings (apenas AForge compatibility - IGNORAR)
```

### Últimas Alterações Completadas (14/10/2025 - Sessão Noturna)

**6 Bugs Críticos Resolvidos:**

1. ✅ **ProgressBar Saltava Valores** (80→23→2→49)
   - **Fix:** `DummyMedicaoService.cs` linha 47-68
   - Mudado de `_trendFactor += random` para `_trendFactor += 0.015` (linear)
   - Resultado: Crescimento linear 0%→95% (~60 leituras @ 1Hz)

2. ✅ **AlvoMelhoria Imutável** (fixo em 95%)
   - **Fix:** `TerapiaFilaItem.cs` linha 55-73
   - Mudado de `{ get; init; }` para propriedade completa com `INotifyPropertyChanged`
   - Agora observável e editável

3. ✅ **Slider Não Propagava Valores** (mostrava 85%, fila tinha 95%)
   - **Fix:** `TerapiasBioenergeticasUserControlViewModel.cs` linha 517-530
   - Adicionado `OnAlvoMelhoriaGlobalChanged()` partial method
   - Atualiza **TODOS** os itens da fila quando slider move

4. ✅ **Botão "Parar" Sempre Desativado**
   - **Fix:** `TerapiasBioenergeticasUserControlViewModel.cs` linha 407
   - Faltava `NotifyCanExecuteChangedFor(nameof(PararSessaoCommand))`
   - Agora ativa/desativa corretamente com base em `IsSessionRunning`

5. ✅ **Botão "Parar" Não Parava Hardware**
   - **Fix:** `TerapiasBioenergeticasUserControlViewModel.cs` linha 753-775
   - Mudado para `PararSessaoAsync()` com:
     - `_sessaoCts?.Cancel()` (cancela loops)
     - `await _tiePieService.StopAllChannelsAsync()` (para OUTPUT)
     - `await _medicaoService.PararCapturaContinuaAsync()` (para INPUT)

6. ✅ **Secção Monitorização Redundante**
   - **Fix:** `TerapiasBioenergeticasUserControl.xaml`
   - Removida Border com CurrentProtocolName/CurrentProgress/CurrentImprovementPercent
   - Info já estava na tabela (colunas Estado + ProgressBar)

---

## 🎯 SPRINT 2 STATUS: 99% COMPLETO

### Features Implementadas ✅
- ✅ Tabela Fila de Execução atualiza em tempo real
- ✅ ProgressBar visual IN-TABLE (coluna "Melhoria %")
- ✅ Seleção em massa (slider + 5 botões Top N)
- ✅ Crescimento linear de ProgressBar (sem saltos)
- ✅ Alvo configurável (slider 80-100%, steps 5%)
- ✅ Slider sempre visível (header da tabela)
- ✅ Slider atualiza protocolos existentes (não só novos)
- ✅ Botões "Aplicar Terapias" e "Parar" com estados corretos
- ✅ Stop assíncrono completo (hardware + captura + loops)

### Testes Validados ✅
- ✅ Scan completo: 1094 protocolos
- ✅ Adicionar 8 protocolos à fila
- ✅ Slider move para 85% → Todos atualizam
- ✅ Slider move para 100% → Todos atualizam
- ✅ "Aplicar Terapias" inicia sessão → Botão "Parar" ativa
- ✅ ProgressBar cresce linearmente (0%→95%)
- ✅ "Parar" interrompe sessão → Botão "Aplicar Terapias" ativa

---

## 📂 ARQUITETURA DO CÓDIGO

### ViewModels Critical Files
```
src/BioDesk.ViewModels/UserControls/
├── TerapiasBioenergeticasUserControlViewModel.cs  # ViewModel principal (781 linhas)
│   ├── Linha 407: IsSessionRunning [ObservableProperty] + NotifyCanExecuteChanged
│   ├── Linha 444-475: AddToQueue() - aplica AlvoMelhoriaGlobal
│   ├── Linha 517-530: OnAlvoMelhoriaGlobalChanged() - atualiza fila existente
│   ├── Linha 586-681: IniciarSessaoAsync() - loop principal execução
│   ├── Linha 686: CanIniciarSessao() => FilaTerapias.Count > 0 && !IsSessionRunning
│   ├── Linha 753-775: PararSessaoAsync() - stop completo (hardware + captura)
│   └── Linha 777: CanPararSessao() => IsSessionRunning
```

### Services Critical Files
```
src/BioDesk.Services/
├── Medicao/
│   └── DummyMedicaoService.cs  # Simulação biofeedback
│       └── Linha 47-68: _trendFactor += 0.015 (linear growth)
├── Hardware/
│   └── DummyTiePieHardwareService.cs  # Simulação hardware TiePie
└── Backup/
    ├── IBackupService.cs  # Interface backup (recém-editada)
    └── BackupService.cs   # Implementação (recém-editada)
```

### DTOs Critical Files
```
src/BioDesk.Domain/DTOs/
├── TerapiaFilaItem.cs  # DTO observável para fila
│   └── Linha 55-73: AlvoMelhoria property (agora mutável + INotifyPropertyChanged)
└── ProtocoloComValue.cs  # DTO para protocolos escaneados
```

### Views Critical Files
```
src/BioDesk.App/Views/Abas/
└── TerapiasBioenergeticasUserControl.xaml  # UI principal
    ├── Row 0: Header com slider AlvoMelhoriaGlobal (80-100%)
    ├── Row 1: DataGrid FilaTerapias (colunas: Ordem, Nome, Estado, Progresso %, Melhoria %, Alvo %)
    ├── Row 2: Seleção Rápida (slider + 5 botões Top N)
    └── Row 3: Botões "Aplicar Terapias" / "Parar" / "Limpar Fila"
```

---

## 🔧 PADRÕES CRÍTICOS A SEGUIR

### 1. ExecuteWithErrorHandlingAsync (Obrigatório)
```csharp
// ✅ SEMPRE usar em comandos async
[RelayCommand]
private async Task MinhaOperacaoAsync()
{
    await ExecuteWithErrorHandlingAsync(async () =>
    {
        // 1. Validar inputs
        if (string.IsNullOrWhiteSpace(Input)) return;

        // 2. Business logic
        var resultado = await _service.DoSomething();

        // 3. Atualizar UI
        MinhaPropriedade = resultado;
    },
    errorContext: "ao executar operação",
    logger: _logger);
}
```

### 2. Observable Properties com CommunityToolkit.Mvvm
```csharp
// ✅ CORRETO
[ObservableProperty]
private string _minhaPropriedade = string.Empty;

// ✅ Com notificação de CanExecute
[ObservableProperty]
[NotifyCanExecuteChangedFor(nameof(MeuComandoCommand))]
private bool _estadoAtivo;

// ✅ Partial method para reações
partial void OnMinhaPropriedadeChanged(string value)
{
    // Lógica quando propriedade muda
}
```

### 3. RelayCommand com CanExecute
```csharp
// ✅ CORRETO
[RelayCommand(CanExecute = nameof(CanExecutar))]
private async Task MeuComandoAsync()
{
    // Implementação
}

private bool CanExecutar() => CondicaoBooleana;
```

### 4. Dispose Pattern Completo (CA1063)
```csharp
private bool _disposed = false;

public void Dispose()
{
    Dispose(true);
    GC.SuppressFinalize(this);
}

protected virtual void Dispose(bool disposing)
{
    if (!_disposed && disposing)
    {
        _recurso?.Dispose();
    }
    _disposed = true;
}
```

---

## 🚨 REGRAS CRÍTICAS (NÃO QUEBRAR!)

### NUNCA Fazer
1. ❌ NUNCA dizer "problema resolvido" sem `dotnet build` + `dotnet test`
2. ❌ NUNCA adaptar testes para esconder erros
3. ❌ NUNCA ignorar squiggles vermelhos no VS Code
4. ❌ NUNCA usar try-catch para silenciar problemas
5. ❌ NUNCA alterar código funcional sem razão explícita
6. ❌ NUNCA usar hardcoded paths - sempre `PathService`
7. ❌ NUNCA colocar múltiplos UserControls sem `Panel.ZIndex`

### SEMPRE Fazer
1. ✅ SEMPRE verificar build antes e depois: `dotnet clean && dotnet build`
2. ✅ SEMPRE usar `ExecuteWithErrorHandlingAsync` para operações async
3. ✅ SEMPRE validar com FluentValidation antes de gravar
4. ✅ SEMPRE usar `SetPacienteAtivo` antes de `NavigateTo("FichaPaciente")`
5. ✅ SEMPRE implementar Dispose pattern completo (CA1063)
6. ✅ SEMPRE testar navegação entre TODAS as abas após mudanças XAML
7. ✅ SEMPRE usar `PathService` para caminhos de ficheiros
8. ✅ SEMPRE definir `d:DataContext` em UserControls para IntelliSense

---

## 📋 TAREFAS PENDENTES SPRINT 2

### 1. Testes End-to-End (E2E) - PRIORIDADE ALTA ⚠️
**Status:** 0% completo
**Ficheiro:** Criar `src/BioDesk.Tests/E2E/TerapiasBioenergeticasE2ETests.cs`

**Cenários a Testar:**
```csharp
[Fact] public async Task ScanValuesCompleto_Deve_Retornar1094Protocolos() { }
[Fact] public async Task AddToQueue_AplicaAlvoMelhoriaGlobal() { }
[Fact] public async Task AlvoMelhoriaGlobalChanged_AtualizaFilaExistente() { }
[Fact] public async Task IniciarSessao_AtivaBotaoParar() { }
[Fact] public async Task ProgressBar_CrescimentoLinear_SemSaltos() { }
[Fact] public async Task PararSessao_InterrompeExecucao_DesativaBotao() { }
[Fact] public async Task AlvoAtingido_AutoStop() { }
```

### 2. Logs Estruturados - PRIORIDADE MÉDIA
**Status:** 50% completo (logs existem mas não estruturados)
**Ficheiro:** `TerapiasBioenergeticasUserControlViewModel.cs`

**Melhorias:**
- Adicionar structured logging com Serilog
- Exemplo: `_logger.LogInformation("🎯 Alvo alterado de {AlvoAntigo}% para {AlvoNovo}%", old, new)`
- Logs de performance (tempo execução cada protocolo)
- Logs de erro com stack trace completo

### 3. Validação de Dados - PRIORIDADE MÉDIA
**Status:** 0% completo
**Ficheiro:** Criar `TerapiaFilaItemValidator.cs` (FluentValidation)

**Validações Necessárias:**
```csharp
public class TerapiaFilaItemValidator : AbstractValidator<TerapiaFilaItem>
{
    public TerapiaFilaItemValidator()
    {
        RuleFor(x => x.AlvoMelhoria)
            .InclusiveBetween(50.0, 100.0)
            .WithMessage("Alvo deve estar entre 50% e 100%");

        RuleFor(x => x.Nome)
            .NotEmpty()
            .WithMessage("Nome do protocolo obrigatório");
    }
}
```

### 4. Persistência de Estado - PRIORIDADE BAIXA
**Status:** 0% completo
**Ficheiro:** `ConfiguracaoClinicaViewModel.cs` (já existe sistema para outras abas)

**O que Salvar:**
- `AlvoMelhoriaGlobal` (último valor usado)
- `FiltroValueMinimo` (último filtro usado)
- `FilaTerapias` (persistir entre sessões? - discutir com user)

### 5. Documentação Utilizador - PRIORIDADE MÉDIA
**Status:** 0% completo
**Ficheiro:** Criar `MANUAL_TERAPIAS_BIOENERGETICAS.md`

**Conteúdo:**
- Como escanear valores dos protocolos
- O que significa "Value %" e "Improvement %"
- Diferença entre alvos 80%, 95%, 100%
- Como interpretar a barra de progresso
- Quando usar "Parar" vs deixar auto-stop

---

## 🎯 PRÓXIMA TAREFA SUGERIDA

### Opção A: Completar Testes E2E (Mais Urgente)
**Razão:** Garantir que código atual funciona 100% antes de adicionar features
**Tempo Estimado:** 2-3 horas
**Complexidade:** Média (requer mocking de services)

**Comando para Iniciar:**
```bash
# Criar ficheiro de testes
New-Item -Path "src/BioDesk.Tests/E2E" -ItemType Directory -Force
New-Item -Path "src/BioDesk.Tests/E2E/TerapiasBioenergeticasE2ETests.cs" -ItemType File

# Instalar pacotes se necessário
dotnet add src/BioDesk.Tests package Moq --version 4.20.70
dotnet add src/BioDesk.Tests package xunit.assert --version 2.9.2
```

### Opção B: Implementar Validação FluentValidation
**Razão:** Prevenir inputs inválidos (ex: AlvoMelhoria = 150%)
**Tempo Estimado:** 1 hora
**Complexidade:** Baixa (padrão já usado noutras entidades)

### Opção C: Melhorar Logs (Structured Logging)
**Razão:** Debugging mais fácil, troubleshooting em produção
**Tempo Estimado:** 1.5 horas
**Complexidade:** Baixa

---

## 🔍 FICHEIROS RECÉM-EDITADOS (User)

**Atenção:** Estes ficheiros foram editados desde a última sessão:
- `src/BioDesk.Services/Backup/IBackupService.cs`
- `src/BioDesk.Services/Backup/BackupService.cs`
- `SESSAO_14OUT2025_EVOLUCOES.md`
- `AUDITORIA_BACKUP_RESTORE_14OUT2025.md`
- `TAREFAS_PENDENTES_SPRINTS_TERAPIAS_14OUT2025.md`

**SEMPRE** ler estes ficheiros antes de fazer alterações relacionadas com backup!

---

## 🛠️ COMANDOS ÚTEIS

### Build & Run
```bash
# Build limpo
dotnet clean && dotnet restore && dotnet build

# Executar aplicação
dotnet run --project src/BioDesk.App

# Testes
dotnet test src/BioDesk.Tests

# Build verboso (análise CA)
dotnet build --verbosity normal --no-incremental
```

### Git
```bash
# Verificar mudanças
git status
git diff

# Commit (usar mensagens descritivas)
git add .
git commit -m "feat(terapias): corrige IsSessionRunning e AlvoMelhoriaGlobal propagation"
```

---

## 📚 DOCUMENTAÇÃO DE REFERÊNCIA

### Ficheiros de Instruções
- `.github/copilot-instructions.md` - **LEITURA OBRIGATÓRIA** (regras globais)
- `CHECKLIST_ANTI_ERRO_UI.md` - Regras críticas XAML/binding
- `REGRAS_CONSULTAS.md` - Por que consultas não podem ser editadas
- `SISTEMA_CONFIGURACOES.md` - Sistema ConfiguracaoClinicaViewModel
- `PLANO_DESENVOLVIMENTO_RESTANTE.md` - Roadmap funcionalidades futuras
- `RELATORIO_SPRINT2_COMPLETO_12OUT2025.md` - Último sprint report

### Dependências Principais
- **CommunityToolkit.Mvvm** 8.4.0 - `[ObservableProperty]`, `[RelayCommand]`
- **Entity Framework Core** 8.0.10 - SQLite persistence
- **FluentValidation** 11.11.0 - Validação de regras
- **QuestPDF** 2024.10.3 - Geração PDFs
- **AForge** 2.2.5 - Captura câmara (warnings esperados)

---

## 🎯 PROMPT PARA INICIAR NOVO CHAT

**Copiar e colar:**

```
Olá! Estou a desenvolver o BioDeskPro2, um sistema WPF .NET 8 de gestão clínica.

**CONTEXTO:**
- Sprint 2 (Terapias Bioenergéticas) está 99% completo
- Última sessão (14/10/2025): 6 bugs críticos resolvidos ✅
- Build status: 0 Errors, 31 Warnings (AForge - ignorar)
- Aplicação executável e funcional

**FICHEIROS CRÍTICOS:**
- ViewModel: `src/BioDesk.ViewModels/UserControls/TerapiasBioenergeticasUserControlViewModel.cs`
- Service: `src/BioDesk.Services/Medicao/DummyMedicaoService.cs`
- DTO: `src/BioDesk.Domain/DTOs/TerapiaFilaItem.cs`
- View: `src/BioDesk.App/Views/Abas/TerapiasBioenergeticasUserControl.xaml`

**PRÓXIMA TAREFA:**
[ESCOLHE UMA:]
- Opção A: Implementar testes E2E (prioridade alta)
- Opção B: Adicionar validação FluentValidation
- Opção C: Melhorar structured logging

**LEITURA OBRIGATÓRIA ANTES DE COMEÇAR:**
1. Lê `.github/copilot-instructions.md` (regras globais)
2. Lê `PROMPT_CONTINUAR_SPRINT2_14OUT2025.md` (este ficheiro - contexto completo)
3. Verifica `TAREFAS_PENDENTES_SPRINTS_TERAPIAS_14OUT2025.md` (editado recentemente)

**REGRAS CRÍTICAS:**
- SEMPRE executar `dotnet build` antes e depois de mudanças
- NUNCA alterar testes para esconder erros
- SEMPRE usar `ExecuteWithErrorHandlingAsync` em operações async
- SEMPRE verificar ficheiros recém-editados antes de mexer

Pronto para começar? Por favor confirma que leste o contexto e escolhe a tarefa (A/B/C).
```

---

**Criado em:** 14/10/2025 23:45
**Sessão:** Correções críticas Sprint 2 completadas
**Próximo Agente:** Deve ler este ficheiro COMPLETO antes de fazer qualquer alteração!

---

