# BioDesk PRO 2.0 — TESTS-GUIDE.md
*(Escrever testes que apanham erros cedo · RED → GREEN → REFACTOR)*

## 1) Princípios
- **RED → GREEN → REFACTOR**: escrever primeiro o teste que falha, aplicar patch mínimo, limpar.
- **Piramide**: Unidade (VM, validadores) > Integração (EF/Repo/Migrations) > UI (smoke) > Dispositivos (simulados).
- **Sem regressões**: cada bug apanhado = 1 teste novo que fica no repositório.

## 2) Configuração de Testes
- `EnableDetailedErrors()` e `EnableSensitiveDataLogging()` em DEV/TEST.
- SQLite em ficheiro temporário com `WAL` (mais realista que InMemory) e limpeza no fim.
- Transações de teste com rollback para não poluir dados.

## 3) Categorias & Exemplos

### 3.1 Anti-duplicação Paciente (Integração)
```csharp
[Fact]
public async Task NaoPermiteDuplicar_PorNomeNormalizadoEData()
{
    using var db = NewContext();
    await db.Pacientes.AddAsync(new Paciente { NomeNormalizado = "joaosilva", DataNascimento = "1980-05-10" });
    await db.SaveChangesAsync();

    db.Pacientes.Add(new Paciente { NomeNormalizado = "joão silva".NormalizeKey(), DataNascimento = "1980-05-10" });
    await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
}
```

### 3.2 Guard IsDirty (Unidade/VM)
```csharp
[Fact]
public void Navegacao_Bloqueada_QuandoIsDirty()
{
    var vm = new FichaPacienteViewModel(...);
    vm.IsDirty = true;
    var canLeave = vm.CanLeave(); // deve abrir modal no app real; aqui retorna false
    Assert.False(canLeave);
}
```

### 3.3 Outbox (Offline-first)
```csharp
[Fact]
public async Task EmailSemNet_VaiParaOutbox()
{
    var svc = new EmailOutboxService(new FakeNoNetworkSmtp());
    await svc.QueueAsync(1, "Assunto", "<b>Corpo</b>", new[] { "doc.pdf" });
    var itens = await svc.ListAsync();
    Assert.Contains(itens, x => x.Estado == EstadoEmail.Pendente);
}
```

### 3.4 Binding Errors (DEBUG / Smoke)
- Ativar `PresentationTraceSources.DataBindingSource` em DEBUG e falhar o teste se o output contiver “BindingExpression path error”.
- Pequenos testes de UI podem abrir a view e verificar logs (Snapshot testing opcional).

### 3.5 Íris — Calibração & Findings
```csharp
[Fact]
public void Finding_ValidaLimites()
{
    var f = new IrisFinding { Angulo = 361, Severidade = 6 };
    var erros = f.Validate();
    Assert.Contains(erros, e => e.Campo == nameof(f.Angulo));
    Assert.Contains(erros, e => e.Campo == nameof(f.Severidade));
}
```

### 3.6 Quântica — Cancelamento
```csharp
[Fact]
public async Task Emissao_Para_QuandoCancelada()
{
    var device = new QuantumDeviceDemo();
    var cts = new CancellationTokenSource();
    var task = device.EmitirAsync(new Params{Tempo=30000}, cts.Token);
    cts.CancelAfter(50);
    await Assert.ThrowsAsync<TaskCanceledException>(() => task);
}
```

## 4) Pipeline CI (bloqueios)
- `dotnet build -warnaserror`
- `dotnet test --collect:"XPlat Code Coverage"`
- `dotnet format --verify-no-changes`
- Falhar se logs contiverem “BindingExpression path error”.

## 5) UAT — como escrever
- **Roteiro curto (5–10 passos)** por ecrã. Ex.: “Dashboard: procurar Ana → abrir ficha → tentar Capturar Íris sem paciente → ver modal”.
- Critério de aprovação = todos os passos a **✓**. Itens a ✗ viram issues.

## 6) Dicas Práticas
- Sempre que um bug aparece sem teste → criar teste que o reproduza **antes** do patch.
- Usa Fixtures de dados falsos consistentes (6–10 pacientes demo).
- Mantém Helpers para normalização de strings e geração de thumbnails testáveis.
