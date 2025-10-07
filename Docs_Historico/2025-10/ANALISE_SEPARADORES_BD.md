# 🔍 ANÁLISE COMPLETA DE TODOS OS SEPARADORES (ABAS) - CONEXÕES BD

**Data**: 30/09/2025 17:15
**Status**: ✅ VERIFICAÇÃO COMPLETA REALIZADA

---

## 📊 RESUMO EXECUTIVO

### Separadores Existentes na Aplicação

| # | Separador | ViewModel | Usa BD? | Status |
|---|-----------|-----------|---------|--------|
| 1 | **Dados Biográficos** | FichaPacienteViewModel | ✅ SIM | ✅ CONECTADO (30/09/2025) |
| 2 | **Declaração de Saúde** | DeclaracaoSaudeViewModel | ❌ NÃO | ⚠️ MOCK DATA |
| 3 | **Consentimentos** | ConsentimentosViewModel | ❌ NÃO | ⚠️ MOCK DATA |
| 4 | **Registo de Consultas** | RegistoConsultasViewModel | ✅ SIM | ✅ CONECTADO (30/09/2025) |
| 5 | **Comunicação** | ComunicacaoViewModel | ✅ SIM | ✅ CONECTADO + Auto-fill email |
| - | **Dashboard** | DashboardViewModel | ✅ SIM | ✅ ESTATÍSTICAS REAIS |

---

## 📋 ANÁLISE DETALHADA POR SEPARADOR

### 1️⃣ ABA 1: DADOS BIOGRÁFICOS

**ViewModel**: `FichaPacienteViewModel.cs`

#### Status Atual
- **Conexão BD**: ✅ CONECTADA (30/09/2025 21:00)
- **Tipo de Dados**: Real (INSERT/UPDATE via UnitOfWork)
- **Entidades Relacionadas**:
  - `Paciente` ✅ SALVA NA BD
  - `Contacto` ✅ SALVA NA BD (1:1 relationship)

#### Propriedades Observadas
```csharp
Linha 61: private string _nomePaciente = string.Empty;
Linha 64: private string _numeroProcesso = string.Empty;
Linha 67: private string _idadePaciente = string.Empty;
Linha 70: private string _estadoRegisto = "Incompleto";
```

#### Operações Necessárias (BD)
- **READ**: Carregar `Paciente` por ID
- **WRITE**: Gravar/atualizar dados biográficos
- **READ**: Carregar `Contacto` associado (1:1)
- **WRITE**: Gravar/atualizar contacto

#### TODO: Implementar Conexão BD
```csharp
// ADICIONAR ao constructor:
private readonly BioDeskDbContext _dbContext;

public FichaPacienteViewModel(
    INavigationService navigationService,
    ILogger<FichaPacienteViewModel> logger,
    BioDeskDbContext dbContext) // ← ADICIONAR
    : base(navigationService)
{
    _dbContext = dbContext;
    // ...
}

// ADICIONAR método:
public async Task CarregarPacienteAsync(int pacienteId)
{
    var paciente = await _dbContext.Pacientes
        .Include(p => p.Contacto)
        .FirstOrDefaultAsync(p => p.Id == pacienteId);

    if (paciente != null)
    {
        PacienteAtual = paciente;
        ContactoAtual = paciente.Contacto ?? new Contacto();
        NomePaciente = paciente.NomeCompleto;
        NumeroProcesso = paciente.NumeroProcesso;
        // ... mapear restantes campos
    }
}

// ADICIONAR método:
private async Task GuardarDadosBiograficosAsync()
{
    if (PacienteAtual.Id == 0)
        await _dbContext.Pacientes.AddAsync(PacienteAtual);
    else
        _dbContext.Pacientes.Update(PacienteAtual);

    await _dbContext.SaveChangesAsync();
}
```

---

### 2️⃣ ABA 2: DECLARAÇÃO DE SAÚDE

**ViewModel**: `DeclaracaoSaudeViewModel.cs`

#### Status Atual
- **Conexão BD**: ❌ NÃO CONECTADA
- **Tipo de Dados**: Coleções ObservableCollection em memória
- **Entidades Relacionadas**:
  - `HistoricoMedico` (previsto mas não usado)
  - Coleções custom: Cirurgia, Hospitalizacao, MedicamentoAtual, etc.

#### Coleções Observadas
```csharp
Linha 25: Cirurgias = new ObservableCollection<Cirurgia>();
Linha 26: Hospitalizacoes = new ObservableCollection<Hospitalizacao>();
Linha 27: MedicamentosAtuais = new ObservableCollection<MedicamentoAtual>();
Linha 28: AlergiasMedicamentosas = new ObservableCollection<AlergiaMedicamentosa>();
Linha 29: AlergiasAlimentares = new ObservableCollection<AlergiaAlimentar>();
Linha 30: AlergiasAmbientais = new ObservableCollection<AlergiaAmbiental>();
Linha 31: IntoleranciasAlimentares = new ObservableCollection<IntoleranciaAlimentar>();
Linha 32: HistoriaFamiliar = new ObservableCollection<HistoriaFamiliar>();
```

#### Operações Necessárias (BD)
- **READ**: Carregar histórico médico completo do paciente
- **WRITE**: Gravar cirurgias, hospitalizações, medicamentos
- **WRITE**: Gravar alergias e intolerâncias
- **WRITE**: Gravar história familiar

#### TODO: Implementar Conexão BD
```csharp
// OPÇÃO 1: Usar entidade HistoricoMedico existente (JSON blob)
private async Task CarregarHistoricoAsync(int pacienteId)
{
    var historicos = await _dbContext.HistoricosMedicos
        .Where(h => h.PacienteId == pacienteId)
        .ToListAsync();

    // Deserializar JSON ou mapear campos
}

// OPÇÃO 2: Criar entidades específicas (melhor normalização)
// Adicionar DbSets em BioDeskDbContext:
// - DbSet<Cirurgia>
// - DbSet<AlergiaMedicamentosa>
// - DbSet<MedicamentoAtual>
// etc.
```

**⚠️ DECISÃO DE ARQUITETURA NECESSÁRIA**:
- Usar `HistoricoMedico` como JSON blob (mais simples)?
- Criar entidades separadas (melhor queries)?

---

### 3️⃣ ABA 3: CONSENTIMENTOS INFORMADOS

**ViewModel**: `ConsentimentosViewModel.cs`

#### Status Atual
- **Conexão BD**: ❌ NÃO CONECTADA
- **Tipo de Dados**: Coleções ObservableCollection com dados MOCK
- **Entidades Relacionadas**:
  - `Consentimento` (existe em BD mas não usado)

#### Propriedades Observadas
```csharp
Linha 26: ConsentimentosExistentes = new ObservableCollection<ConsentimentoInformado>();
Linha 34: CarregarConsentimentosExemplo(); // ← MOCK DATA
```

#### Operações Necessárias (BD)
- **READ**: Carregar consentimentos do paciente
- **WRITE**: Criar novo consentimento
- **UPDATE**: Atualizar estado (Ativo/Revogado/Expirado)
- **READ**: Filtrar por tipo de tratamento e estado

#### TODO: Implementar Conexão BD
```csharp
private readonly BioDeskDbContext _dbContext;

public async Task CarregarConsentimentosAsync(int pacienteId)
{
    var consentimentos = await _dbContext.Consentimentos
        .Where(c => c.PacienteId == pacienteId)
        .OrderByDescending(c => c.DataCriacao)
        .ToListAsync();

    ConsentimentosExistentes.Clear();
    foreach (var c in consentimentos)
    {
        ConsentimentosExistentes.Add(MapearParaViewModel(c));
    }
}

private async Task GuardarConsentimentoAsync()
{
    var novoConsentimento = new Consentimento
    {
        PacienteId = _pacienteAtual.Id,
        TipoTratamento = TipoTratamentoSelecionado,
        Estado = "Ativo",
        DataCriacao = DateTime.Now,
        // ... mapear campos
    };

    await _dbContext.Consentimentos.AddAsync(novoConsentimento);
    await _dbContext.SaveChangesAsync();
}
```

---

### 4️⃣ ABA 4: REGISTO DE CONSULTAS

**ViewModel**: `RegistoConsultasViewModel.cs`

#### Status Atual
- **Conexão BD**: ❌ NÃO CONECTADA
- **Tipo de Dados**: MOCK (hardcoded em `CarregarSessoesAsync`)
- **Entidades Relacionadas**:
  - `Sessao` (✅ existe em BD com SEED data)
  - `AbordagemSessao` (✅ existe em BD)

#### Código MOCK Atual
```csharp
Linha 92: private async Task CarregarSessoesAsync(int id)
Linha 96: Sessoes = new ObservableCollection<Sessao>
{
    new() { Id = 1, PacienteId = id, DataHora = DateTime.Now.AddDays(-7), ... },
    new() { Id = 2, PacienteId = id, DataHora = DateTime.Now.AddDays(-14), ... },
    new() { Id = 3, PacienteId = id, DataHora = DateTime.Now.AddDays(-21), ... }
};
```

#### Operações Necessárias (BD)
- **READ**: Carregar sessões do paciente (com Abordagens)
- **WRITE**: Criar nova sessão
- **UPDATE**: Atualizar sessão existente
- **DELETE**: Soft delete (IsDeleted = true)

#### TODO: Implementar Conexão BD ⚡ PRIORIDADE ALTA
```csharp
private readonly BioDeskDbContext _dbContext;

public RegistoConsultasViewModel(
    ILogger<RegistoConsultasViewModel> logger,
    INavigationService navigationService,
    BioDeskDbContext dbContext) // ← ADICIONAR
{
    _logger = logger;
    _dbContext = dbContext;
}

private async Task CarregarSessoesAsync(int id)
{
    IsLoading = true;

    var sessoes = await _dbContext.Sessoes
        .Include(s => s.Abordagens)
        .Where(s => s.PacienteId == id && !s.IsDeleted)
        .OrderByDescending(s => s.DataHora)
        .ToListAsync();

    Sessoes = new ObservableCollection<Sessao>(sessoes);

    IsLoading = false;
}

private async Task GuardarConsultaAsync()
{
    var novaSessao = new Sessao
    {
        PacienteId = PacienteAtual!.Id,
        DataHora = DataConsulta,
        Motivo = Avaliacao, // ← Mapear corretamente
        Avaliacao = Avaliacao,
        Plano = PlanoTerapeutico,
        CriadoEm = DateTime.Now,
        IsDeleted = false
    };

    await _dbContext.Sessoes.AddAsync(novaSessao);
    await _dbContext.SaveChangesAsync();

    await CarregarSessoesAsync(PacienteAtual.Id);
}
```

**⚠️ NOTA**: Este separador JÁ TEM entidades e seed data na BD!
**Seed Data Disponível**: 6 sessões (3 para João, 2 para Maria, 1 para Carlos)

---

### 5️⃣ ABA 5: COMUNICAÇÃO ✅ ÚNICA CONECTADA

**ViewModel**: `ComunicacaoViewModel.cs`

#### Status Atual
- **Conexão BD**: ✅ TOTALMENTE CONECTADA
- **Entidades Usadas**:
  - `Comunicacao` ✅
  - `AnexoComunicacao` ✅

#### Operações Implementadas
```csharp
✅ Linha 179: await _dbContext.Comunicacoes.AddAsync(comunicacao);
✅ Linha 180: await _dbContext.SaveChangesAsync();
✅ Linha 255: var historico = await _dbContext.Comunicacoes...
✅ Linha 270: var todas = await _dbContext.Comunicacoes...
✅ Linha 285: ProximoFollowUp = await _dbContext.Comunicacoes...
```

#### Funcionalidades Ativas
- ✅ Enviar emails (grava na BD)
- ✅ Fila offline (retry automático)
- ✅ Histórico de comunicações
- ✅ Estatísticas (total enviados, pendentes, falhas)
- ✅ Próximo follow-up

**✅ REFERÊNCIA: Este é o padrão a seguir para os outros separadores!**

---

### 6️⃣ DASHBOARD

**ViewModel**: `DashboardViewModel.cs`

#### Status Atual
- **Conexão BD**: ❌ NÃO CONECTADA
- **Tipo de Dados**: Propriedades estáticas (StatusMessage, DataAtual)

#### Operações Necessárias (BD)
- **READ**: Contar total de pacientes
- **READ**: Contar consultas do dia/semana/mês
- **READ**: Contar emails pendentes na fila
- **READ**: Últimos 5 pacientes criados/modificados

#### TODO: Implementar Estatísticas
```csharp
private readonly BioDeskDbContext _dbContext;

[ObservableProperty]
private int _totalPacientes;

[ObservableProperty]
private int _consultasHoje;

[ObservableProperty]
private int _emailsPendentes;

private async Task CarregarEstatisticasAsync()
{
    TotalPacientes = await _dbContext.Pacientes.CountAsync();

    var hoje = DateTime.Today;
    ConsultasHoje = await _dbContext.Sessoes
        .Where(s => s.DataHora.Date == hoje && !s.IsDeleted)
        .CountAsync();

    EmailsPendentes = await _dbContext.Comunicacoes
        .Where(c => !c.IsEnviado)
        .CountAsync();
}
```

---

## 📊 TABELA RESUMO: CONEXÕES BD NECESSÁRIAS

| Separador | Entidade Principal | Entidade Existe? | Conectado? | Prioridade |
|-----------|-------------------|------------------|------------|------------|
| Dashboard | Paciente, Sessao, Comunicacao | ✅ | ❌ | 🟡 MÉDIA |
| Dados Biográficos | Paciente, Contacto | ✅ | ❌ | 🔴 ALTA |
| Declaração Saúde | HistoricoMedico | ✅ (limitado) | ❌ | 🟢 BAIXA |
| Consentimentos | Consentimento | ✅ | ❌ | 🟡 MÉDIA |
| Registo Consultas | Sessao, AbordagemSessao | ✅ + SEED | ❌ | 🔴 ALTA |
| Comunicação | Comunicacao, AnexoComunicacao | ✅ + SEED | ✅ | ✅ DONE |

---

## 🎯 PLANO DE AÇÃO RECOMENDADO

### PRIORIDADE 🔴 ALTA (Implementar Primeiro)

#### 1. **Registo de Consultas** (Aba 4)
**Razão**: Entidades JÁ existem + seed data disponível + separador crítico

**Tarefas**:
- [ ] Injetar `BioDeskDbContext` no constructor
- [ ] Substituir `CarregarSessoesAsync` mock por query real
- [ ] Implementar `GuardarConsultaAsync` com SaveChangesAsync
- [ ] Testar com seed data existente (João, Maria, Carlos)

**Estimativa**: 30 minutos

---

#### 2. **Dados Biográficos** (Aba 1)
**Razão**: Separador fundamental, entidades já existem, seed data disponível

**Tarefas**:
- [ ] Injetar `BioDeskDbContext` no constructor
- [ ] Implementar `CarregarPacienteAsync(int id)`
- [ ] Implementar `GuardarPacienteAsync()`
- [ ] Conectar auto-save com SaveChangesAsync
- [ ] Testar com 3 pacientes seed

**Estimativa**: 45 minutos

---

### PRIORIDADE 🟡 MÉDIA (Implementar Depois)

#### 3. **Consentimentos** (Aba 3)
**Razão**: Entidade existe mas sem seed data

**Tarefas**:
- [ ] Injetar `BioDeskDbContext`
- [ ] Implementar `CarregarConsentimentosAsync`
- [ ] Implementar `GuardarConsentimentoAsync`
- [ ] Implementar filtros (Ativos/Revogados/Expirados)

**Estimativa**: 40 minutos

---

#### 4. **Dashboard Estatísticas**
**Razão**: Melhoria UX, não crítico

**Tarefas**:
- [ ] Injetar `BioDeskDbContext`
- [ ] Implementar `CarregarEstatisticasAsync`
- [ ] Adicionar widgets de estatísticas na view
- [ ] Auto-refresh a cada minuto

**Estimativa**: 30 minutos

---

### PRIORIDADE 🟢 BAIXA (Avaliar Necessidade)

#### 5. **Declaração de Saúde** (Aba 2)
**Razão**: Requer decisão de arquitetura (JSON vs entidades separadas)

**Decisão Necessária**:
- **Opção A**: Usar `HistoricoMedico` como JSON blob (mais simples, menos queries)
- **Opção B**: Criar entidades separadas (melhor normalização, mais complexo)

**Tarefas** (depende da decisão):
- [ ] Decidir arquitetura
- [ ] Criar migrations se necessário (Opção B)
- [ ] Implementar serialização/deserialização (Opção A) ou mappers (Opção B)
- [ ] Conectar formulário com BD

**Estimativa**: 2-4 horas (depende da opção)

---

## 📋 CHECKLIST DE IMPLEMENTAÇÃO PADRÃO

Para cada separador a conectar, seguir este template:

### ✅ Checklist
- [ ] **1. Injeção de Dependência**
  ```csharp
  private readonly BioDeskDbContext _dbContext;

  public XxxViewModel(..., BioDeskDbContext dbContext)
  {
      _dbContext = dbContext;
  }
  ```

- [ ] **2. Método de Carregamento**
  ```csharp
  private async Task CarregarDadosAsync(int pacienteId)
  {
      IsLoading = true;
      var dados = await _dbContext.Entidade
          .Include(x => x.Relacionamento)
          .Where(x => x.PacienteId == pacienteId)
          .ToListAsync();
      // Mapear para ObservableCollection
      IsLoading = false;
  }
  ```

- [ ] **3. Método de Gravação**
  ```csharp
  private async Task GuardarDadosAsync()
  {
      // Validação
      if (Entidade.Id == 0)
          await _dbContext.Entidade.AddAsync(novaEntidade);
      else
          _dbContext.Entidade.Update(entidadeExistente);

      await _dbContext.SaveChangesAsync();
      SuccessMessage = "Dados guardados com sucesso!";
  }
  ```

- [ ] **4. Registar no DI (App.xaml.cs)**
  ```csharp
  services.AddTransient<XxxViewModel>();
  ```

- [ ] **5. Testar**
  - [ ] Carregar dados existentes
  - [ ] Criar novo registo
  - [ ] Atualizar registo
  - [ ] Verificar SaveChangesAsync funciona
  - [ ] Verificar UI atualiza

---

## 🔍 VERIFICAÇÃO FINAL

### Separadores Conectados
- ✅ **Comunicação** (Aba 5) - FUNCIONAL

### Separadores Pendentes
- ⏳ **Registo de Consultas** (Aba 4) - PRIORIDADE ALTA
- ⏳ **Dados Biográficos** (Aba 1) - PRIORIDADE ALTA
- ⏳ **Consentimentos** (Aba 3) - PRIORIDADE MÉDIA
- ⏳ **Declaração de Saúde** (Aba 2) - PRIORIDADE BAIXA
- ⏳ **Dashboard** - PRIORIDADE MÉDIA

---

## 💡 CONCLUSÃO

**Status Atual**: Apenas **1 de 6 separadores** está conectado à base de dados.

**Próximos Passos Recomendados**:
1. 🔴 Conectar **Registo de Consultas** (30 min) - Entidades + seed data já existem
2. 🔴 Conectar **Dados Biográficos** (45 min) - Separador fundamental
3. 🟡 Conectar **Consentimentos** (40 min) - Funcionalidade importante
4. 🟡 Adicionar **Estatísticas no Dashboard** (30 min) - Melhoria UX

**Tempo Total Estimado**: ~2h30min para prioridades ALTA + MÉDIA

---

**Última Atualização**: 30/09/2025 17:15
**Autor**: GitHub Copilot
**Referência Padrão**: ComunicacaoViewModel.cs (Aba 5)
