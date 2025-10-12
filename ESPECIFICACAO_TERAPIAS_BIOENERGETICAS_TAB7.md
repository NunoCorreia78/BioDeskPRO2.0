# 🌿 BioDesk Tab 7 — Especificação Técnica Completa (v1)
**Data**: 12 de Outubro de 2025
**Origem**: Plano ChatGPT (sessão 68ebfc22-6a80-8011-9861-f9e2899b60d9)
**Status**: 📋 PLANEADO - Aguarda Implementação

> Implementação integral do módulo de **Terapias Bioenergéticas** "tipo CoRe 5.0, mas moderno", com avaliação (Value %), Improvement %, protocolos em Excel, controlo de voltagem/corrente/frequência (AWG TiePie HS3), biofeedback fisiológico e suporte opcional a RNG físico (Alea/Hologram Generator).

---

## 1) Objetivo & Âmbito

* Replicar o **fluxo funcional do Inergetix-CoRe v5.0** (Resonant Frequencies, Biofeedback, Frequency Program) com UI moderna, segurança clínica e rastreabilidade total.
* Incluir **3 modos de operação**: determinístico (seed por sessão), **RNG físico Alea** (CoRe-like), e **biofeedback fisiológico** (recomendado) usando o TiePie HS3.
* Importar/gerir **protocolos** via Excel (idempotência por `ExternalId`).
* Produzir **relatórios** com Value % iniciais e Improvement % finais + parâmetros emitidos.

---

## 2) Fluxo funcional (espelhado do CoRe)

1. **Abrir ficha do paciente** (pré-requisito).
2. **Avaliação (Resonant-like)**: gerar lista ordenada por **Value %** (topo = 100%; limiar configurável, ex. >30%).
3. **Seleção** de itens e **criação de fila** de emissão (ou uso direto de **Frequency Program/Excel**).
4. **Execução sequencial** (não mistura ondas) com controlo de **Frequência/Amplitude/Forma/Canal/Tempo**.
5. **Improvement % em tempo real** durante a emissão; quando ~100%, **desmarcar e seguir**.
6. **Fecho e relatório**: Value % inicial, Improvement % final, parâmetros, tempo total, notas.

---

## 3) Modos de "fonte de aleatoriedade"

* **A) Determinístico (CSPRNG + seed por sessão)**: reprodutibilidade/auditoria; seed única por sessão (derivada de SessaoId/DataHora).
* **B) RNG físico (Alea/Hologram)**: "CoRe-like" (não reprodutível), opcional e automático quando o dispositivo é detetado.
* **C) Fisiológico**: sem RNG — avaliação/ajuste pela resposta medida (RMS, Pico, FFT, Impedância/GSR).

Padrão: **Fisiológico ON** + **Alea se presente**; fallback para **Determinístico**.

---

## 4) Arquitetura

* **.NET 8 LTS** · **WPF** · **MVVM (CommunityToolkit.Mvvm)** · **EF Core + SQLite** · **Repository + Unit of Work** · **FluentValidation** · **ILogger**.
* **Serviços**: `IMedicaoService` (medição + AWG), `IRandomSource`, `IExcelImportService`, `IProtocoloService`, `ISessaoService`.
* **UI**: Tab 7 (`TerapiasUserControl`), **LiveCharts2** para tempo real + FFT.
* **Threads**: captura em background (Task + `CancellationToken`), comunicação via `Channels`.

### 4.1 Diagrama (alto nível)

```
UI (TerapiasUserControl)
  ↕ (bindings/commands)
ViewModel (TerapiasViewModel)
  ↔ IMedicaoService (TiePieService/Mock)
  ↔ IProtocoloService (carrega/resolve sequência)
  ↔ IRandomSource (Alea | Deterministic | System)
  ↔ IExcelImportService (EPPlus/ClosedXML)
  ↔ ISessaoService (persistência, relatórios)
  ↔ ILogger / IValidator
```

---

## 5) Modelo de Domínio (BD)

**Tabelas (principais)**

* `Paciente` (já existente) ✅
* `Sessao` (já existente) ✅
* `PlanoTerapia` *(ex-TerapiaProgramada)*: Id, Nome, Categoria, Notas, VersaoSchema, CreatedAt/By, etc.
* `ProtocoloTerapeutico`: Id, Nome, Categoria, Fonte (Excel/Custom), JsonParametros, Versao, Hash.
* `Terapia` (catálogo base): Id, Nome, Categoria, ResumoParametros.
* `SessaoTerapia`: Id, SessaoId (FK), ProtocoloId (FK), Status (Pendente/EmCurso/Concluída/Cancelada), Canal, Forma, FrequenciaHz, AmplitudeV, LimiteCorrenteMa, DuracaoMin, Ordem, StartedAt, EndedAt, ImprovementFinal, ValueInicial, RngInfo, AlgVersao, ConsentimentoId, DispositivoSerial, CreatedAt/By, ModifiedAt/By, SoftDelete.
* `LeituraBioenergetica`: Id, SessaoTerapiaId (FK), SampleRate, Canal, PathBruto, Rms, Pico, FreqDominante, EspectroResumoJson, Inicio, Fim.
* `EventoHardware`: Id, SessaoId, Tipo (Connected/Disconnected/Error/Overlimit), Detalhe, Timestamp.
* `ImportacaoExcelLog`: Id, Arquivo, VersaoSchema, LinhasOk, WarningsJson, ErrosJson, Data.

**Índices**: `SessaoTerapia(SessaoId, Ordem)`, `LeituraBioenergetica(SessaoTerapiaId)`, `ProtocoloTerapeutico(Nome)`, `ImportacaoExcelLog(Data)`.

**Armazenamento bruto**: amostras **fora da BD** (ficheiro `.bin` ou `.csv.gz`) em `Data/Sessions/{SessaoId}/{SessaoTerapiaId}.bin`; BD guarda o **path** + estatísticas.

---

## 6) Integração Hardware — TiePie HS3

* **Descoberta**: enumerar dispositivos, obter **serial**, capacidades (AWG, faixas, sample rates).
* **Captura**: iniciar leitura em **thread** dedicada, buffer circular, downsampling para UI.
* **AWG/Output**: configurar forma (Sine/Square/Triangle/Saw), Hz, Vpp, offset, duty, canal; iniciar/pausar/parar.
* **Segurança**: **limites hard** (ex. AmplitudeV ≤ 20 V; LimiteCorrenteMa ≤ 50 mA).
* **Eventos**: Connected/Disconnected/Overlimit/Error → UI.

**Interface (essencial)**

```csharp
public interface IMedicaoService {
    DeviceInfo DispositivoAtual { get; }
    Task<bool> ProcurarAsync(CancellationToken ct);
    Task ConectarAsync(string serial, CancellationToken ct);
    Task DesconectarAsync();

    // Captura
    IAsyncEnumerable<LeituraAmostra> LerAsync(LeituraConfig cfg, CancellationToken ct);

    // AWG / Output
    Task IniciarEmissaoAsync(SaidaConfig cfg, CancellationToken ct);
    Task PausarEmissaoAsync();
    Task PararEmissaoAsync();
}
```

---

## 7) RNG & Seeds

**Interface**

```csharp
public interface IRandomSource {
    void NextBytes(Span<byte> buffer);
    string Id { get; } // "DeterministicCSPRNG:v1", "AleaRNG:v1", "SystemRNG"
}
```

**Implementações**

* `DeterministicCsprng(seed: byte[32])` — **seed guardada** por sessão (`ScanSeedHex`).
* `AleaRngSource` — integra o teu Alea (se ligado).
* `SystemRngSource` — fallback.

**Estratégia por sessão**:

```
if (AleaDetetado) rng = AleaRng;
else rng = DeterministicCsprng(SeedSessao);
```

SeedSessao = HMAC(appSecret, PacienteId|SessaoId|DataHoraISO).

---

## 8) Algoritmos

### 8.1 Value % (Resonant-like)

* **Determinístico/Alea**: usa RNG para gerar um score-base por item (estável por sessão) e normaliza para [0..100].
* **Fisiológico**: realiza **mini-sweeps** (rápidos) e calcula score por **melhoria de métricas** (queda de RMS, pico espectral pontiagudo, variação de impedância).
* **Peso combinado** (se ambos ativos): `Score = w_rng*ScoreRng + w_phys*ScorePhys` (configurável).
* **Ordenação**: desc a 100%; **limiar default 30%**.

### 8.2 Improvement % (durante emissão)

**Métricas**: RMS(t), Pico(t), FreqDom(t), Espectralidade/Entropia(t), Impedância/GSR(t).
**EMA**: `emaX(t) = α*X(t) + (1-α)*emaX(t-1)` (α≈0.2).
**Heurística** (exemplo):

```
base = clamp01((RMS0 - RMSt)/RMS0) * 0.4
     + clamp01((Pico0 - Picot)/Pico0) * 0.2
     + clamp01(|FreqDomShift|/limiarHz) * 0.2
     + clamp01((GSRt - GSR0)/escalaGSR) * 0.2
Improvement% = round(100 * clamp01(base))
```

Quando `Improvement% ≥ alvo` (ex. 95–100), **auto-desmarcar** item e seguir o próximo.

---

## 9) Excel v1 — Schema & Validação

**Colunas**

* `ExternalId` (GUID) — **idempotência**
* `Nome` (string, obrigatório)
* `Categoria` (string)
* `FrequenciaHz` (decimal > 0)
* `AmplitudeV` (decimal 0..20)
* `LimiteCorrenteMa` (int 0..50)
* `FormaOnda` (enum: Sine|Square|Triangle|Saw)
* `Modulacao` (enum: None|AM|FM|Burst)
* `DuracaoMin` (int 1..180)
* `Canal` (string/int)
* `SequenciaJSON` (JSON opcional: etapas com Hz/min/amp)
* `Contraindicacoes` (string)
* `Notas` (string)
* `Versao` (int)

**Validação (FluentValidation)**

* Campos obrigatórios, ranges, enums válidos;
* **Pré-visualização** no UI; relatório com **OK/Warnings/Erros**, **Upsert** por `ExternalId`.

---

## 10) UI/UX (Tab 7)

* **Topo**: Estado do Dispositivo · Consentimento · Paciente · Ações (Abrir Consentimento/Exportar Sessão).
* **Coluna 1**: Catálogo + Pesquisa · **Importar Excel** · **Fila (Plano de Terapia)** com `Ordem/Nome/Hz/V/mA/Min` + ações (Adicionar/Remover/Guardar como Protocolo).
* **Coluna 2**: Controlo de Saída (Amplitude, Corrente, Frequência, Forma, Modulação, Canal) + Botões (Iniciar/Pausar/Parar) · **Biofeedback** (Impedância, GSR, Mensagens).
* **Coluna 3**: **Gráfico tempo real** (LiveCharts2) · **FFT** · Indicadores (Freq. Dom, Pico, RMS, Tempo) · **Improvement %** por item.
* **Checklist pré‑sessão**: consentimento OK, dispositivo pronto, protocolo válido, limites seguros → só então habilita "Iniciar".
* **Acessibilidade**: textos legíveis, contraste suficiente, tamanhos de clique ≥ 36 px.

---

## 11) ViewModel (resumo de propriedades/comandos)

```csharp
class TerapiasViewModel : ObservableObject {
  // Estado
  public string EstadoDispositivo { get; }
  public string DispositivoNome { get; }
  public bool PodeIniciar { get; }
  public bool SessaoEmCurso { get; }

  // Catálogo & Fila
  public ObservableCollection<TerapiaDto> TerapiasFiltradas { get; }
  public TerapiaDto? TerapiaSelecionada { get; set; }
  public ObservableCollection<ItemFilaDto> FilaTerapias { get; }

  // Controlo
  public double AmplitudeV { get; set; }
  public int LimiteCorrenteMa { get; set; }
  public double FrequenciaHz { get; set; }
  public string FormaOndaSelecionada { get; set; }
  public string CanalSelecionado { get; set; }

  // Medições/Indicadores
  public double Rms { get; }
  public double AmplitudePico { get; }
  public double FrequenciaDominante { get; }
  public TimeSpan TempoDecorrido { get; }

  // Comandos
  public IRelayCommand ImportarExcelCommand { get; }
  public IRelayCommand AdicionarTerapiaSelecionadaCommand { get; }
  public IRelayCommand GuardarFilaComoProtocoloCommand { get; }
  public IRelayCommand IniciarSessaoCommand { get; }
  public IRelayCommand PausarSessaoCommand { get; }
  public IRelayCommand PararSessaoCommand { get; }
}
```

---

## 12) Logging & Erros

* **Categorias**: `Hardware`, `Algoritmo`, `Importacao`, `Persistencia`, `UI`.
* **Códigos**: `HW_TIMEOUT`, `HW_DISCONNECTED`, `HW_OVERLIMIT`, `IMPORT_SCHEMA_INVALID`, `IMPORT_DUPLICATE_ID`, `ALGO_CONFIG_INVALID`.
* **UI**: banners legíveis e ações de retry.
* **Anexar logs** à sessão em caso de falha.

---

## 13) Segurança & GDPR

* **Consentimento** obrigatório ligado a cada `SessaoTerapia` (hash SHA256 do PDF assinado + timestamp + cédula profissional).
* **Minimização**: guardar bruto apenas quando justificável; **retenção** configurável; export "Right to Access".
* **Audit trail**: Created/Modified/Deleted (soft) + utilizador responsável.

---

## 14) Testes

* **Unit**: ViewModel, validadores, importador, calculadora de Value%/Improvement%.
* **Contract**: `IMedicaoService` (TiePie vs Mock) — mesmas assinaturas/comportamentos esperados.
* **Golden tests**: ficheiros de amostra → resultado esperado (para não "partir" o algoritmo).
* **Hardware-in-the-loop**: script lê 10 s @1 kHz e valida SNR/latência.
* **UI Smoke**: inicialização com Mock + bindings básicos OK.

---

## 15) Performance

* **Buffer ring** com backpressure para UI.
* **Downsampling** para gráficos; armazenamento bruto sem passar pela UI.
* **LiveCharts2**: séries reusadas; limitar pontos visíveis; `EnableAnimations=false` em tempo real.

---

## 16) Deployment

* **Installer**: MSIX/WiX; pergunta pasta de dados; cria `Data/` e `Logs/`.
* **Pré‑requisitos**: .NET 8, driver TiePie, permissões de USB.
* **Config**: `appsettings.json` (limites V/mA, paths, flags RNG/biofeedback, paleta).
* **Paths**: dados por utilizador em `%ProgramData%/BioDesk/` ou `%LOCALAPPDATA%/BioDesk/`.

---

## 17) Versionamento & Migração

* **SemVer** de app e **AlgoritmoVersao** (guardado na sessão).
* EF Core **Migrations**; compatibilidade ascend./descend. de Excel (campo `Versao`).

---

## 18) Riscos & Mitigações

* **Dependência Alea** (descontinuado) → opcional; fallback deterministic.
* **Carga de CPU** (FFT) → usar FFT otimizadas e janelas curtas; limitar FPS gráfico.
* **Segurança elétrica** → limites hard V/mA; check de impedância e pausa automática.
* **Dados volumosos** → ficheiro externo por sessão + compressão.

---

## 19) "Definição de Feito" (Tab 7)

1. ✅ Lista **Value %** (limiar 30%) + **Fila** + execução **sequencial**.
2. ✅ **Improvement %** ao vivo por item; auto‑desmarcar ao atingir alvo.
3. ✅ AWG TiePie a emitir com controlo de Hz/V/Forma/Canal/Tempo; **limites hard**.
4. ✅ Importação Excel v1 **idempotente** + relatório e pré‑visualização.
5. ✅ Sessão gravada: metadados, ficheiro bruto, estatísticas, consentimento, Rng/Seed/AlgVersao.
6. ✅ Logs estruturados + mensagens de erro claras.

---

## 20) Estimativas (referência)

* Entidades/BD: 4–6 h
* Abstração hardware + Mock: 3–4 h
* TiePie Service (captura + AWG): 6–10 h
* Algoritmos (Value/Improvement) + testes: 6–8 h
* Importador Excel + validação + UI pré‑view: 5–7 h
* UI Tab 7 completa (LiveCharts2 + FFT + estados + histórico): 12–16 h
* Relatórios + export: 3–4 h
* Documentação final + runbook: 3–4 h

**Total**: ~42–59 h (variável com drivers/FFT e polimento de UI).

---

## 21) Snippets essenciais

### 21.1 Deterministic CSPRNG (seed)

```csharp
public sealed class DeterministicCsprng : IRandomSource, IDisposable {
  private readonly HMACSHA256 _hmac; private ulong _ctr;
  public string Id => "DeterministicCSPRNG:v1";
  public DeterministicCsprng(ReadOnlySpan<byte> seed) {
    var key = SHA256.HashData(seed); _hmac = new HMACSHA256(key);
  }
  public void NextBytes(Span<byte> buffer) {
    int off=0; Span<byte> blk=stackalloc byte[32];
    while(off<buffer.Length){ Span<byte> ctr=stackalloc byte[8];
      BitConverter.TryWriteBytes(ctr,_ctr); if(BitConverter.IsLittleEndian) ctr.Reverse();
      _hmac.TryComputeHash(ctr, blk, out _); int n=Math.Min(blk.Length, buffer.Length-off);
      blk[..n].CopyTo(buffer.Slice(off,n)); off+=n; _ctr++; }
  }
  public void Dispose()=>_hmac.Dispose();
}
```

### 21.2 IMedicaoService (assinaturas base)

```csharp
public record LeituraConfig(double SampleRate, string Canal, TimeSpan Janela);
public record SaidaConfig(double FrequenciaHz, double AmplitudeV, string Forma, string Canal, double? LimiteCorrenteMa, TimeSpan Duracao);
public record LeituraAmostra(DateTimeOffset T, double Rms, double Pico, double FreqDom, double[]? Espectro);
```

### 21.3 Validador Excel (trecho)

```csharp
RuleFor(x=>x.Nome).NotEmpty();
RuleFor(x=>x.FrequenciaHz).GreaterThan(0);
RuleFor(x=>x.AmplitudeV).InclusiveBetween(0,20);
RuleFor(x=>x.LimiteCorrenteMa).InclusiveBetween(0,50);
RuleFor(x=>x.FormaOnda).Must(v=> new[]{"Sine","Square","Triangle","Saw"}.Contains(v));
```

---

## 22) Próximos Passos

1. ✅ Fechar **schema Excel v1** (ficheiro base + 5 exemplos).
2. ⏸️ Implementar **IMedicaoService** (Mock) + **LiveCharts2** com feed em tempo real.
3. ⏸️ Implementar **Value % + Improvement %** (v1) com testes.
4. ⏸️ Integrar **TiePie HS3** (captura + AWG).
5. ⏸️ Ligar **importação Excel** e **relatórios**.

---

## 🔗 Integração com Arquitetura BioDeskPro2 Existente

### ✅ **COMPATÍVEL COM INFRAESTRUTURA ATUAL**:

1. **Base de Dados**:
   - `Paciente` e `Sessao` já existem ✅
   - `TipoAbordagem.MedicinaBioenergetica` já definido ✅
   - EF Core Migrations prontas para novas tabelas

2. **Arquitetura MVVM**:
   - `ViewModelBase` com `ExecuteWithErrorHandlingAsync` ✅
   - `[ObservableProperty]` e `[RelayCommand]` CommunityToolkit ✅
   - Dependency Injection em `App.xaml.cs` ✅

3. **Padrões Estabelecidos**:
   - Repository Pattern + UnitOfWork ✅
   - FluentValidation para regras de negócio ✅
   - PathService para gestão de ficheiros ✅
   - ILogger estruturado ✅

### 🆕 **NOVAS DEPENDÊNCIAS NECESSÁRIAS**:

1. **LiveCharts2**: Gráficos tempo real
   ```bash
   dotnet add package LiveChartsCore.SkiaSharpView.WPF
   ```

2. **Excel Import**: EPPlus ou ClosedXML
   ```bash
   dotnet add package EPPlus --version 7.0.0
   # ou
   dotnet add package ClosedXML --version 0.102.0
   ```

3. **TiePie SDK**: Driver C# (wrapper nativo)
   - Requer SDK do fabricante + wrapper .NET

4. **FFT Library**: Math.NET Numerics
   ```bash
   dotnet add package MathNet.Numerics --version 5.0.0
   ```

---

## 📋 Estrutura de Pastas Proposta

```
src/
├── BioDesk.Domain/
│   └── Entities/
│       ├── PlanoTerapia.cs (NOVO)
│       ├── ProtocoloTerapeutico.cs (NOVO)
│       ├── Terapia.cs (NOVO)
│       ├── SessaoTerapia.cs (NOVO)
│       ├── LeituraBioenergetica.cs (NOVO)
│       ├── EventoHardware.cs (NOVO)
│       └── ImportacaoExcelLog.cs (NOVO)
│
├── BioDesk.Data/
│   ├── Migrations/ (7 novas migrations)
│   └── Repositories/
│       ├── ITerapiaRepository.cs (NOVO)
│       ├── IProtocoloRepository.cs (NOVO)
│       └── ISessaoTerapiaRepository.cs (NOVO)
│
├── BioDesk.Services/
│   ├── Medicao/
│   │   ├── IMedicaoService.cs (NOVO)
│   │   ├── TiePieService.cs (NOVO)
│   │   └── MockMedicaoService.cs (NOVO)
│   ├── RNG/
│   │   ├── IRandomSource.cs (NOVO)
│   │   ├── DeterministicCsprng.cs (NOVO)
│   │   ├── AleaRngSource.cs (NOVO - opcional)
│   │   └── SystemRngSource.cs (NOVO)
│   ├── Excel/
│   │   ├── IExcelImportService.cs (NOVO)
│   │   └── ExcelImportService.cs (NOVO)
│   └── Terapias/
│       ├── IProtocoloService.cs (NOVO)
│       ├── ProtocoloService.cs (NOVO)
│       └── AlgoritmosService.cs (NOVO - Value%/Improvement%)
│
├── BioDesk.ViewModels/
│   ├── Abas/
│   │   └── TerapiasViewModel.cs (NOVO)
│   └── Validators/
│       └── ProtocoloExcelValidator.cs (NOVO)
│
└── BioDesk.App/
    └── Views/
        └── Abas/
            └── TerapiasUserControl.xaml (NOVO)
```

---

## ⚠️ DECISÕES CRÍTICAS ANTES DE INICIAR

### 1. **Hardware TiePie HS3**
- ❓ Tem o dispositivo fisicamente disponível?
- ❓ SDK/Drivers instalados e testados?
- ❓ Documentação API disponível?

**Recomendação**: Iniciar com **MockMedicaoService** e testar UI/algoritmos **SEM hardware** primeiro.

### 2. **Alea RNG (Opcional)**
- ❓ Dispositivo disponível?
- ❓ SDK/API disponível?

**Recomendação**: Implementar apenas **DeterministicCsprng** inicialmente (suficiente para auditorias).

### 3. **Excel Schema Definitivo**
- ❓ Tem exemplos de protocolos reais em Excel?
- ❓ Campos adicionais necessários além dos especificados?

**Recomendação**: Criar **template Excel v1.0** com 5 protocolos exemplo antes de codificar.

### 4. **Prioridade de Implementação**
**Opção A - MVP Rápido (2-3 semanas)**:
1. UI básica + Mock (sem hardware)
2. Algoritmos Value%/Improvement% (modo determinístico)
3. Importação Excel
4. Relatórios simples

**Opção B - Completo (6-8 semanas)**:
1. Todas as tabelas BD
2. TiePie integration completa
3. LiveCharts2 + FFT tempo real
4. RNG físico Alea
5. Relatórios avançados + export

---

## 🚀 PRÓXIMO PASSO IMEDIATO

Escolha UMA opção:

### **A) Começar MVP (SEM hardware)** ✅ RECOMENDADO
```bash
1. Criar entidades BD básicas (PlanoTerapia, ProtocoloTerapeutico, SessaoTerapia)
2. Migration EF Core
3. MockMedicaoService (retorna dados sintéticos)
4. UI Tab 7 básica (sem gráficos tempo real)
5. Algoritmo Value% determinístico
6. Importador Excel v1
```
**Tempo**: 2-3 semanas
**Vantagem**: Funcional rapidamente, testável sem hardware

### **B) Aguardar Decisões** ⏸️
Responder às 4 perguntas críticas acima antes de começar.

### **C) Criar Template Excel Primeiro** 📊
Definir schema Excel definitivo com 5-10 protocolos exemplo.

---

**Qual opção prefere para começar?** 🤔
