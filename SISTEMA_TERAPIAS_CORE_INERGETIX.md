# 🌿 Sistema de Terapias BioDeskPro2 - Guia Completo
## Inspirado no Core Inergetix System

**Data:** 16 de outubro de 2025
**Versão:** 1.0
**Status:** Estrutura criada, aguardando implementação completa

---

## 📋 Índice

1. [Visão Geral do Sistema](#visão-geral-do-sistema)
2. [Arquitetura Atual](#arquitetura-atual)
3. [Explicação Detalhada dos 5 Sub-Separadores](#explicação-detalhada-dos-5-sub-separadores)
4. [Onde Colar o Excel de Frequências](#onde-colar-o-excel-de-frequências)
5. [Plano de Implementação Core Inergetix](#plano-de-implementação-core-inergetix)
6. [Roadmap de Desenvolvimento](#roadmap-de-desenvolvimento)

---

## 1. Visão Geral do Sistema

### 🎯 Objetivo
Replicar as funcionalidades principais do **Inergetix CoRe 5.0**, um sistema de biofeedback e biorressonância que combina níveis informacionais e energéticos:

- **Avaliação Informacional** (via gerador de eventos aleatórios - REG)
- **Base de Dados** de >110.000 itens (doenças, frequências, remédios, emoções)
- **Balanceamento Local** (frequências físicas via hardware)
- **Balanceamento Remoto** (transmissão informacional quântica)
- **Biofeedback em Tempo Real** (ajuste automático de frequências)

### 🏗️ Estrutura Atual (7 Abas)
```
📋 Dados Biográficos
🏥 Declaração Saúde
📄 Consentimentos
🏥 Consultas
👁️ Íris
📧 Emails
🌿 Terapias ← FOCO DESTE DOCUMENTO
    ├── Avaliacao (Scan informacional)
    ├── Programas (Protocolos de frequências)
    ├── Ressonantes (Frequency sweeps)
    ├── Biofeedback (Emissão local/remota)
    └── Historico (Sessões anteriores)
```

---

## 2. Arquitetura Atual

### 📂 Ficheiros Principais

```
src/BioDesk.App/Views/Terapia/
├── TerapiaCoreView.xaml          # Container principal (TabControl)
├── AvaliacaoView.xaml             # Sub-aba 1
├── ProgramasView.xaml             # Sub-aba 2
├── RessonantesView.xaml           # Sub-aba 3
├── BiofeedbackView.xaml           # Sub-aba 4
└── HistoricoView.xaml             # Sub-aba 5

src/BioDesk.ViewModels/UserControls/Terapia/
├── TerapiaCoreViewModel.cs        # Orquestrador principal
├── AvaliacaoViewModel.cs          # Lógica de scan
├── ProgramasViewModel.cs          # Gestão de programas
├── RessonantesViewModel.cs        # Frequency sweeps
├── BiofeedbackViewModel.cs        # Emissão de frequências
└── HistoricoViewModel.cs          # Histórico de sessões
```

### 🔗 Dependency Injection (App.xaml.cs)
```csharp
// ViewModels registados como Transient
services.AddTransient<TerapiaCoreViewModel>();
services.AddTransient<AvaliacaoViewModel>();
services.AddTransient<ProgramasViewModel>();
services.AddTransient<RessonantesViewModel>();
services.AddTransient<BiofeedbackViewModel>();
services.AddTransient<HistoricoViewModel>();

// UserControl com DI no construtor
services.AddTransient<TerapiasUserControl>();
```

---

## 3. Explicação Detalhada dos 5 Sub-Separadores

### 🔬 **Sub-Aba 1: AVALIAÇÃO**
**Objetivo:** Simular o "scan informacional" do CoRe (análise via REG).

#### Campos e Funcionalidade:

| Campo | Descrição | Equivalente CoRe |
|-------|-----------|------------------|
| **Fonte da semente** | Origem do seed para RNG (nome paciente, timestamp, etc.) | Client data (name, DOB, photo) |
| **Gerador RNG** | Tipo de gerador aleatório (Pseudo, Hardware, Quantum) | Holographic REG (PEAR-based) |
| **Salt da sessão** | Salt único para cada sessão (botão "Regenerar") | Session entropy |
| **Iterações** | Nº de testes micro (ex: 10000 = simula 10k testes musculares) | Rapid testing iterations |

#### Botões:
- **Executar scan**: Inicia análise informacional contra base de dados
- **Adicionar à lista ativa**: Move itens ressonantes (>30%) para terapia
- **Guardar sessão**: Persiste resultados na BD para histórico

#### DataGrid Resultados:
| Coluna | Significado |
|--------|-------------|
| **Nome** | Item da base de dados (ex: "Fígado", "Ansiedade", "Vitamina C") |
| **Código** | ID interno ou código de classificação |
| **Categoria** | Grupo (Órgão, Emoção, Patógeno, Remédio) |
| **Score** | % de ressonância (100% = maior, >30% = significativo) |
| **Rank** | Posição ordenada por relevância |

#### 🧠 Lógica de Funcionamento (a implementar):
```csharp
// Pseudocódigo simplificado
1. Gerar seed único = Hash(NomePaciente + DataNascimento + SessionSalt)
2. Inicializar RNG com seed
3. Para cada item da base de dados (loop de Iterações):
   - Gerar número aleatório
   - Comparar com "assinatura" do item
   - Contar coincidências significativas
4. Rankear itens por % de coincidências
5. Retornar top 50-100 resultados (threshold >30%)
```

#### 📊 Base de Dados Necessária:
```sql
CREATE TABLE ItensInformacionais (
    Id INT PRIMARY KEY,
    Nome NVARCHAR(200),
    Codigo NVARCHAR(50),
    Categoria NVARCHAR(100), -- Orgao, Emocao, Patogeno, Remedio, Chakra, etc.
    FrequenciaHz DECIMAL(10,2), -- Frequência associada (se houver)
    Descricao NVARCHAR(MAX),
    Tags NVARCHAR(500) -- Para pesquisa
);
```

**Total Estimado:** 5.000-10.000 itens inicialmente (vs 110.000 do CoRe completo).

---

### 📋 **Sub-Aba 2: PROGRAMAS**
**Objetivo:** Biblioteca de protocolos terapêuticos pré-definidos (ex: "Detox Hepático", "Lyme Protocol").

#### ⚠️ **ONDE COLAR O EXCEL DE FREQUÊNCIAS** ← RESPOSTA DIRETA!

##### Localização no Interface:
```
🌿 Terapias → Programas
```

##### Campos:
| Campo | Descrição | Ação |
|-------|-----------|------|
| **Caminho Excel** | Textbox para caminho do ficheiro | Preencher com `C:\Frequencias\programa.xlsx` |
| **Botão "Importar Excel"** | Carrega Excel → Cria programa na BD | **← CLICAR AQUI APÓS COLAR CAMINHO** |
| **Pesquisa** | Filtrar programas por nome | Ex: "Lyme" |
| **Botão "Atualizar"** | Recarregar lista de programas | Refresh após import |

##### Estrutura do Excel Esperada:
```excel
# Ficheiro: programa_detox_hepatico.xlsx
# Folha: Passos

| # | Hz      | Duty | Segundos | Notas                          |
|---|---------|------|----------|--------------------------------|
| 1 | 728.00  | 50   | 180      | Frequência base Rife           |
| 2 | 880.00  | 50   | 180      | Reforço imunológico            |
| 3 | 5000.00 | 30   | 120      | Estímulo hepático              |
| 4 | 2008.00 | 50   | 240      | Drenagem linfática             |
```

**Colunas Obrigatórias:**
- `#` ou `Index`: Ordem de execução
- `Hz`: Frequência em Hertz (ex: 728.00)
- `Duty`: Ciclo de trabalho % (ex: 50 = onda quadrada 50/50)
- `Segundos`: Duração do passo (ex: 180 = 3 minutos)
- `Notas`: Descrição opcional

##### Lógica de Importação (a implementar):
```csharp
// ProgramasViewModel.cs
[RelayCommand]
private async Task ImportExcel()
{
    // 1. Validar caminho Excel
    if (!File.Exists(ExcelPath)) return;

    // 2. Ler Excel (EPPlus ou ClosedXML)
    var workbook = new ExcelPackage(new FileInfo(ExcelPath));
    var worksheet = workbook.Workbook.Worksheets[0];

    // 3. Parsear linhas (skip header)
    var steps = new List<ProgramStep>();
    for (int row = 2; row <= worksheet.Dimension.End.Row; row++)
    {
        steps.Add(new ProgramStep
        {
            Index = int.Parse(worksheet.Cells[row, 1].Value?.ToString() ?? "0"),
            Hz = decimal.Parse(worksheet.Cells[row, 2].Value?.ToString() ?? "0"),
            Duty = int.Parse(worksheet.Cells[row, 3].Value?.ToString() ?? "50"),
            Seconds = int.Parse(worksheet.Cells[row, 4].Value?.ToString() ?? "60"),
            Notes = worksheet.Cells[row, 5].Value?.ToString() ?? ""
        });
    }

    // 4. Criar programa na BD
    var programa = new TerapiaPrograma
    {
        Nome = Path.GetFileNameWithoutExtension(ExcelPath),
        DataCriacao = DateTime.Now,
        Steps = steps
    };

    await _unitOfWork.TerapiaProgramas.AddAsync(programa);
    await _unitOfWork.SaveChangesAsync();

    // 5. Refresh lista
    await LoadProgramsAsync();
}
```

##### Exemplo de Excel Pré-Formatado:
**Criar ficheiro:** `C:\Frequencias\Templates\template_programa.xlsx`

```
Folha "Passos":
#  | Hz     | Duty | Segundos | Notas
1  | 728    | 50   | 180      | Descrição passo 1
2  | 880    | 50   | 120      | Descrição passo 2
```

**Instruções:**
1. Preencher valores
2. Guardar como `.xlsx`
3. Colar caminho completo no campo "Caminho Excel"
4. Clicar "Importar Excel"

---

### 🔊 **Sub-Aba 3: RESSONANTES**
**Objetivo:** Frequency sweep (varredura automática) para encontrar frequências ressonantes personalizadas.

#### Campos:

| Campo | Descrição | Exemplo |
|-------|-----------|---------|
| **Início (Hz)** | Frequência inicial do sweep | 1 |
| **Fim (Hz)** | Frequência final | 10000 |
| **Passo (Hz)** | Incremento entre testes | 10 (testa 1, 11, 21...) |
| **Dwell (ms)** | Tempo de permanência por frequência | 100 (0.1s por step) |

#### Funcionamento:
1. Sistema varre de `Início` até `Fim` em incrementos de `Passo`
2. Em cada frequência, permanece `Dwell` ms
3. **Com hardware:** Mede resposta biológica (GSR, HRV, etc.)
4. **Sem hardware (modo simulado):** Usa algoritmo probabilístico
5. Ranqueia frequências por "score de ressonância"
6. Permite adicionar top frequencies à lista ativa

#### DataGrid Resultados:
| Coluna | Significado |
|--------|-------------|
| **Hz** | Frequência testada |
| **Score** | % de ressonância detectada |
| **Notas** | Anotações automáticas (ex: "Possível pico") |

#### 🧠 Algoritmo de Sweep (a implementar):
```csharp
// RessonantesViewModel.cs
[RelayCommand]
private async Task RunSweep()
{
    SweepResults.Clear();

    for (decimal hz = StartHz; hz <= StopHz; hz += StepHz)
    {
        // Simular medição (substituir por leitura real de hardware)
        var score = SimulateBiofeedback(hz);

        if (score > 30) // Threshold de significância
        {
            SweepResults.Add(new SweepPoint
            {
                Hz = hz,
                Score = score,
                Notes = score > 70 ? "Pico forte" : "Ressonância"
            });
        }

        await Task.Delay(DwellMs); // Aguardar Dwell
    }

    // Ordenar por score descendente
    SweepResults = new ObservableCollection<SweepPoint>(
        SweepResults.OrderByDescending(x => x.Score));
}

private double SimulateBiofeedback(decimal hz)
{
    // Simulação: Usar RNG + curva gaussiana em torno de frequências conhecidas
    var rng = new Random();
    var baseScore = rng.NextDouble() * 30; // Ruído base 0-30%

    // Picos simulados em frequências Rife conhecidas
    var rifeFreqs = new[] { 728, 880, 2008, 5000, 10000 };
    foreach (var rife in rifeFreqs)
    {
        var distance = Math.Abs((double)hz - rife);
        if (distance < 50) // Janela de 50 Hz
        {
            baseScore += (50 - distance) * 2; // Boost até +100%
        }
    }

    return Math.Min(baseScore, 100);
}
```

---

### ⚡ **Sub-Aba 4: BIOFEEDBACK**
**Objetivo:** Emissão de frequências terapêuticas (local ou remota).

#### Secção: Lista Ativa
**DataGrid com itens selecionados** das abas Avaliação, Programas ou Ressonantes.

| Coluna | Origem |
|--------|--------|
| Nome | Item da base de dados ou programa |
| Categoria | Classificação |
| Score | Relevância para o paciente |
| Rank | Ordem de prioridade |

#### Secção: Configuração Geral

| Campo | Valores | Significado |
|-------|---------|-------------|
| **Modo** | Local / Remoto | Tipo de emissão |
| **Estado** | Parado / Executando / Pausado | Status atual |

#### Secção: Emissão Local (Modo Físico)
**Visível apenas quando Modo = Local**

| Campo | Descrição | Faixa Típica |
|-------|-----------|--------------|
| **Forma de onda** | Senoidal, Quadrada, Triangular, Dente de serra | Quadrada (padrão Rife) |
| **Frequência (Hz)** | Frequência principal a emitir | 1-10000 Hz |
| **Duty (%)** | Ciclo de trabalho (% de tempo ON) | 10-90% |
| **Vpp (V)** | Tensão pico-a-pico | 0.1-10V (segurança) |
| **Limite corrente (mA)** | Máximo de corrente permitida | 0.1-5 mA |
| **Compliance (V)** | Tensão máxima de segurança | 12V |

**Hardware Necessário:**
- **Gerador de Funções** programável (ex: MHS-5200A, Rigol DG1022)
- **Interface USB** (FTDI, CH340)
- **Aplicadores:** Eletrodos, bobinas magnéticas, LEDs pulsantes

**Comunicação:**
```csharp
// Exemplo com gerador MHS-5200A via porta série
public class FrequencyGenerator : IDisposable
{
    private SerialPort _port;

    public void SetFrequency(decimal hz, int duty)
    {
        // Comando exemplo: ":w00=728.00,50.\r\n"
        var command = $":w00={hz:F2},{duty}.\r\n";
        _port.WriteLine(command);
    }

    public void Start() => _port.WriteLine(":w00=1.\r\n");
    public void Stop() => _port.WriteLine(":w00=0.\r\n");
}
```

#### Secção: Emissão Remota (Modo Informacional)
**Visível apenas quando Modo = Remoto**

| Campo | Descrição | Conceito CoRe |
|-------|-----------|---------------|
| **Âncora** | Identificador único do cliente | Nome + DOB + Foto (hash) |
| **Hash** | Algoritmo de hash (SHA256, MD5) | Assinatura informacional |
| **Modulação** | Tipo de modulação (AM, FM, PWM) | Carrier informacional |
| **Ciclos** | Nº de repetições do padrão | Reforço por repetição |
| **Tempo item (s)** | Duração por item da lista ativa | Exposição por frequência |
| **On (ms)** / **Off (ms)** | Pulsos ON/OFF | Ritmo de emissão |
| **Verificar drift** | Monitorizar desvio do RNG | Garantir estabilidade |

**Conceito Teórico:**
- Transmissão via **campo informacional** (não eletromagnético clássico)
- Usa gerador holográfico (REG) para modular "intenção"
- Baseado em física quântica (não-localidade, entrelaçamento)
- **Não requer internet ou proximidade física**

**Implementação Prática (discussão filosófica):**
```csharp
// RemoteTransmitter.cs
public class RemoteTransmitter
{
    public async Task TransmitInformational(
        string anchor,        // Hash do paciente
        List<Item> items,     // Itens a transmitir
        int durationSeconds)
    {
        var anchorHash = ComputeHash(anchor);

        foreach (var item in items)
        {
            // Modular padrão informacional
            var pattern = GenerateInformationalPattern(item, anchorHash);

            // "Broadcast" via RNG ou audio/visual encoding
            await BroadcastPattern(pattern, durationSeconds);
        }
    }

    private byte[] GenerateInformationalPattern(Item item, byte[] anchor)
    {
        // Combinar frequência do item + hash do paciente
        var combined = BitConverter.GetBytes((double)item.FrequenciaHz)
            .Concat(anchor)
            .ToArray();

        // Gerar sequência pseudoaleatória baseada nesse padrão
        using var rng = new RNGCryptoServiceProvider();
        var pattern = new byte[1024];
        rng.GetBytes(pattern);

        // XOR com combined para "imprimir" informação
        for (int i = 0; i < pattern.Length; i++)
        {
            pattern[i] ^= combined[i % combined.Length];
        }

        return pattern;
    }

    private async Task BroadcastPattern(byte[] pattern, int seconds)
    {
        // Emissão via:
        // 1. Audio (sub-threshold, 16-20 kHz)
        // 2. Visual (flicker imperceptível)
        // 3. RNG output file (para radiônica)

        await Task.Delay(seconds * 1000);
    }
}
```

#### Secção: Execução

| Botão | Função |
|-------|--------|
| **Iniciar** | Começa emissão (local ou remota) |
| **Pausar** | Suspende temporariamente |
| **Parar** | Termina sessão (salva no histórico) |
| **Emergência** | STOP imediato + desliga hardware |

**TextBox Telemetria:** Mostra logs em tempo real:
```
[10:15:32] Iniciando sessão - Modo: Local
[10:15:33] Item 1/5: Fígado (728 Hz, 50% duty)
[10:15:35] Corrente: 1.2 mA, Tensão: 3.5V
[10:18:33] Item 1/5 concluído
[10:18:34] Item 2/5: Ansiedade (7.83 Hz, 30% duty)
...
```

---

### 📚 **Sub-Aba 5: HISTÓRICO**
**Objetivo:** Registo permanente de todas as sessões realizadas.

#### DataGrid de Sessões:

| Coluna | Descrição |
|--------|-----------|
| **Data** | Timestamp da sessão (dd/MM/yyyy HH:mm) |
| **Seed** | Seed usado no RNG (para reprodução) |
| **RNG** | Tipo de gerador utilizado |
| **Iterações** | Nº de micro-testes realizados |
| **Resumo** | Texto livre (ex: "Scan focado em fígado") |

#### Funcionalidade (a implementar):
- **Auto-save** ao finalizar sessão (botão "Parar" no Biofeedback)
- **Clicar em linha** → Carrega detalhes da sessão em modal
- **Exportar para PDF** → Relatório com gráficos
- **Comparar sessões** → Evolução ao longo do tempo

```csharp
// Entidade BD
public class SessaoTerapia
{
    public int Id { get; set; }
    public int PacienteId { get; set; }
    public DateTime DataSessao { get; set; }
    public string Seed { get; set; } = string.Empty;
    public string TipoRNG { get; set; } = string.Empty;
    public int Iteracoes { get; set; }
    public string Resumo { get; set; } = string.Empty;
    public string ResultadosJson { get; set; } = string.Empty; // JSON com lista de itens
}
```

---

## 4. Onde Colar o Excel de Frequências (Resumo)

### ✅ Localização: `🌿 Terapias → Programas`

### 📝 Passos Completos:

1. **Preparar Excel:**
   ```excel
   Folha: Passos
   Colunas: # | Hz | Duty | Segundos | Notas
   ```

2. **Navegar:**
   ```
   Ficha Paciente → Aba "🌿 Terapias" → Sub-aba "Programas"
   ```

3. **Colar Caminho:**
   ```
   Campo "Caminho Excel": C:\Frequencias\meu_programa.xlsx
   ```

4. **Importar:**
   ```
   Botão "Importar Excel" → Aguardar "Importado com sucesso!"
   ```

5. **Verificar:**
   ```
   Lista "Programas" (esquerda) → Deve aparecer nome do ficheiro
   DataGrid "Passos" (direita) → Deve mostrar todos os passos
   ```

6. **Utilizar:**
   ```
   Selecionar programa → "Adicionar à lista ativa" → Ir para "Biofeedback"
   ```

---

## 5. Plano de Implementação Core Inergetix

### 📊 Componentes Principais a Desenvolver

#### **5.1. Base de Dados Informacional**

**Entidades Necessárias:**

```csharp
// Domain/Entities/ItemInformacional.cs
public class ItemInformacional
{
    public int Id { get; set; }
    public string Nome { get; set; } = string.Empty;
    public string Codigo { get; set; } = string.Empty;
    public string Categoria { get; set; } = string.Empty; // Orgao, Emocao, Patogeno, etc.
    public decimal? FrequenciaHz { get; set; }
    public string Descricao { get; set; } = string.Empty;
    public string Tags { get; set; } = string.Empty;
}

// Domain/Entities/TerapiaPrograma.cs
public class TerapiaPrograma
{
    public int Id { get; set; }
    public string Nome { get; set; } = string.Empty;
    public DateTime DataCriacao { get; set; }
    public List<ProgramaStep> Steps { get; set; } = new();
}

public class ProgramaStep
{
    public int Id { get; set; }
    public int ProgramaId { get; set; }
    public int Index { get; set; }
    public decimal Hz { get; set; }
    public int Duty { get; set; }
    public int Segundos { get; set; }
    public string Notas { get; set; } = string.Empty;
}

// Domain/Entities/SessaoTerapia.cs
public class SessaoTerapia
{
    public int Id { get; set; }
    public int PacienteId { get; set; }
    public DateTime DataSessao { get; set; }
    public string Seed { get; set; } = string.Empty;
    public string TipoRNG { get; set; } = string.Empty;
    public int Iteracoes { get; set; }
    public string ModoEmissao { get; set; } = string.Empty; // Local/Remoto
    public string ResultadosJson { get; set; } = string.Empty;
    public string TelemetriaJson { get; set; } = string.Empty;
}
```

**Migration (Entity Framework):**
```bash
dotnet ef migrations add AddTerapiaTables -p src/BioDesk.Data -s src/BioDesk.App
dotnet ef database update -p src/BioDesk.Data -s src/BioDesk.App
```

**Seed Inicial (100 itens exemplo):**
```csharp
// Data/Seed/ItensInformacionaisSeed.cs
modelBuilder.Entity<ItemInformacional>().HasData(
    // Órgãos
    new ItemInformacional { Id = 1, Nome = "Fígado", Codigo = "ORG-001", Categoria = "Orgao", FrequenciaHz = 728 },
    new ItemInformacional { Id = 2, Nome = "Rins", Codigo = "ORG-002", Categoria = "Orgao", FrequenciaHz = 880 },

    // Emoções
    new ItemInformacional { Id = 50, Nome = "Ansiedade", Codigo = "EMO-001", Categoria = "Emocao", FrequenciaHz = 7.83m },
    new ItemInformacional { Id = 51, Nome = "Depressão", Codigo = "EMO-002", Categoria = "Emocao", FrequenciaHz = 10.00m },

    // Patógenos (Frequências Rife)
    new ItemInformacional { Id = 100, Nome = "Candida", Codigo = "PAT-001", Categoria = "Patogeno", FrequenciaHz = 464 },
    new ItemInformacional { Id = 101, Nome = "Borrelia (Lyme)", Codigo = "PAT-002", Categoria = "Patogeno", FrequenciaHz = 432 }

    // ... adicionar até 5000-10000 itens
);
```

#### **5.2. Algoritmo de Scan Informacional**

**Serviço de Análise:**
```csharp
// Services/Terapia/InformationalScanService.cs
public class InformationalScanService : IInformationalScanService
{
    private readonly IUnitOfWork _unitOfWork;
    private readonly IRNGService _rngService;

    public async Task<List<ScanResult>> ExecutarScanAsync(
        string seedSource,
        string rngEngine,
        string sessionSalt,
        int iterations)
    {
        // 1. Gerar seed único
        var seed = GenerateSeed(seedSource, sessionSalt);

        // 2. Obter todos os itens da BD
        var items = await _unitOfWork.ItensInformacionais.GetAllAsync();

        // 3. Inicializar RNG
        var rng = _rngService.CreateGenerator(rngEngine, seed);

        // 4. Executar análise
        var coincidencias = new Dictionary<int, int>(); // ItemId -> Contagem

        for (int i = 0; i < iterations; i++)
        {
            var randomValue = rng.NextDouble();

            // Comparar com cada item (simplificado)
            foreach (var item in items)
            {
                var itemSignature = ComputeItemSignature(item);

                if (Math.Abs(randomValue - itemSignature) < 0.01) // Threshold
                {
                    if (!coincidencias.ContainsKey(item.Id))
                        coincidencias[item.Id] = 0;

                    coincidencias[item.Id]++;
                }
            }
        }

        // 5. Calcular scores e rankear
        var maxCoincidencias = coincidencias.Values.Max();

        var results = coincidencias
            .Select(kvp => new ScanResult
            {
                ItemId = kvp.Key,
                Name = items.First(i => i.Id == kvp.Key).Nome,
                Code = items.First(i => i.Id == kvp.Key).Codigo,
                Category = items.First(i => i.Id == kvp.Key).Categoria,
                ScorePercent = (double)kvp.Value / maxCoincidencias * 100,
                Rank = 0 // Será preenchido após ordenação
            })
            .Where(r => r.ScorePercent >= 30) // Threshold de significância
            .OrderByDescending(r => r.ScorePercent)
            .ToList();

        // Atribuir ranks
        for (int i = 0; i < results.Count; i++)
        {
            results[i].Rank = i + 1;
        }

        return results;
    }

    private double ComputeItemSignature(ItemInformacional item)
    {
        // Converter características do item numa assinatura 0-1
        var hash = item.Nome.GetHashCode() ^ item.Categoria.GetHashCode();

        if (item.FrequenciaHz.HasValue)
            hash ^= ((int)item.FrequenciaHz.Value).GetHashCode();

        return Math.Abs(hash) / (double)int.MaxValue;
    }

    private string GenerateSeed(string seedSource, string salt)
    {
        using var sha256 = SHA256.Create();
        var bytes = Encoding.UTF8.GetBytes(seedSource + salt);
        var hash = sha256.ComputeHash(bytes);
        return Convert.ToBase64String(hash);
    }
}
```

#### **5.3. Importador de Excel**

**NuGet Packages:**
```xml
<PackageReference Include="EPPlus" Version="7.0.0" />
<!-- ou -->
<PackageReference Include="ClosedXML" Version="0.102.0" />
```

**Serviço:**
```csharp
// Services/Terapia/ExcelImportService.cs
public class ExcelImportService : IExcelImportService
{
    public TerapiaPrograma ImportarPrograma(string excelPath)
    {
        using var package = new ExcelPackage(new FileInfo(excelPath));
        var worksheet = package.Workbook.Worksheets[0]; // Primeira folha

        var programa = new TerapiaPrograma
        {
            Nome = Path.GetFileNameWithoutExtension(excelPath),
            DataCriacao = DateTime.Now,
            Steps = new List<ProgramaStep>()
        };

        // Ler linhas (skip header row 1)
        for (int row = 2; row <= worksheet.Dimension.End.Row; row++)
        {
            var index = int.Parse(worksheet.Cells[row, 1].Value?.ToString() ?? "0");
            var hz = decimal.Parse(worksheet.Cells[row, 2].Value?.ToString() ?? "0");
            var duty = int.Parse(worksheet.Cells[row, 3].Value?.ToString() ?? "50");
            var seconds = int.Parse(worksheet.Cells[row, 4].Value?.ToString() ?? "60");
            var notes = worksheet.Cells[row, 5].Value?.ToString() ?? "";

            programa.Steps.Add(new ProgramaStep
            {
                Index = index,
                Hz = hz,
                Duty = duty,
                Segundos = seconds,
                Notas = notes
            });
        }

        return programa;
    }
}
```

#### **5.4. Gerador de Frequências (Hardware)**

**Interface USB com Gerador de Funções:**

```csharp
// Services/Hardware/FrequencyGeneratorService.cs
public class FrequencyGeneratorService : IFrequencyGeneratorService, IDisposable
{
    private SerialPort? _port;

    public void Connect(string portName = "COM3", int baudRate = 57600)
    {
        _port = new SerialPort(portName, baudRate);
        _port.Open();
    }

    public void SetWaveform(Waveform type)
    {
        // Comandos variam por modelo de gerador
        // Exemplo: MHS-5200A
        var command = type switch
        {
            Waveform.Sine => ":w00=0.\r\n",
            Waveform.Square => ":w00=1.\r\n",
            Waveform.Triangle => ":w00=2.\r\n",
            _ => ":w00=1.\r\n"
        };
        _port?.WriteLine(command);
    }

    public void SetFrequency(decimal hz, int duty)
    {
        var command = $":w00={hz:F2},{duty}.\r\n";
        _port?.WriteLine(command);
    }

    public void SetAmplitude(decimal vpp)
    {
        var command = $":w20={vpp:F2}.\r\n";
        _port?.WriteLine(command);
    }

    public void Start() => _port?.WriteLine(":w00=1.\r\n");
    public void Stop() => _port?.WriteLine(":w00=0.\r\n");

    public void Dispose()
    {
        Stop();
        _port?.Close();
        _port?.Dispose();
    }
}

public enum Waveform
{
    Sine,
    Square,
    Triangle,
    Sawtooth
}
```

**DI Registration:**
```csharp
// App.xaml.cs
services.AddSingleton<IFrequencyGeneratorService, FrequencyGeneratorService>();
```

#### **5.5. Transmissão Remota (Informacional)**

**Abordagem Prática (Radiônica Digital):**

```csharp
// Services/Terapia/RemoteTransmissionService.cs
public class RemoteTransmissionService : IRemoteTransmissionService
{
    public async Task TransmitirInformacionalAsync(
        string anchor,
        List<ItemInformacional> items,
        RemoteConfig config)
    {
        var anchorHash = ComputeAnchorHash(anchor);

        foreach (var item in items)
        {
            // Gerar padrão informacional
            var pattern = GeneratePattern(item, anchorHash, config);

            // Emitir via múltiplos canais
            await EmitAudioPattern(pattern, config.PerItemSeconds);
            await EmitVisualPattern(pattern, config.PerItemSeconds);
            await WriteRadionicsFile(pattern, item.Nome);

            // Pulso ON/OFF
            await Task.Delay(config.OnMs);
            await Task.Delay(config.OffMs);
        }
    }

    private byte[] GeneratePattern(
        ItemInformacional item,
        byte[] anchorHash,
        RemoteConfig config)
    {
        // Combinar frequência + anchor + modulação
        var seed = BitConverter.GetBytes((double)item.FrequenciaHz ?? 1.0)
            .Concat(anchorHash)
            .ToArray();

        // Gerar sequência pseudoaleatória
        var rng = new Random(BitConverter.ToInt32(seed, 0));
        var pattern = new byte[1024];
        rng.NextBytes(pattern);

        // Aplicar modulação
        pattern = ApplyModulation(pattern, config.SelectedModulation);

        return pattern;
    }

    private async Task EmitAudioPattern(byte[] pattern, int seconds)
    {
        // Converter bytes em audio de alta frequência (16-20 kHz)
        // Usar NAudio para playback
        // (Imperceptível ao ouvido humano, mas processado pelo sistema nervoso)
        await Task.Delay(seconds * 1000);
    }

    private async Task EmitVisualPattern(byte[] pattern, int seconds)
    {
        // Converter bytes em flicker de LED/tela
        // (Sub-threshold, não perceptível conscientemente)
        await Task.Delay(seconds * 1000);
    }

    private async Task WriteRadionicsFile(byte[] pattern, string itemName)
    {
        // Gravar ficheiro para uso em radiônica clássica
        var path = PathService.GetRadionicsPath();
        var filename = $"{itemName}_{DateTime.Now:yyyyMMddHHmmss}.dat";
        await File.WriteAllBytesAsync(Path.Combine(path, filename), pattern);
    }
}
```

---

## 6. Roadmap de Desenvolvimento

### 🚀 **Fase 1: Fundação (2-3 semanas)**

#### Sprint 1.1 - Base de Dados
- [ ] Criar migrations para `ItemInformacional`, `TerapiaPrograma`, `SessaoTerapia`
- [ ] Seed inicial com 1000 itens (órgãos, emoções, frequências Rife)
- [ ] Repositories e Unit of Work

#### Sprint 1.2 - Import/Export
- [ ] Implementar `ExcelImportService` (EPPlus)
- [ ] UI "Programas" funcional (importar Excel)
- [ ] Validação de formato Excel
- [ ] Templates Excel prontos (5 programas exemplo)

#### Sprint 1.3 - Histórico
- [ ] Persistência de sessões na BD
- [ ] UI "Histórico" com DataGrid
- [ ] Export para PDF (QuestPDF)

---

### 🔬 **Fase 2: Análise Informacional (3-4 semanas)**

#### Sprint 2.1 - RNG Service
- [ ] Interface `IRNGService`
- [ ] Implementação Pseudo-Random (System.Random)
- [ ] Implementação Hardware (RNGCryptoServiceProvider)
- [ ] (Opcional) Integração com QRNG real (Quantum Random Number Generator)

#### Sprint 2.2 - Scan Engine
- [ ] `InformationalScanService` completo
- [ ] Algoritmo de coincidência significativa
- [ ] Cálculo de scores e ranking
- [ ] Testes unitários com dataset conhecido

#### Sprint 2.3 - UI Avaliação
- [ ] Conectar ViewModel ao Service
- [ ] Progressbar durante scan
- [ ] Botão "Adicionar à lista ativa" funcional
- [ ] Guardar sessão no histórico

---

### 🔊 **Fase 3: Frequency Sweeps (2 semanas)**

#### Sprint 3.1 - Sweep Algorithm
- [ ] `FrequencySweepService`
- [ ] Loop Start → Stop com Step/Dwell
- [ ] Detecção de picos (threshold)
- [ ] Ordenação por score

#### Sprint 3.2 - UI Ressonantes
- [ ] Conectar ViewModel ao Service
- [ ] Gráfico visual de sweep (OxyPlot ou LiveCharts)
- [ ] Export de resultados para programa

---

### ⚡ **Fase 4: Hardware Local (4-5 semanas)**

#### Sprint 4.1 - Serial Communication
- [ ] `FrequencyGeneratorService` base
- [ ] Detecção automática de portas COM
- [ ] Comandos básicos (SetFrequency, Start, Stop)

#### Sprint 4.2 - Waveform Control
- [ ] Suporte para Sine, Square, Triangle
- [ ] Controlo de Duty cycle
- [ ] Controlo de amplitude (Vpp)
- [ ] Limite de corrente (segurança)

#### Sprint 4.3 - Biofeedback Real
- [ ] (Opcional) Integração com sensores GSR/HRV
- [ ] Ajuste automático de frequência baseado em resposta
- [ ] Logging de telemetria

#### Sprint 4.4 - UI Biofeedback Local
- [ ] Conectar ViewModel ao Hardware Service
- [ ] Gráficos em tempo real (corrente, tensão)
- [ ] Botão Emergência (E-Stop)

---

### 🌐 **Fase 5: Transmissão Remota (3 semanas)**

#### Sprint 5.1 - Informational Patterns
- [ ] `RemoteTransmissionService`
- [ ] Geração de padrões (hash + frequência)
- [ ] Modulação (AM, FM, PWM)

#### Sprint 5.2 - Multi-Channel Emission
- [ ] Audio encoding (NAudio, 16-20 kHz)
- [ ] Visual encoding (WPF Flicker)
- [ ] Radionics file output

#### Sprint 5.3 - UI Biofeedback Remoto
- [ ] Configuração de âncora (hash do paciente)
- [ ] Validação de parâmetros
- [ ] Logging de transmissão

---

### 📊 **Fase 6: Otimização e Polimento (2 semanas)**

#### Sprint 6.1 - Performance
- [ ] Caching de itens informacionais (Redis/Memory)
- [ ] Paralelização de scans
- [ ] Otimização de queries BD

#### Sprint 6.2 - UX
- [ ] Tooltips explicativos em todos os campos
- [ ] Animações de transição
- [ ] Feedback visual (loading spinners, success toasts)

#### Sprint 6.3 - Documentação
- [ ] Manual do utilizador (PDF)
- [ ] Vídeo tutorial (YouTube)
- [ ] FAQ online

---

## 📚 Recursos de Referência

### Livros e Papers
1. **"The Living Matrix"** - Harry Oldfield (biofeedback e campos energéticos)
2. **"Radionics: Science or Magic?"** - David V. Tansley
3. **PEAR Technical Reports** - Princeton Engineering Anomalies Research
4. **"The Field"** - Lynne McTaggart (física quântica e consciência)

### Frequências de Referência
1. **Royal Rife Frequency List** - 3000+ frequências catalogadas
2. **Hulda Clark Frequency Guide** - Parasitas e patógenos
3. **Global Scaling Frequencies** - Hartmut Müller
4. **Solfeggio Frequencies** - 174 Hz, 285 Hz, 396 Hz, 417 Hz, 528 Hz, 639 Hz, 741 Hz, 852 Hz, 963 Hz

### Hardware Recomendado
1. **MHS-5200A** - Gerador de Funções dual-channel (~80€)
2. **Rigol DG1022** - Gerador profissional (~300€)
3. **TrueRNG** - Quantum Random Number Generator (~50€)
4. **Electrodes TENS** - Aplicadores reutilizáveis (~20€)

### Software Open-Source
1. **Spooky2** - Software de frequências (Windows)
2. **FreX** - Gerador de frequências Rife
3. **ZYNQ SDR** - Rádio definido por software

---

## ⚠️ Avisos Legais e Éticos

### Disclaimer Obrigatório
```
⚠️ O Sistema de Terapias do BioDeskPro2 é uma ferramenta INFORMACIONAL
e EDUCACIONAL. NÃO substitui diagnóstico médico convencional.

- Não fazer alegações terapêuticas não comprovadas
- Não tratar condições graves sem supervisão médica
- Usar apenas como complemento à medicina convencional
- Obter consentimento informado antes de qualquer sessão
- Respeitar legislação local sobre dispositivos médicos
```

### Responsabilidade do Utilizador
- **Portugal:** Dispositivos de biofeedback não regulamentados (uso livre)
- **UE:** Verificar diretiva 93/42/CEE (dispositivos médicos)
- **EUA:** FDA classifica como "wellness device" (não-médico)

### Segurança Elétrica (Modo Local)
- **Nunca exceder 10V** de amplitude
- **Limite de corrente: 5 mA** máximo
- **Não usar em:** Pacientes com pacemaker, epilepsia, gestantes
- **Sempre usar:** Isolador galvânico (transformador 1:1)

---

## 📞 Suporte Técnico

### Contactos
- **Email:** suporte@biodeskpro.pt
- **Fórum:** https://forum.biodeskpro.pt/terapias
- **GitHub Issues:** https://github.com/NunoCorreia78/BioDeskPRO2.0/issues

### Contribuições
Pull requests são bem-vindos! Áreas prioritárias:
1. Expansão da base de dados informacional
2. Novos programas terapêuticos (Excel templates)
3. Drivers para hardware adicional
4. Traduções (EN, ES, FR)

---

## 🎯 Conclusão

O **Sistema de Terapias** do BioDeskPro2 está estruturado para replicar as funcionalidades principais do Core Inergetix, com:

✅ **5 Sub-Abas** implementadas (UI pronta)
✅ **Import de Excel** preparado (ProgramasView)
✅ **Arquitetura modular** (Services + ViewModels)
⏳ **Backend a implementar** (6 fases, ~12-16 semanas)

**Prioridade Imediata:**
1. Implementar `ExcelImportService` (Sprint 1.2)
2. Criar templates Excel de exemplo
3. Testar importação de programa simples

**Próximo Passo:**
```bash
# 1. Criar branch de desenvolvimento
git checkout -b feature/terapias-excel-import

# 2. Instalar EPPlus
dotnet add src/BioDesk.Services package EPPlus

# 3. Implementar ExcelImportService.cs
# (código fornecido na secção 5.3)

# 4. Conectar ao ProgramasViewModel
# 5. Testar com Excel de 3 frequências
```

---

**Documento Criado:** 16/10/2025
**Última Atualização:** 16/10/2025
**Versão:** 1.0
**Autor:** Sistema BioDeskPro2 + GitHub Copilot
**Licença:** MIT (código) / CC BY-NC-SA 4.0 (documentação)
