# 📊 RELATÓRIO GAPS TERAPIAS - Análise Codex
**Data:** 13 de Outubro de 2025
**Fonte:** Codex Analysis
**Objetivo:** Roadmap para paridade com CoRe 5.0

---

## ✅ **O QUE JÁ ESTÁ IMPLEMENTADO**

### **1. Protocolos e Importação** ✅
- ✅ Parser Excel com ExcelDataReader
- ✅ Upsert de protocolos (mas **não idempotente** - ExternalId é sempre novo GUID)
- ✅ Repository pattern (IProtocoloRepository)
- ✅ UI básica para escolher protocolo
- ✅ Seleção de N frequências aleatórias

**Ficheiros:**
- `src/BioDesk.Services/Excel/ExcelImportService.cs`
- `src/BioDesk.Data/Repositories/ProtocoloRepository.cs`
- `src/BioDesk.App/Views/Abas/TerapiasUserControl.xaml`

---

### **2. RNG Service** ✅
- ✅ 3 fontes: HardwareCrypto, AtmosphericNoise (random.org), PseudoRandom
- ✅ Testes unitários
- ✅ Interface `IRngService` implementada

**Ficheiros:**
- `src/BioDesk.Services/Rng/RngService.cs`
- `src/BioDesk.Tests/Services/RngServiceTests.cs`

---

### **3. Hardware TiePie** ✅
- ✅ Serviço real via P/Invoke (libtiepie.dll)
- ✅ Serviço dummy para simulação
- ✅ DI registado (App.xaml.cs)
- ✅ UI básica para teste e emissão sequencial

**Ficheiros:**
- `src/BioDesk.Services/Hardware/RealTiePieHardwareService.cs`
- `src/BioDesk.Services/Hardware/DummyTiePieHardwareService.cs`
- `src/BioDesk.App/App.xaml.cs:330`

---

### **4. Domínio Criado** ✅
Entidades definidas em `src/BioDesk.Domain/Entities/`:
- ✅ `ProtocoloTerapeutico`
- ✅ `PlanoTerapia`
- ✅ `Terapia`
- ✅ `SessaoTerapia`
- ✅ `LeituraBioenergetica`
- ✅ `EventoHardware`
- ✅ `ImportacaoExcelLog`

**Status:** Entidades existem, mas **não estão no DbContext** (exceto ProtocoloTerapeutico)

---

## 🔴 **GAPS CRÍTICOS (Prioridade Alta)**

### **GAP 1: Base de Dados (DbContext + Migrations)** 🔴

**Problema:**
```csharp
// src/BioDesk.Data/BioDeskDbContext.cs:44
public DbSet<ProtocoloTerapeutico> ProtocolosTerapeuticos { get; set; } = null!;

// ❌ FALTAM:
// public DbSet<PlanoTerapia> PlanosTerapia { get; set; }
// public DbSet<Terapia> Terapias { get; set; }
// public DbSet<SessaoTerapia> SessoesTerapia { get; set; }
// public DbSet<LeituraBioenergetica> LeiturasBioenergeticas { get; set; }
// public DbSet<EventoHardware> EventosHardware { get; set; }
// public DbSet<ImportacaoExcelLog> ImportacoesExcelLog { get; set; }
```

**Ação:**
1. Adicionar todos os `DbSet<>` ao `BioDeskDbContext.cs`
2. Configurar relacionamentos em `OnModelCreating`:
   - `PlanoTerapia` → `Sessao` (FK)
   - `SessaoTerapia` → `PlanoTerapia` (FK)
   - `LeituraBioenergetica` → `SessaoTerapia` (FK)
   - `EventoHardware` → `SessaoTerapia` (FK)
3. Adicionar índices:
   - `SessaoTerapia(SessaoId, Ordem)`
   - `LeituraBioenergetica(SessaoTerapiaId)`
   - `ProtocoloTerapeutico(Nome)`
4. Criar migration:
   ```bash
   dotnet ef migrations add AddTerapiasBioenergeticas --project src/BioDesk.Data
   dotnet ef database update --project src/BioDesk.Data
   ```

**Estimativa:** 2-3 horas

---

### **GAP 2: Importação Excel (Idempotência)** 🔴

**Problema:**
```csharp
// src/BioDesk.Services/Excel/ExcelImportService.cs:137
ExternalId = Guid.NewGuid(), // ❌ SEMPRE NOVO! Não é idempotente
```

**Impacto:**
- Reimportar Excel cria duplicados em vez de atualizar
- Impossível rastrear alterações em protocolos

**Ação:**
1. **Opção A (recomendada):** Ler `ExternalId` do Excel
   ```csharp
   // Se coluna "ExternalId" existe no Excel:
   ExternalId = worksheet.Cells[row, colExternalId].GetValue<Guid>()

   // Se não existe, gerar hash estável:
   ExternalId = GerarHashEstavel(nome, categoria, frequenciasStr)
   ```

2. **Opção B:** Hash estável (SHA256 de nome+frequências)
   ```csharp
   private Guid GerarHashEstavel(string nome, string categoria, string frequencias)
   {
       var input = $"{nome}|{categoria}|{frequencias}".ToLowerInvariant();
       using var sha256 = SHA256.Create();
       var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
       return new Guid(hash.Take(16).ToArray());
   }
   ```

3. Adicionar log de importação:
   ```csharp
   // Criar método no IProtocoloRepository:
   Task AddImportLogAsync(ImportacaoExcelLog log);

   // Persistir no fim do ImportAsync:
   await _repository.AddImportLogAsync(new ImportacaoExcelLog {
       Arquivo = Path.GetFileName(filePath),
       VersaoSchema = "1.0",
       LinhasOk = sucessos,
       WarningsJson = JsonSerializer.Serialize(warnings),
       ErrosJson = JsonSerializer.Serialize(erros),
       Data = DateTime.UtcNow
   });
   ```

**Estimativa:** 1-2 horas

---

### **GAP 3: Seleção "Value %" e Fila de Execução** 🔴

**Problema:**
- UI atual: escolhe **1 protocolo** → seleciona **N frequências** → executa
- CoRe 5.0: **scan completo** → lista **todos os itens** ordenados por **Value %** → utilizador seleciona → fila de execução

**Ação:**
1. Criar modelo `ItemAvaliacao`:
   ```csharp
   public class ItemAvaliacao
   {
       public string Nome { get; set; }
       public string Categoria { get; set; }
       public double ValuePercent { get; set; } // 0-100%
       public ProtocoloTerapeutico? Protocolo { get; set; }
       public double[] Frequencias { get; set; }
       public bool Selecionado { get; set; }
   }
   ```

2. Criar serviço de avaliação:
   ```csharp
   public interface IAvaliacaoService
   {
       Task<List<ItemAvaliacao>> RealizarScanAsync(
           int pacienteId,
           EntropySource fonte = EntropySource.HardwareCrypto,
           double limiarMinimo = 30.0
       );
   }
   ```

3. Atualizar ViewModel:
   ```csharp
   [ObservableProperty] private ObservableCollection<ItemAvaliacao> _itensAvaliados = new();
   [ObservableProperty] private ObservableCollection<ItemAvaliacao> _filaExecucao = new();

   [RelayCommand]
   private async Task RealizarScanAsync()
   {
       var itens = await _avaliacaoService.RealizarScanAsync(PacienteAtualId);
       ItensAvaliados = new ObservableCollection<ItemAvaliacao>(
           itens.OrderByDescending(x => x.ValuePercent)
       );
   }

   [RelayCommand]
   private void AdicionarAFila(ItemAvaliacao item)
   {
       if (!FilaExecucao.Contains(item))
       {
           FilaExecucao.Add(item);
           item.Selecionado = true;
       }
   }
   ```

4. Atualizar UI (adicionar antes da seção "Execução"):
   ```xml
   <!-- Seção: Scan e Avaliação -->
   <Border>
       <StackPanel>
           <Button Content="🔍 Realizar Scan" Command="{Binding RealizarScanCommand}"/>

           <DataGrid ItemsSource="{Binding ItensAvaliados}" AutoGenerateColumns="False">
               <DataGrid.Columns>
                   <DataGridTextColumn Header="Nome" Binding="{Binding Nome}"/>
                   <DataGridTextColumn Header="Value %" Binding="{Binding ValuePercent, StringFormat={}{0:N1}%}"/>
                   <DataGridTemplateColumn Header="Ação">
                       <DataGridTemplateColumn.CellTemplate>
                           <DataTemplate>
                               <Button Content="➕ Adicionar"
                                       Command="{Binding DataContext.AdicionarAFilaCommand,
                                                 RelativeSource={RelativeSource AncestorType=UserControl}}"
                                       CommandParameter="{Binding}"/>
                           </DataTemplate>
                       </DataGridTemplateColumn.CellTemplate>
                   </DataGridTemplateColumn>
               </DataGrid.Columns>
           </DataGrid>
       </StackPanel>
   </Border>

   <!-- Seção: Fila de Execução -->
   <Border>
       <StackPanel>
           <TextBlock Text="📋 Fila de Execução" FontSize="16"/>
           <ListBox ItemsSource="{Binding FilaExecucao}">
               <ListBox.ItemTemplate>
                   <DataTemplate>
                       <TextBlock Text="{Binding Nome}"/>
                   </DataTemplate>
               </ListBox.ItemTemplate>
           </ListBox>
       </StackPanel>
   </Border>
   ```

**Estimativa:** 4-6 horas

---

### **GAP 4: Biofeedback e "Improvement %"** 🟡

**Status:** Especificação criada em `IMPLEMENTACAO_BIOFEEDBACK_TIEPIE.md`

**Problema:**
- Falta captura/medição (RMS, pico, FFT) em tempo real
- Falta cálculo de Improvement % por item
- Falta persistir `LeituraBioenergetica`

**Ação:**
1. Implementar `IMedicaoService` (conforme documento)
2. Adicionar P/Invoke para osciloscópio (TiePie INPUT)
3. Integrar no loop de execução do ViewModel
4. Adicionar UI para Improvement % (barra de progresso)

**Estimativa:** 8-12 horas (já documentado)

---

### **GAP 5: Gráficos (LiveCharts2)** 🟡

**Problema:**
```csharp
// src/BioDesk.App/BioDesk.App.csproj:1
// ❌ NÃO TEM: LiveChartsCore.SkiaSharpView.WPF
```

**Ação:**
1. Adicionar pacote:
   ```bash
   dotnet add src/BioDesk.App package LiveChartsCore.SkiaSharpView.WPF --version 2.0.0-rc2
   ```

2. Criar ViewModel para gráficos:
   ```csharp
   public partial class GraficoBiofeedbackViewModel : ObservableObject
   {
       [ObservableProperty] private ISeries[] _seriesRms = Array.Empty<ISeries>();
       [ObservableProperty] private ISeries[] _seriesFft = Array.Empty<ISeries>();

       public void AtualizarRms(double[] valores)
       {
           SeriesRms = new ISeries[]
           {
               new LineSeries<double> { Values = valores }
           };
       }
   }
   ```

3. Adicionar na UI:
   ```xml
   <lvc:CartesianChart Series="{Binding SeriesRms}" Height="200"/>
   ```

**Estimativa:** 2-3 horas

---

## 🟢 **GAPS MENORES (Prioridade Média/Baixa)**

### **GAP 6: Histórico (DataGrid Binding)** 🟢

**Problema:**
```csharp
// VM: src/BioDesk.ViewModels/.../TerapiasBioenergeticasUserControlViewModel.cs:54
[ObservableProperty] private ObservableCollection<string> _historicoSessoes = new();

// XAML: src/BioDesk.App/Views/Abas/TerapiasUserControl.xaml:405
<DataGrid ItemsSource="{Binding HistoricoSessoes}">
    <DataGrid.Columns>
        <DataGridTextColumn Binding="{Binding Data}"/> <!-- ❌ string não tem .Data -->
```

**Ação:**
1. Criar modelo:
   ```csharp
   public class HistoricoSessaoItem
   {
       public DateTime Data { get; set; }
       public string Protocolo { get; set; }
       public int NumFrequencias { get; set; }
       public string FonteEntropia { get; set; }
       public string Canal { get; set; }
       public double Voltagem { get; set; }
       public string FormaOnda { get; set; }
       public double DuracaoTotal { get; set; }
   }
   ```

2. Alterar propriedade:
   ```csharp
   [ObservableProperty] private ObservableCollection<HistoricoSessaoItem> _historicoSessoes = new();
   ```

**Estimativa:** 30 minutos

---

### **GAP 7: Toggle Dummy/Real (Configuração)** 🟢

**Problema:**
```csharp
// src/BioDesk.App/App.xaml.cs:330
services.AddSingleton<ITiePieHardwareService, RealTiePieHardwareService>(); // ❌ Hardcoded
// services.AddSingleton<ITiePieHardwareService, DummyTiePieHardwareService>(); // linha 333
```

**Ação:**
1. Adicionar a `appsettings.json`:
   ```json
   {
     "Hardware": {
       "UseDummyTiePie": true
     }
   }
   ```

2. Ler no DI:
   ```csharp
   var useDummy = Configuration.GetValue<bool>("Hardware:UseDummyTiePie");

   if (useDummy)
       services.AddSingleton<ITiePieHardwareService, DummyTiePieHardwareService>();
   else
       services.AddSingleton<ITiePieHardwareService, RealTiePieHardwareService>();
   ```

**Estimativa:** 15 minutos

---

### **GAP 8: Ligação a Sessão/Paciente** 🟢

**Problema:**
- Execução não está ligada à `Sessao` atual
- Não persiste `PlanoTerapia` nem `SessaoTerapia`
- Não grava parâmetros emitidos

**Ação:**
1. No `IniciarTerapiaAsync`, criar entidades:
   ```csharp
   // Criar PlanoTerapia
   var plano = new PlanoTerapia
   {
       Nome = $"Plano {DateTime.Now:dd/MM/yyyy HH:mm}",
       Categoria = ProtocoloSelecionado.Categoria,
       CreatedAt = DateTime.UtcNow
   };
   await _unitOfWork.PlanosTerapia.AddAsync(plano);

   // Criar SessaoTerapia para cada frequência
   for (int i = 0; i < _frequenciasRaw.Length; i++)
   {
       var sessaoTerapia = new SessaoTerapia
       {
           SessaoId = _sessaoAtualId,
           ProtocoloId = ProtocoloSelecionado.Id,
           FrequenciaHz = _frequenciasRaw[i],
           AmplitudeV = Voltagem,
           Canal = CanalSelecionado == "Ch1" ? 1 : 2,
           Forma = FormaOndaSelecionada,
           DuracaoMin = DuracaoPorFrequencia / 60.0,
           Ordem = i + 1,
           Status = "EmCurso",
           StartedAt = DateTime.UtcNow
       };

       await _unitOfWork.SessoesTerapia.AddAsync(sessaoTerapia);

       // ... executar sinal ...

       sessaoTerapia.Status = "Concluída";
       sessaoTerapia.EndedAt = DateTime.UtcNow;
       sessaoTerapia.ImprovementFinal = ImprovementPercent;
   }

   await _unitOfWork.SaveChangesAsync();
   ```

**Estimativa:** 2-3 horas

---

### **GAP 9: Validação de Corrente (mA)** 🟢

**Problema:**
```csharp
// SignalConfiguration só valida Volts (0.2..8V)
// Falta limite de corrente mA
```

**Ação:**
1. Adicionar campo:
   ```csharp
   public class SignalConfiguration
   {
       // ... existente ...
       public double? MaxCurrentMa { get; set; } // Limite de corrente (opcional)
   }
   ```

2. Validar:
   ```csharp
   public bool IsValid()
   {
       // ... validações existentes ...
       if (MaxCurrentMa.HasValue && MaxCurrentMa.Value > 50.0)
           return false; // Limite de segurança: 50 mA

       return true;
   }
   ```

**Estimativa:** 30 minutos

---

## 📊 **PRIORIZAÇÃO (Roadmap)**

### **Sprint 1: Fundação BD (Alta Prioridade)** - 4-6 horas
1. ✅ GAP 1: DbContext + Migrations
2. ✅ GAP 2: Importação idempotente
3. ✅ GAP 7: Toggle Dummy/Real

**Resultado:** BD completa, importação robusta, configuração flexível

---

### **Sprint 2: Funcionalidade CoRe (Alta Prioridade)** - 6-10 horas
1. ✅ GAP 3: Value % + Fila de execução
2. ✅ GAP 6: Histórico correto
3. ✅ GAP 8: Ligação a Sessão

**Resultado:** Workflow completo tipo CoRe (sem biofeedback ainda)

---

### **Sprint 3: Biofeedback (Média Prioridade)** - 8-12 horas
1. ✅ GAP 4: INPUT TiePie + Improvement %
2. ✅ GAP 5: Gráficos LiveCharts2

**Resultado:** Biofeedback completo em tempo real

---

### **Sprint 4: Polimento (Baixa Prioridade)** - 1-2 horas
1. ✅ GAP 9: Validação corrente mA
2. ✅ Relatórios PDF
3. ✅ Testes unitários

---

## 🎯 **AÇÃO IMEDIATA**

**Recomendo começar por:**

### **Tarefa 1: DbContext + Migrations (2h)**
```bash
# 1. Adicionar DbSet<> ao BioDeskDbContext.cs
# 2. Configurar relacionamentos em OnModelCreating
# 3. Criar migration
dotnet ef migrations add AddTerapiasBioenergeticas --project src/BioDesk.Data
dotnet ef database update --project src/BioDesk.Data
```

### **Tarefa 2: Importação Idempotente (1h)**
```csharp
// ExcelImportService.cs linha 137
ExternalId = GerarHashEstavel(nome, categoria, frequenciasStr)
```

### **Tarefa 3: Toggle Dummy/Real (15min)**
```csharp
// App.xaml.cs linha 330
var useDummy = Configuration.GetValue<bool>("Hardware:UseDummyTiePie");
```

---

**Queres que comece pela Tarefa 1 (DbContext)?** 🚀
