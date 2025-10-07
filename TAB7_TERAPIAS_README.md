# 🌿 TAB 7 - TERAPIAS BIOENERGÉTICAS

## 📁 Estrutura de Ficheiros

### Domain Layer (BioDesk.Domain)
```
Entities/
├── ProtocoloTerapia.cs          // Protocolos importados de Excel
├── SessaoTerapia.cs             // Histórico de sessões
├── FrequenciaRessonante.cs      // Resultados de scan (Value %)
└── EmissaoFrequencia.cs         // Registo de emissões (Improvement %)
```

### ViewModel Layer (BioDesk.ViewModels)
```
Abas/
└── TerapiaBioenergeticaViewModel.cs  // ViewModel principal do Tab 7
```

### View Layer (BioDesk.App)
```
Views/Abas/
├── TerapiaBioenergeticaUserControl.xaml      // UI de 3 colunas
└── TerapiaBioenergeticaUserControl.xaml.cs   // Code-behind
```

### Configuração
```
App.xaml.cs                      // Registo DI: TerapiaBioenergeticaViewModel
FichaPacienteView.xaml           // Tab 7 habilitado + UserControl
FichaPacienteView.xaml.cs        // Inicialização do ViewModel
```

---

## 🎯 Funcionalidades Implementadas

### ✅ Completo
- [x] Domain entities (4 entidades)
- [x] ViewModel principal com estrutura completa
- [x] UI de 3 colunas responsiva
- [x] Checklist pré-sessão
- [x] Indicadores tempo real (RMS, Pico, FFT, Impedância, Improvement %)
- [x] Controlo de saída (Freq/Forma/V/mA/Canal)
- [x] Validação de limites (0-20V, 0-50mA)
- [x] Integração com FichaPacienteView
- [x] Registo no DI container
- [x] Documentação completa (MANUAL_TERAPIAS_BIOENERGETICAS.md)
- [x] Excel Schema v1 documentado

### 🚧 Placeholder (Próximos Passos)
- [ ] Importação Excel real (atualmente placeholder)
- [ ] Scan ressonante com TRNG/CSPRNG
- [ ] Emissão AWG via TiePie SDK
- [ ] Gráfico FFT em tempo real (LiveCharts)
- [ ] Biofeedback fisiológico com métricas reais
- [ ] Exportação de relatórios PDF/CSV
- [ ] Migrations EF Core para novas entidades

---

## 🔌 Integração com Hardware

### TiePie HS3 (Osciloscópio + AWG)

**SDK**: LibTiePie .NET bindings
**NuGet**: Não disponível oficialmente - usar DLLs do vendor

#### Instalação Driver
1. Download: https://www.tiepie.com/downloads
2. Instalar driver Windows
3. Conectar HS3 via USB 3.0
4. Verificar Device Manager → "TiePie HS3"

#### Código de Exemplo (Placeholder)
```csharp
// TODO: Implementar integração real
using TiePie;

var device = TiePie.Hardware.GetDeviceByIndex(0);
if (device.DeviceType == DeviceType.Oscilloscope)
{
    var generator = device.Generator;
    generator.SignalType = SignalType.Sine;
    generator.Frequency = 528.0; // Hz
    generator.Amplitude = 5.0;   // V
    generator.Start();
}
```

### Hologram Generator / Alea TRNG

**Status**: Opcional - sistema funciona sem HG

**Com HG**:
```csharp
// TODO: Integração com Alea I/II via Serial Port
using System.IO.Ports;

var port = new SerialPort("COM3", 9600);
port.Open();
var randomBytes = new byte[1024];
port.Read(randomBytes, 0, 1024);
// Usar bytes para seed do scan ressonante
```

**Sem HG** (CSPRNG):
```csharp
using System.Security.Cryptography;

var rng = RandomNumberGenerator.Create();
var seed = new byte[32];
rng.GetBytes(seed);
// Usar seed para scan reprodutível
```

---

## 📊 Fluxo de Dados

### 1. Importação Excel → BD

```
Excel (.xlsx)
    ↓ (EPPlus ou ClosedXML)
Validação (ExternalId, Freq, V, mA)
    ↓
Upsert (baseado em ExternalId)
    ↓
ProtocoloTerapia (EF Core)
    ↓
ObservableCollection<ProtocoloTerapia> (UI)
```

### 2. Scan Ressonante → Emissão

```
IniciarScanRessonanteCommand
    ↓
Gerar frequências (TRNG/CSPRNG)
    ↓
Calcular Value % para cada frequência
    ↓
Ordenar por Value % (100% → 0%)
    ↓
Filtrar por LimiarRelevancia (ex: > 30%)
    ↓
ObservableCollection<FrequenciaRessonante> (UI)
    ↓
Utilizador seleciona items
    ↓
AdicionarSelecionadasFilaCommand
    ↓
ObservableCollection<EmissaoFrequencia> (Fila)
    ↓
IniciarEmissaoCommand
    ↓
Emitir sequencialmente (AWG)
    ↓
Capturar biofeedback (RMS, Pico, FFT)
    ↓
Atualizar ImprovementPct em tempo real
    ↓
Salvar SessaoTerapia + Emissoes (BD)
```

### 3. Protocolo Excel → Emissão

```
ObservableCollection<ProtocoloTerapia>
    ↓
Utilizador seleciona protocolo
    ↓
AdicionarProtocoloFilaCommand
    ↓
Converter ProtocoloTerapia → EmissaoFrequencia
    ↓
ObservableCollection<EmissaoFrequencia> (Fila)
    ↓
IniciarEmissaoCommand
    ↓
(mesmo fluxo de emissão acima)
```

---

## 🧪 Testes

### Unit Tests (BioDesk.Tests)

```csharp
// TODO: Criar testes unitários

[Fact]
public void ProtocoloTerapia_ValidaFrequencia_DentroLimites()
{
    var protocolo = new ProtocoloTerapia { FrequenciaHz = 528.0m };
    Assert.InRange(protocolo.FrequenciaHz, 0.01m, 2000000m);
}

[Fact]
public void TerapiaBioenergeticaViewModel_ValidarChecklistPreSessao_TodosItensObrigatorios()
{
    var vm = new TerapiaBioenergeticaViewModel(logger);
    vm.ConsentimentoAssinado = false;
    var resultado = vm.ValidarChecklistPreSessao();
    Assert.False(resultado);
}
```

### Integration Tests

```csharp
// TODO: Testes de integração com BD

[Fact]
public async Task ImportarProtocolosExcel_UpsertIdempotente()
{
    // Importar Excel com 10 protocolos
    await service.ImportarProtocolosAsync("test.xlsx");
    
    // Importar novamente (mesmo ExternalId)
    await service.ImportarProtocolosAsync("test.xlsx");
    
    // Verificar que ainda há só 10 (não 20)
    var count = await db.ProtocolosTerapia.CountAsync();
    Assert.Equal(10, count);
}
```

---

## 🔐 Segurança

### Validações Hard

```csharp
// TerapiaBioenergeticaViewModel.cs
private bool ValidarChecklistPreSessao()
{
    if (AmplitudeV < 0 || AmplitudeV > 20)
    {
        ErrorMessage = "❌ Amplitude fora dos limites (0-20V)";
        return false;
    }

    if (LimiteCorrenteMa < 0 || LimiteCorrenteMa > 50)
    {
        ErrorMessage = "❌ Corrente fora dos limites (0-50mA)";
        return false;
    }

    // ... outros checks
}
```

### Pausa Automática

```csharp
// TODO: Implementar monitorização de impedância
private void MonitorizarImpedancia()
{
    if (ImpedanciaOhms < 100 || ImpedanciaOhms > 10000)
    {
        PausarEmissao();
        ErrorMessage = "⚠️ Impedância fora de gama - verificar eletrodos";
        LogMotivoParada("IMPEDANCIA_FORA_GAMA");
    }
}
```

---

## 📝 Comandos Implementados

| Comando | Descrição | Status |
|---------|-----------|--------|
| `ImportarProtocolosExcelCommand` | Importação idempotente Excel v1 | 🚧 Placeholder |
| `PesquisarProtocolosCommand` | Filtrar protocolos por nome | 🚧 Placeholder |
| `AdicionarProtocoloFilaCommand` | Adicionar protocolo à fila | 🚧 Placeholder |
| `IniciarScanRessonanteCommand` | Scan ressonante com Value % | 🚧 Placeholder |
| `SelecionarFrequenciaCommand` | Toggle checkbox frequência | 🚧 Placeholder |
| `AdicionarSelecionadasFilaCommand` | Adicionar selecionadas à fila | 🚧 Placeholder |
| `IniciarEmissaoCommand` | Iniciar emissão sequencial | 🚧 Placeholder |
| `PausarEmissaoCommand` | Pausar emissão atual | 🚧 Placeholder |
| `PararEmissaoCommand` | Cancelar sessão | 🚧 Placeholder |
| `ExportarRelatorioCommand` | Exportar PDF/CSV | 🚧 Placeholder |

---

## 🎨 Paleta de Cores

```xaml
<!-- Cores terroso pastel (padrão BioDeskPro2) -->
<SolidColorBrush x:Key="TextoPrincipal">#3F4A3D</SolidColorBrush>
<SolidColorBrush x:Key="TextoSecundario">#5A6558</SolidColorBrush>
<SolidColorBrush x:Key="BotaoPrincipal">#9CAF97</SolidColorBrush>
<SolidColorBrush x:Key="BotaoHover">#879B83</SolidColorBrush>
<SolidColorBrush x:Key="Cartao">#F7F9F6</SolidColorBrush>
<SolidColorBrush x:Key="Borda">#E3E9DE</SolidColorBrush>
```

### Indicadores por Cor

- **Verde** (#E8F5E9): RMS, Improvement % OK
- **Laranja** (#FFF3E0): Pico, Tempo decorrido
- **Azul** (#E3F2FD): Frequência dominante, Scan
- **Roxo** (#F3E5F5): Impedância
- **Amarelo** (#FFF9C4): Tempo

---

## 📦 Dependências Futuras

### NuGet Packages (TODO)

```xml
<!-- Para gráfico FFT -->
<PackageReference Include="LiveCharts.Wpf" Version="0.9.7" />

<!-- Para importação Excel -->
<PackageReference Include="EPPlus" Version="7.0.0" />
<!-- OU -->
<PackageReference Include="ClosedXML" Version="0.102.0" />

<!-- Para exportação PDF relatórios -->
<PackageReference Include="QuestPDF" Version="2024.1.0" />
<!-- (Já usado em outros módulos) -->
```

### DLLs Vendor (Colocar em /lib/)

```
lib/
├── TiePie.LibTiePie.dll         // SDK TiePie HS3
├── TiePie.LibTiePie.Native.dll
└── Alea.SerialTRNG.dll          // (Opcional) SDK Alea
```

---

## 🚀 Roadmap de Desenvolvimento

### Fase 1: Estrutura Base ✅ CONCLUÍDA
- [x] Domain entities
- [x] ViewModel skeleton
- [x] UI layout 3 colunas
- [x] Integração com FichaPacienteView
- [x] Documentação

### Fase 2: Importação Excel (Sprint Atual)
- [ ] EPPlus integration
- [ ] Validação de schema
- [ ] Upsert logic
- [ ] Relatório de importação
- [ ] Pré-visualização modal
- [ ] Error handling

### Fase 3: Scan Ressonante
- [ ] TRNG/CSPRNG implementation
- [ ] Value % calculation algorithm
- [ ] Ordenação e filtragem
- [ ] UI binding com lista
- [ ] Seleção múltipla
- [ ] Adicionar à fila

### Fase 4: Emissão AWG
- [ ] TiePie SDK integration
- [ ] Controlo de forma de onda
- [ ] Emissão sequencial
- [ ] Pausa/Retomar/Cancelar
- [ ] Monitorização de segurança
- [ ] Logs detalhados

### Fase 5: Biofeedback Tempo Real
- [ ] Captura de métricas (RMS, Pico, FFT)
- [ ] Cálculo de Improvement %
- [ ] Gráfico FFT com LiveCharts
- [ ] Atualização UI em tempo real
- [ ] Impedância monitoring
- [ ] Alertas visuais

### Fase 6: Relatórios & Persistência
- [ ] Salvar SessaoTerapia na BD
- [ ] Exportar PDF com QuestPDF
- [ ] Exportar CSV
- [ ] Gráficos históricos
- [ ] Filtros por data/protocolo
- [ ] Comparação de sessões

### Fase 7: Migrations & Deployment
- [ ] EF Core migrations para novas tabelas
- [ ] Seed data de protocolos exemplo
- [ ] Testes E2E completos
- [ ] Documentação final
- [ ] Release notes

---

## 📚 Recursos

### Documentação
- `MANUAL_TERAPIAS_BIOENERGETICAS.md` - Manual completo do utilizador
- `Templates/EXCEL_PROTOCOLOS_TERAPIA_V1.md` - Schema Excel detalhado
- `copilot-instructions.md` - Instruções gerais do projeto

### Links Externos
- [TiePie HS3 Manual](https://www.tiepie.com/hs3)
- [LibTiePie SDK](https://www.tiepie.com/libtiepie-sdk)
- [Inergetix-CoRe](https://core-system.com)
- [EPPlus Documentation](https://epplussoftware.com/docs)
- [LiveCharts WPF](https://lvcharts.net)

---

## 🤝 Contribuir

### Checklist para Pull Requests

- [ ] Código segue padrões existentes (MVVM, CommunityToolkit)
- [ ] Validações de segurança implementadas (0-20V, 0-50mA)
- [ ] Logging com ILogger em operações críticas
- [ ] Try/catch com ExecuteWithErrorHandlingAsync
- [ ] Testes unitários (se aplicável)
- [ ] Documentação atualizada
- [ ] Build limpo (0 erros, 0 warnings)
- [ ] UI testada com paciente ativo

### Estilo de Código

```csharp
// ✅ BOM
[RelayCommand]
private async Task ImportarProtocolosExcelAsync()
{
    await ExecuteWithErrorHandlingAsync(async () =>
    {
        _logger.LogInformation("📥 Importando protocolos Excel...");
        // ... lógica
        SuccessMessage = "✅ Protocolos importados com sucesso";
    });
}

// ❌ EVITAR
private async void ImportarExcel()
{
    try
    {
        // ... lógica sem logging
    }
    catch { } // Engolir exceções
}
```

---

**Última atualização**: 2025-01-09
**Status**: Estrutura base completa - Aguardando implementação de serviços
**Responsável**: BioDeskPro2 Development Team
