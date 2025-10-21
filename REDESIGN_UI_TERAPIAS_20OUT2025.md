# 🎯 REDESIGN UI TERAPIAS - Layout Optimizado (20 OUT 2025)

## 📊 **Objectivo**: Interface Compacta + Informação em Tempo Real

### ✅ **Componentes Criados**:

#### 1️⃣ **TerapiaControlosCompactoUserControl**
**Localização**: `src/BioDesk.App/Controls/TerapiaControlosCompactoUserControl.xaml`

**Layout Horizontal Compacto (2 linhas)**:
```
┌────────────────────────────────────────────────────────────┐
│ [Voltagem ▼] [Duração ━━━○━━ 30min] [5s/10s/15s] [±0 Hz]  │
│ [▶ INICIAR TERAPIA]        [⛔ PARAR]                      │
└────────────────────────────────────────────────────────────┘
```

**Dependency Properties**:
- `VoltagemV` (double, default: 5.0)
- `DuracaoTotalMinutos` (double, default: 30.0)
- `TempoFrequenciaSegundos` (int, default: 10)
- `AjusteHz` (double, default: 0.0)
- `TextoBotao` (string, default: "▶ INICIAR TERAPIA")

**Events**:
- `IniciarClick` (RoutedEventHandler)
- `PararClick` (RoutedEventHandler)

---

#### 2️⃣ **TerapiaProgressoUserControl**
**Localização**: `src/BioDesk.App/Controls/TerapiaProgressoUserControl.xaml`

**Card Sempre Visível** (expand quando `TerapiaEmAndamento=true`):

**Estado INATIVO**:
```
┌────────────────────────────────────────────────────────────┐
│          ⏸ Aguardando início da terapia...                │
└────────────────────────────────────────────────────────────┘
```

**Estado ATIVO**:
```
┌────────────────────────────────────────────────────────────┐
│                 ⚡ TERAPIA EM ANDAMENTO                     │
│                                                            │
│ 🎵 Frequência: 432.50 Hz (Original: 432 Hz, Ajuste: +0.5) │
│ 📋 Programa: PROTO::AIDS secondary                         │
│ 📊 Progresso: 15/120 frequências (12.5%)                   │
│ ⏱ Falta: 18min 45s                                         │
│                                   [████████░░░░░] 12.5%    │
└────────────────────────────────────────────────────────────┘
```

**Dependency Properties**:
- `TerapiaEmAndamento` (bool) - Controla visibilidade expandida
- `FrequenciaAtualHz` (double) - Frequência sendo emitida
- `FrequenciaOriginalHz` (double) - Frequência base (sem ajuste)
- `AjusteAplicadoHz` (double) - Ajuste ±Hz aplicado
- `ProgramaAtual` (string) - Nome do programa/protocolo
- `MostrarPrograma` (bool) - Mostrar linha "Programa" (false para Biofeedback)
- `FrequenciaAtualIndex` (int) - Index da frequência atual
- `TotalFrequencias` (int) - Total de frequências
- `ProgressoPercentual` (double) - % progresso (0-100)
- `TempoRestanteFormatado` (string) - Ex: "18min 45s"

---

## 🔄 **Próximos Passos**:

### **Sprint 7A**: Integrar nos 3 Separadores

1. ✅ **ProgramasView.xaml**
   - Substituir `TerapiaControlosUserControl` → `TerapiaControlosCompactoUserControl`
   - Substituir card progresso condicional → `TerapiaProgressoUserControl`
   - Binding: `ProgramaAtual`, `MostrarPrograma=true`

2. ✅ **RessonantesView.xaml**
   - Adicionar `TerapiaControlosCompactoUserControl` no topo
   - Adicionar `TerapiaProgressoUserControl` abaixo
   - Binding: `ProgramaAtual="Scan Ressonante"`, `MostrarPrograma=false`

3. ✅ **BiofeedbackView.xaml**
   - Adicionar `TerapiaControlosCompactoUserControl` no topo
   - Adicionar `TerapiaProgressoUserControl` abaixo
   - **ESPECIAL**: `MostrarPrograma=false` (só mostra frequência atual)
   - **Remover tabela** histórico de sessões (simplificar)

---

## 🎨 **Vantagens do Novo Layout**:

| Antes ❌ | Depois ✅ |
|----------|-----------|
| Controlos verticais (scroll necessário) | Controlos horizontais compactos (2 linhas) |
| Progresso só visível quando terapia a correr | Progresso **sempre visível** (placeholder quando inativo) |
| Sem indicador de variação de frequência | Mostra **Original + Ajuste aplicado** |
| Informações fragmentadas | **Tudo numa vista**: Freq, Progresso, Tempo |
| 3 colunas (desperdiça espaço vertical) | 2 componentes empilhados + lista |

---

## 📐 **Estrutura Final dos Separadores**:

### **ProgramasView / RessonantesView / BiofeedbackView**:
```xml
<Grid>
    <Grid.RowDefinitions>
        <RowDefinition Height="Auto"/>  <!-- Controlos Compactos -->
        <RowDefinition Height="10"/>    <!-- Espaçamento -->
        <RowDefinition Height="Auto"/>  <!-- Progresso -->
        <RowDefinition Height="15"/>    <!-- Espaçamento -->
        <RowDefinition Height="*"/>     <!-- Lista/Tabela -->
    </Grid.RowDefinitions>

    <!-- CONTROLOS -->
    <controls:TerapiaControlosCompactoUserControl
        Grid.Row="0"
        VoltagemV="5.0"
        DuracaoTotalMinutos="30"
        TempoFrequenciaSegundos="10"
        AjusteHz="0"
        TextoBotao="▶ INICIAR PROGRAMAS"
        IniciarClick="..."
        PararClick="..."/>

    <!-- PROGRESSO -->
    <controls:TerapiaProgressoUserControl
        Grid.Row="2"
        TerapiaEmAndamento="{Binding TerapiaEmAndamento}"
        FrequenciaAtualHz="{Binding FrequenciaAtual}"
        FrequenciaOriginalHz="{Binding FrequenciaOriginal}"
        AjusteAplicadoHz="{Binding AjusteHz}"
        ProgramaAtual="{Binding ProgramaAtual}"
        MostrarPrograma="True/False"
        FrequenciaAtualIndex="{Binding FrequenciaAtualIndex}"
        TotalFrequencias="{Binding TotalFrequencias}"
        ProgressoPercentual="{Binding ProgressoPercentual}"
        TempoRestanteFormatado="{Binding TempoRestanteFormatado}"/>

    <!-- LISTA/TABELA -->
    <Border Grid.Row="4">
        <!-- DataGrid de programas / sweep / ... -->
    </Border>
</Grid>
```

---

## 🚀 **Status**: Componentes Criados ✅ | Integração Pendente ⏳
**Data**: 20 de Outubro de 2025
**Build Status**: Por testar após integração

---

## ⚠️ **Notas Técnicas**:

1. **Converters Necessários**:
   - `BoolToVisibilityConverter` (já existe)
   - `InverseBoolToVisibilityConverter` (já existe)
   - `IntToBoolConverter` (já existe para RadioButtons)

2. **Binding ViewModel**:
   - ViewModels precisam expor: `FrequenciaOriginal`, `AjusteHz`, `TempoRestanteFormatado`
   - Calcular `TempoRestanteFormatado` como: `"{minutos}min {segundos}s"`

3. **Biofeedback Diferenciação**:
   - `MostrarPrograma="False"` esconde linha "Programa"
   - Foco total na frequência atual + progresso
   - Remover tabela histórico → interface minimalista

---

**Princípio**: "Informação crítica sempre visível | Controlos acessíveis sem scroll"
