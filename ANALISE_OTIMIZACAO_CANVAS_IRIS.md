# 🎨 ANÁLISE E OTIMIZAÇÃO: MARGENS CANVAS ÍRIS

**Data:** 07 de Outubro de 2025
**Status:** 📊 ANÁLISE COMPLETA
**Objetivo:** Aproveitar margens de ~1cm (X/Y) do canvas da íris

---

## 📐 SITUAÇÃO ATUAL

### Dimensões do Canvas
```xaml
<!-- Linha 259: IrisdiagnosticoUserControl.xaml -->
<Canvas Width="1400" Height="1400" Background="White">
```

**Estrutura:**
```
┌─────────────────────────────────────────────────────┐
│  Grid (3 colunas)                                   │
│  ┌───────────┬─────────────────────────┬─────────┐ │
│  │ Col 0     │ Col 1 (CANVAS)          │ Col 2   │ │
│  │ Galeria   │ Viewbox                 │ Esquerdo│ │
│  │ Direito   │  Canvas 1400x1400       │         │ │
│  │ Width=1*  │  Width=3* (60%)         │ Width=1*│ │
│  └───────────┴─────────────────────────┴─────────┘ │
└─────────────────────────────────────────────────────┘
```

### Margens Observadas (na imagem fornecida)
- **Margem Superior:** ~100px (estimado ~7% da altura)
- **Margem Inferior:** ~100px
- **Margem Esquerda:** ~100px (estimado ~7% da largura)
- **Margem Direita:** ~100px

**Total desperdiçado:** ~14% vertical + ~14% horizontal = **~28% de espaço utilizável**

---

## 🎯 OBJETIVOS DA OTIMIZAÇÃO

1. ✅ **Reduzir margens do canvas** para aproveitar espaço disponível
2. ✅ **Manter proporções da imagem da íris**
3. ✅ **Garantir que mapa iridológico escala corretamente**
4. ✅ **Preservar funcionalidades existentes** (zoom, arrasto, polígonos)
5. ✅ **Não quebrar alinhamento** com controlos laterais

---

## 📊 ANÁLISE TÉCNICA

### Estrutura do Canvas (3 layers)

```xaml
<Canvas Width="1400" Height="1400">
    <!-- LAYER 0: Placeholder (Z-Index: 0) -->
    <TextBlock Panel.ZIndex="0" .../>

    <!-- LAYER 1: Imagem Real da Íris (Z-Index: 1) -->
    <Image x:Name="IrisCentralImage"
           Width="1400" Height="1400"
           Stretch="Uniform"
           Panel.ZIndex="1"/>

    <!-- LAYER 2: Mapa Iridológico + Polígonos (Z-Index: 2) -->
    <Canvas x:Name="MapaOverlayCanvas"
            Width="1400" Height="1400"
            Panel.ZIndex="2">
        <!-- Polígonos das zonas -->
        <ItemsControl ItemsSource="{Binding PoligonosZonas}"/>

        <!-- Círculos de calibração -->
        <Ellipse ... /> <!-- Círculo Pupila -->
        <Ellipse ... /> <!-- Círculo Limbo -->
    </Canvas>
</Canvas>
```

### Viewbox Container

```xaml
<Viewbox Stretch="Uniform">
    <Canvas Width="1400" Height="1400"/>
</Viewbox>
```

**Como funciona:**
- `Viewbox` escala o Canvas mantendo proporções (Stretch="Uniform")
- Canvas define dimensões "virtuais" de 1400x1400
- Imagem usa `Stretch="Uniform"` → mantém aspect ratio

---

## 💡 SOLUÇÃO PROPOSTA - REDUÇÃO DE MARGENS

### Opção 1: Aumentar Canvas para 1600x1600 (✅ RECOMENDADO)

**Vantagens:**
- ✅ Aumenta área útil em ~28%
- ✅ Mantém todas as proporções existentes
- ✅ Viewbox escala automaticamente
- ✅ Não quebra nenhuma funcionalidade
- ✅ Zero impacto no código-behind (C#)

**Implementação:**
```xaml
<!-- ANTES: Canvas 1400x1400 -->
<Canvas Width="1400" Height="1400" Background="White">

<!-- DEPOIS: Canvas 1600x1600 -->
<Canvas Width="1600" Height="1600" Background="White">
```

**Alterações necessárias:**
1. ✅ Canvas principal: `Width="1600" Height="1600"`
2. ✅ Image IrisCentralImage: `Width="1600" Height="1600"`
3. ✅ MapaOverlayCanvas: `Width="1600" Height="1600"`
4. ⚠️ **TextBlock placeholder**: Ajustar `Canvas.Left` e `Canvas.Top`

**Impacto no mapa iridológico:**
- Polígonos escalam automaticamente (coordenadas relativas)
- Transformações (zoom, pan) mantêm proporções
- Círculos de calibração mantêm-se centrados

---

### Opção 2: Ajustar Padding do Border (🟡 ALTERNATIVA)

**Vantagens:**
- ✅ Não altera dimensões do Canvas
- ✅ Reduz margem visual exterior

**Desvantagens:**
- ❌ Não resolve margens internas da imagem
- ❌ Efeito visual limitado

**Implementação:**
```xaml
<!-- ANTES -->
<Border Grid.Column="1"
        Background="#F7F9F6"
        CornerRadius="8"
        Padding="4"
        Margin="8,0">

<!-- DEPOIS -->
<Border Grid.Column="1"
        Background="#F7F9F6"
        CornerRadius="8"
        Padding="0"
        Margin="4,0">
```

---

### Opção 3: Clip Automático da Imagem (🔴 NÃO RECOMENDADO)

**Problema:**
- Cortaria partes da íris
- Perderia informação visual importante
- Quebraria alinhamento do mapa

---

## ✅ RECOMENDAÇÃO FINAL: OPÇÃO 1

### Implementação Detalhada

#### 1. Atualizar Dimensões do Canvas (3 locais)

**Localização:** `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml`

```xaml
<!-- Linha 259: Canvas principal -->
<Canvas Width="1600" Height="1600" Background="White">

<!-- Linha ~285: Image IrisCentralImage -->
<Image x:Name="IrisCentralImage"
       Width="1600" Height="1600"
       Source="{Binding ...}"
       Stretch="Uniform"
       Panel.ZIndex="1"/>

<!-- Linha ~303: MapaOverlayCanvas -->
<Canvas x:Name="MapaOverlayCanvas"
        Width="1600" Height="1600"
        Panel.ZIndex="2"
        Background="Transparent"
        ...>
```

#### 2. Ajustar Placeholder TextBlock

```xaml
<!-- ANTES: Placeholder centrado em 1400x1400 -->
<TextBlock Panel.ZIndex="0"
           Canvas.Left="200" Canvas.Top="650"
           Width="1000"
           Text="📷 Selecione uma imagem..."/>

<!-- DEPOIS: Placeholder centrado em 1600x1600 -->
<TextBlock Panel.ZIndex="0"
           Canvas.Left="300" Canvas.Top="750"
           Width="1000"
           Text="📷 Selecione uma imagem..."/>
```

**Cálculo do centro:**
```
Canvas.Left = (1600 - 1000) / 2 = 300
Canvas.Top  = (1600 / 2) - (altura_texto / 2) ≈ 750
```

#### 3. (Opcional) Reduzir Padding do Border

```xaml
<Border Grid.Column="1"
        Background="#F7F9F6"
        CornerRadius="8"
        Padding="2"
        Margin="8,0">
```

---

## 🧪 TESTES NECESSÁRIOS

### 1. Visual
- [ ] Imagem da íris preenche melhor o espaço
- [ ] Margens reduzidas visualmente (~1cm ou menos)
- [ ] Sem distorção da imagem
- [ ] Placeholder centrado corretamente

### 2. Funcional
- [ ] Mapa iridológico sobrepõe corretamente
- [ ] Zoom funciona (scroll mouse)
- [ ] Arrasto do mapa funciona (Mover Mapa)
- [ ] Círculos de calibração (Pupila/Limbo) alinham
- [ ] Polígonos das zonas escalam proporcionalmente

### 3. Navegação
- [ ] Alternar entre imagens mantém proporções
- [ ] Desligar mapa iridológico remove overlay
- [ ] Opacidade do mapa ajusta corretamente

---

## 📈 IMPACTO ESPERADO

### Ganhos
- 🎨 **+28% área útil** da imagem da íris
- 👁️ **Melhor visualização** de detalhes iridológicos
- 📱 **UX melhorada** (menos margem desperdiçada)

### Riscos
- ⚠️ **Baixo:** Desalinhamento do mapa (improvável, Viewbox escala tudo)
- ⚠️ **Baixo:** Placeholder mal posicionado (fácil de ajustar)

---

## 🛠️ PLANO DE IMPLEMENTAÇÃO

### Fase 1: Backup & Preparação ✅ CONCLUÍDO
- [x] Criar backup da base de dados
- [x] Commit das alterações atuais
- [x] Push para repositório

### Fase 2: Implementação
1. ✅ Alterar `Canvas Width/Height` de 1400 → 1600 (3 locais)
2. ✅ Ajustar `TextBlock` placeholder (Canvas.Left, Canvas.Top)
3. ✅ Reduzir `Border Padding` de 4 → 2 (opcional)
4. ✅ Build: `dotnet build`

### Fase 3: Testes
1. ✅ Executar aplicação
2. ✅ Abrir Ficha do Paciente → Tab Íris
3. ✅ Selecionar imagem (Maria Fernanda Costa)
4. ✅ Verificar:
   - Imagem preenche melhor o canvas
   - Mapa iridológico alinha corretamente
   - Zoom e arrasto funcionam
5. ✅ Testar com diferentes imagens

### Fase 4: Ajustes Finos
- Calibrar posição do placeholder (se necessário)
- Ajustar padding/margin do Border (se necessário)
- Validar com utilizador

---

## 📋 CHECKLIST DE ALTERAÇÕES

### Ficheiro: `IrisdiagnosticoUserControl.xaml`

```diff
- <Canvas Width="1400" Height="1400" Background="White">
+ <Canvas Width="1600" Height="1600" Background="White">

- <TextBlock Panel.ZIndex="0" Canvas.Left="200" Canvas.Top="650" Width="1000"
+ <TextBlock Panel.ZIndex="0" Canvas.Left="300" Canvas.Top="750" Width="1000"

- <Image x:Name="IrisCentralImage" Width="1400" Height="1400"
+ <Image x:Name="IrisCentralImage" Width="1600" Height="1600"

- <Canvas x:Name="MapaOverlayCanvas" Width="1400" Height="1400"
+ <Canvas x:Name="MapaOverlayCanvas" Width="1600" Height="1600"

- <Border Grid.Column="1" ... Padding="4" Margin="8,0">
+ <Border Grid.Column="1" ... Padding="2" Margin="8,0">
```

---

## 🎯 RESULTADO ESPERADO

### ANTES (1400x1400)
```
┌────────────────────────────────────┐
│ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │ ← Margem ~100px
│ ░░ ╔═══════════════════════════╗ ░░ │
│ ░░ ║                           ║ ░░ │
│ ░░ ║     IMAGEM ÍRIS 70%       ║ ░░ │
│ ░░ ║                           ║ ░░ │
│ ░░ ╚═══════════════════════════╝ ░░ │
│ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
└────────────────────────────────────┘
```

### DEPOIS (1600x1600)
```
┌────────────────────────────────────┐
│ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │ ← Margem ~30px
│ ╔═══════════════════════════════╗  │
│ ║                               ║  │
│ ║     IMAGEM ÍRIS 90%           ║  │
│ ║                               ║  │
│ ╚═══════════════════════════════╝  │
│ ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ │
└────────────────────────────────────┘
```

---

## ✅ CONCLUSÃO

**Recomendação:** Implementar **Opção 1** (Canvas 1400→1600).

**Benefícios:**
- ✅ Simples (5 linhas alteradas)
- ✅ Seguro (Viewbox escala automaticamente)
- ✅ +28% área útil
- ✅ Sem impacto em funcionalidades

**Próximo passo:** Implementar alterações e testar.

---

**Última atualização:** 07 de Outubro de 2025, 19:30
**Autor:** GitHub Copilot + Nuno Correia
**Versão:** BioDeskPro 2.0
