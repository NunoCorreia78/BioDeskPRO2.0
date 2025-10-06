# 📐 Análise Completa: Controle de Tamanho da Iris e Mapa Sobreposto

**Data:** 06/10/2025  
**Branch analisado:** `copilot/fix-dac30c61-7617-4edb-91e2-a9f8ae0e12e7`  
**Status das alterações propostas:** ✅ CORRETAS (focam em performance/logging, não alteram dimensões)

---

## 🎯 LOCALIZAÇÃO EXATA DOS CONTROLES DE TAMANHO

### 1. **Tamanho Base do Canvas (XAML)**
**Ficheiro:** `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml`

#### 📍 Linha 256: Canvas Principal
```xaml
<Canvas Width="950" Height="950" Background="White">
```
**Controla:** Dimensão total do espaço de trabalho (iris + mapa).

#### 📍 Linha 260: Imagem da Iris (Layer 1)
```xaml
<Image x:Name="IrisCentralImage"
       Width="950" Height="950"
       Source="{Binding IrisImagemSelecionada.CaminhoImagem, ...}"
       Stretch="Uniform"
       Panel.ZIndex="1">
```
**Controla:** 
- **Width/Height:** Tamanho máximo da imagem da iris
- **Stretch="Uniform":** Mantém proporção circular (centraliza automaticamente)

#### 📍 Linha 278: Mapa Sobreposto (Layer 2)
```xaml
<Canvas x:Name="MapaOverlayCanvas"
    Width="950" Height="950"
    Panel.ZIndex="2"
    Background="Transparent"
    ...>
    <Canvas.RenderTransform>
        <ScaleTransform ScaleY="-1" CenterY="475"/>
    </Canvas.RenderTransform>
```
**Controla:** 
- **Width/Height:** Tamanho do canvas do mapa (igual à iris)
- **CenterY="475":** Centro do flip vertical (950/2 = 475)

#### 📍 Linha 351: Handlers de Calibração (Layer 3)
```xaml
<Canvas x:Name="HandlersCanvas"
        Width="950" Height="950"
        Panel.ZIndex="3"
```
**Controla:** Tamanho dos handlers de ajuste (devem coincidir com iris/mapa).

---

### 2. **Padding do Container (Espaço Disponível)**
**Ficheiro:** `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml`

#### 📍 Linha 251: Padding do Border
```xaml
<Border Grid.Column="1"
        Background="#F7F9F6"
        CornerRadius="8"
        Padding="4"    <!-- ⚠️ CRÍTICO: controla espaço disponível -->
        Margin="8,0">
```
**Impacto:**
- `Padding="4"` → Iris tem **942px disponíveis** na vertical (950 - 8)
- `Padding="16"` → Iris teria apenas **918px** (reduz 24px)

---

### 3. **Escala Dinâmica do Mapa (ViewModel)**
**Ficheiro:** `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs`

#### 📍 Propriedade MapaZoom (Linha ~140)
```csharp
[ObservableProperty]
private double _mapaZoom = 1.0;  // Escala inicial do mapa
```

#### 📍 Método AplicarEscalaMapa (Linha 1696)
```csharp
private void AplicarEscalaMapa(double multiplicador)
{
    if (Math.Abs(multiplicador - 1.0) < 0.0001) return;

    _suspendHandlerUpdates = true;
    try
    {
        // 🔍 ESCALA PUPILA
        if (HandlersPupila.Count > 0)
        {
            var centroX = CentroPupilaX;
            var centroY = CentroPupilaY;

            foreach (var handler in HandlersPupila)
            {
                double offsetX = (handler.X + 8) - centroX;
                double offsetY = (handler.Y + 8) - centroY;

                handler.X = centroX + offsetX * multiplicador - 8;
                handler.Y = centroY + offsetY * multiplicador - 8;
            }
        }

        // 🔍 ESCALA IRIS
        if (HandlersIris.Count > 0)
        {
            var centroX = CentroIrisX;
            var centroY = CentroIrisY;

            foreach (var handler in HandlersIris)
            {
                double offsetX = (handler.X + 8) - centroX;
                double offsetY = (handler.Y + 8) - centroY;

                handler.X = centroX + offsetX * multiplicador - 8;
                handler.Y = centroY + offsetY * multiplicador - 8;
            }
        }
    }
    finally
    {
        _suspendHandlerUpdates = false;
    }

    AtualizarTransformacoesGlobais();  // ⚠️ Recalcula polígonos
}
```

**Como funciona:**
1. Calcula offset de cada handler em relação ao centro
2. Multiplica offset pelo fator de escala
3. Reposiciona handler mantendo proporção radial

---

## 🔧 COMO AJUSTAR O TAMANHO DA IRIS/MAPA

### ✅ Opção 1: Aumentar Canvas (Recomendado)
**Para aumentar iris SEM cortar:**

1. Aumentar todas as dimensões proporcionalmente:
```xaml
<!-- IrisdiagnosticoUserControl.xaml -->

<!-- Canvas principal -->
<Canvas Width="1000" Height="1000" Background="White">

<!-- Imagem da iris -->
<Image x:Name="IrisCentralImage"
       Width="1000" Height="1000"

<!-- Mapa sobreposto -->
<Canvas x:Name="MapaOverlayCanvas"
    Width="1000" Height="1000"
    <Canvas.RenderTransform>
        <ScaleTransform ScaleY="-1" CenterY="500"/>  <!-- 1000/2 -->
    </Canvas.RenderTransform>

<!-- Handlers -->
<Canvas x:Name="HandlersCanvas"
        Width="1000" Height="1000"
```

2. Atualizar CenterY do ScaleTransform:
   - **Regra:** `CenterY = Canvas.Height / 2`
   - 950 → CenterY="475"
   - 1000 → CenterY="500"
   - 1100 → CenterY="550"

### ✅ Opção 2: Reduzir Padding (Ganhar Espaço)
**Já aplicado na versão atual:**
```xaml
<Border Grid.Column="1"
        Padding="4"    <!-- Era 16, agora 4 → ganha 24px -->
```

### ⚠️ Opção 3: UniformToFill (NÃO RECOMENDADO)
```xaml
<Viewbox Stretch="UniformToFill">  <!-- ❌ Corta bordas da iris -->
```
**Problema:** Preenche espaço mas **corta** partes da imagem circular.

---

## 🎨 CALIBRAÇÃO DO MAPA SOBREPOSTO

### Propriedades de Zoom/Opacidade
**Ficheiro:** `IrisdiagnosticoViewModel.cs`

```csharp
// Zoom do mapa (0.5x a 2.0x)
[ObservableProperty]
private double _mapaZoom = 1.0;

// Opacidade do mapa (0% a 100%)
[ObservableProperty]
private double _opacidadeMapa = 0.5;  // 50% por defeito
```

### Comandos de Ajuste
```csharp
[RelayCommand]
private void ZoomInMapa() => AjustarZoomMapa(0.1);   // +10%

[RelayCommand]
private void ZoomOutMapa() => AjustarZoomMapa(-0.1);  // -10%

[RelayCommand]
private void ResetZoomMapa() => MapaZoom = 1.0;       // Reset 100%
```

---

## 🐛 PROBLEMA ATUAL: MAPA NÃO ESCALA PROPORCIONALMENTE

### Causa Raiz
O **Canvas do mapa** tem tamanho fixo (950x950) e usa **TranslateTransform** para mover, mas **NÃO tem ScaleTransform global aplicado aos polígonos**.

### Diagnóstico
```xaml
<!-- ❌ FALTA ScaleTransform para zoom do mapa -->
<Canvas x:Name="MapaOverlayCanvas" Width="950" Height="950">
    <Canvas.RenderTransform>
        <ScaleTransform ScaleY="-1" CenterY="475"/>  <!-- Só flip vertical -->
    </Canvas.RenderTransform>
```

### Solução Proposta
Adicionar **TransformGroup** com Scale + Translate:

```xaml
<Canvas x:Name="MapaOverlayCanvas" Width="950" Height="950">
    <Canvas.RenderTransform>
        <TransformGroup>
            <!-- 1. Flip vertical (mapa invertido) -->
            <ScaleTransform ScaleY="-1" CenterY="475"/>
            
            <!-- 2. Escala global do mapa (binding ao MapaZoom) -->
            <ScaleTransform 
                ScaleX="{Binding MapaZoom}" 
                ScaleY="{Binding MapaZoom}"
                CenterX="475" 
                CenterY="475"/>
            
            <!-- 3. Translação para mover mapa -->
            <TranslateTransform 
                X="{Binding TranslateX}" 
                Y="{Binding TranslateY}"/>
        </TransformGroup>
    </Canvas.RenderTransform>
```

**Ordem crítica:** ScaleY flip → Scale zoom → Translate move

---

## 📊 VERIFICAÇÃO DAS ALTERAÇÕES DO BRANCH PROPOSTO

### Ficheiros Modificados
```
✅ .gitignore                          → Remove artefactos de log
✅ CORRECOES_LOGGING_PERFORMANCE.md    → Documentação
✅ DragDebugLogger.cs                  → Novo serviço async logging
✅ DragDebugService.cs                 → Implementação logging
✅ IDragDebugService.cs                → Interface logging
✅ IrisdiagnosticoUserControl.xaml.cs  → Remove Console.WriteLine
✅ IrisdiagnosticoViewModel.cs         → Remove File.AppendAllText
```

### ⚠️ NENHUMA alteração às dimensões do Canvas/Imagem
As propostas do agente **NÃO tocam** em:
- Canvas Width/Height
- Image Width/Height  
- Padding do Border
- ScaleTransform CenterY

**Conclusão:** Alterações são **seguras** e focam apenas em **performance/logging**.

---

## 🚀 PRÓXIMOS PASSOS RECOMENDADOS

### 1. Corrigir Escala do Mapa (PRIORIDADE ALTA)
**Problema:** Zoom do mapa não funciona de forma proporcional.
**Solução:** Implementar TransformGroup no MapaOverlayCanvas (código acima).

### 2. Aumentar Tamanho Máximo (Se necessário)
**Se iris ainda pequena após Padding="4":**
```xaml
<!-- Testar com 1000x1000 -->
<Canvas Width="1000" Height="1000">
<Image Width="1000" Height="1000">
<ScaleTransform CenterY="500"/>  <!-- 1000/2 -->
```

### 3. Aceitar Branch do Agente (RECOMENDADO)
```bash
git checkout copilot/fix-dac30c61-7617-4edb-91e2-a9f8ae0e12e7
git merge main
# Testar app
git checkout main
git merge copilot/fix-dac30c61-7617-4edb-91e2-a9f8ae0e12e7
```

**Benefícios:**
- ✅ Remove logging síncrono pesado (File.AppendAllText)
- ✅ Melhora performance de arrasto/zoom
- ✅ Limpa artefactos de debug do repositório
- ✅ Adiciona serviço async profissional

---

## 📐 FÓRMULAS DE CÁLCULO

### Centro do ScaleTransform
```
CenterY = Canvas.Height / 2
```

**Exemplos:**
- 600x600 → CenterY = 300
- 800x800 → CenterY = 400
- 950x950 → CenterY = 475 ✅ (atual)
- 1000x1000 → CenterY = 500

### Espaço Disponível Real
```
Espaço = Canvas.Height - (2 × Border.Padding)
```

**Exemplo atual:**
- Canvas: 950px
- Padding: 4px
- **Disponível:** 950 - (2×4) = **942px**

### Escala Radial dos Handlers
```csharp
newX = centerX + (oldX - centerX) × multiplicador
newY = centerY + (oldY - centerY) × multiplicador
```

Mantém proporção radial em zoom/escala.

---

## ✅ CHECKLIST DE VERIFICAÇÃO

Antes de fazer merge do branch proposto:

- [ ] Build compila sem erros (`dotnet build`)
- [ ] App executa e mostra iris corretamente
- [ ] Arrasto do mapa funciona (modo "Mover Mapa")
- [ ] Botões +/- zoom respondem
- [ ] Handlers de calibração movem-se
- [ ] Performance melhorou (sem lag em arrasto)
- [ ] Nenhum ficheiro .log gerado durante uso
- [ ] .gitignore ignora DebugOutput/**

---

**Conclusão Final:**
- ✅ Branch proposto está **correto** e **seguro**
- ⚠️ Problema de escala do mapa **NÃO está resolvido** (precisa TransformGroup)
- 📐 Tamanho atual (950x950) é **adequado**, ajustar apenas se necessário
- 🎯 Aplicar branch + corrigir TransformGroup = **solução completa**
