# 🎯 Análise UX - Movimento do Mapa Iridológico

**Data**: 5 outubro 2025  
**Status**: ⚠️ FUNCIONAL mas UX CONFUSA  
**Objetivo**: Simplificar fluxo de movimento do mapa para ser intuitivo

---

## 🔴 PROBLEMA IDENTIFICADO

### Fluxo Atual (Confuso e Errático)
```
1. ✅ Ativar mapa (checkbox "Mostrar Mapa")
2. ❌ Carregar "Modo Ajuste de Calibração" para handlers aparecerem
3. ❌ Carregar "Modo Mover Mapa"
4. ❌ Desmarcar "Modo Ajuste de Calibração"
5. ❌ Voltar a marcar "Modo Mover Mapa" (?)
6. ⚠️ Arrastar: Mapa DESAPARECE durante drag
7. ⚠️ Soltar: Mapa aparece no local final
```

### Sintomas Reportados
- **Fluxo errático**: Muitos passos desnecessários para ativar movimento
- **Dependências confusas**: "Modo Ajuste" deve ser ativado/desativado em ordem específica
- **Feedback visual pobre**: Mapa desaparece durante arrasto (não é user-friendly)
- **Expectativa vs Realidade**: Utilizador espera arrastar e VER o mapa a mover-se em tempo real

---

## 🧩 ARQUITETURA ATUAL

### Estado do ViewModel (IrisdiagnosticoViewModel.cs)

```csharp
// Flags de controle
[ObservableProperty]
private bool _mostrarMapaIridologico = false;  // ✅ Mapa visível

[ObservableProperty]
private bool _modoCalibracaoAtivo = false;     // ⚠️ Mostra handlers

[ObservableProperty]
private bool _modoMoverMapa = false;           // ⚠️ Ativa drag global
```

### Lógica de Drag (IrisdiagnosticoUserControl.xaml.cs)

```csharp
// MouseLeftButtonDown no MapaOverlayCanvas
if (!viewModel.ModoCalibracaoAtivo && !viewModel.ModoMoverMapa) return;
//     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
//     PROBLEMA: Requer um DOS dois modos ativos

viewModel.BeginDrag();  // ⚠️ Oculta polígonos durante drag
_isDraggingMapa = true;
```

```csharp
// MouseMove - Atualiza posição
viewModel.TransladarCalibracao(tipo, deltaX, deltaY);
```

```csharp
// MouseLeftButtonUp
viewModel.EndDrag();  // ⚠️ Força renderização final (mapa "aparece" aqui)
```

### Problema Crítico: `BeginDrag()` / `EndDrag()`

**IrisdiagnosticoViewModel.cs** (linha ~1800):
```csharp
public void BeginDrag()
{
    _isDragging = true;
    MostrarPoligonosDuranteArrasto = false;  // ⚠️ OCULTA mapa!
    RegistarEstadoAtual("BeginDrag");
}

public void EndDrag()
{
    _isDragging = false;
    MostrarPoligonosDuranteArrasto = true;   // ⚠️ MOSTRA mapa novamente
    RecalcularPoligonosComDeformacao();      // Força renderização
    RegistarEstadoAtual("EndDrag");
}
```

**XAML** (linha ~329):
```xaml
<ItemsControl ItemsSource="{Binding PoligonosZonas}"
              Visibility="{Binding MostrarPoligonosDuranteArrasto, 
                          Converter={StaticResource BoolToVisibilityConverter}}">
    <!-- Polígonos das zonas -->
</ItemsControl>
```

---

## ✅ SOLUÇÃO PROPOSTA

### Objetivo: Fluxo Simples e Intuitivo

```
1. ✅ Ativar mapa (checkbox "Mostrar Mapa")
2. ✅ Carregar "Modo Mover Mapa"
3. ✅ Arrastar: Mapa move-se EM TEMPO REAL (feedback visual contínuo)
4. ✅ Soltar: Mapa fica na posição final
```

### Mudanças Necessárias

#### 1. **Remover dependência de `ModoCalibracaoAtivo`**
```csharp
// ANTES (confuso)
if (!viewModel.ModoCalibracaoAtivo && !viewModel.ModoMoverMapa) return;

// DEPOIS (simples)
if (!viewModel.ModoMoverMapa) return;
```

#### 2. **Não ocultar polígonos durante drag em modo "Mover Mapa"**
```csharp
public void BeginDrag()
{
    _isDragging = true;
    
    // ✅ NOVO: Só oculta se estiver em modo calibração (handlers)
    if (ModoCalibracaoAtivo && !ModoMoverMapa)
    {
        MostrarPoligonosDuranteArrasto = false;
    }
    
    RegistarEstadoAtual("BeginDrag");
}

public void EndDrag()
{
    _isDragging = false;
    MostrarPoligonosDuranteArrasto = true;
    RecalcularPoligonosComDeformacao();
    RegistarEstadoAtual("EndDrag");
}
```

#### 3. **Atualizar feedback visual em tempo real**
```csharp
// MouseMove - chamar RecalcularPoligonosComDeformacao() durante drag
private void MapaOverlayCanvas_MouseMove(object sender, MouseEventArgs e)
{
    if (!_isDraggingMapa) return;
    if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
    
    // ... cálculo de deltaX/deltaY ...
    
    viewModel.TransladarCalibracao(tipo, deltaX, deltaY);
    
    // ✅ NOVO: Atualizar visual em tempo real (se não for modo calibração)
    if (viewModel.ModoMoverMapa)
    {
        viewModel.RecalcularPoligonosComDeformacao();
    }
    
    _ultimaPosicaoMapa = current;
    e.Handled = true;
}
```

#### 4. **Simplificar UI: Separar claramente os modos**

**XAML** (melhorar labels):
```xaml
<!-- MODO 1: Mover mapa globalmente -->
<ToggleButton Content="🖐️ Mover Mapa Completo"
              IsChecked="{Binding ModoMoverMapa}"
              ToolTip="Ativa modo de arrasto livre do mapa inteiro"
              IsEnabled="{Binding MostrarMapaIridologico}"/>

<!-- MODO 2: Ajuste fino (handlers) -->
<ToggleButton Content="🎯 Ajuste Fino (Handlers)"
              IsChecked="{Binding ModoCalibracaoAtivo}"
              ToolTip="Mostra pontos de controle para ajustar deformação"
              IsEnabled="{Binding MostrarMapaIridologico}"/>
```

---

## 🎨 MELHORIAS VISUAIS ADICIONAIS

### 1. **Cursor personalizado durante drag**
```csharp
// MouseLeftButtonDown
if (viewModel.ModoMoverMapa)
{
    MapaOverlayCanvas.Cursor = Cursors.SizeAll;  // ✋ cursor de movimento
}

// MouseLeftButtonUp
MapaOverlayCanvas.Cursor = Cursors.Arrow;
```

### 2. **Opacidade durante drag (feedback sutil)**
```xaml
<Canvas.Style>
    <Style TargetType="Canvas">
        <Setter Property="Opacity" Value="1.0"/>
        <Style.Triggers>
            <DataTrigger Binding="{Binding RelativeSource={RelativeSource Self}, 
                                   Path=IsMouseCaptured}" 
                         Value="True">
                <Setter Property="Opacity" Value="0.8"/>  <!-- Sutil -->
            </DataTrigger>
        </Style.Triggers>
    </Style>
</Canvas.Style>
```

### 3. **Tooltip explicativo no botão**
```xaml
<ToggleButton.ToolTip>
    <ToolTip>
        <StackPanel>
            <TextBlock Text="Modo Mover Mapa" FontWeight="Bold"/>
            <TextBlock Text="Arraste para reposicionar o mapa iridológico" 
                       Margin="0,4,0,0"/>
            <TextBlock Text="O mapa move-se em tempo real durante o arrasto" 
                       FontStyle="Italic" 
                       Foreground="#6B8E63"/>
        </StackPanel>
    </ToolTip>
</ToggleButton.ToolTip>
```

---

## 📋 CHECKLIST DE IMPLEMENTAÇÃO

### Fase 1: Simplificar Lógica ✅
- [ ] Remover dependência de `ModoCalibracaoAtivo` no MouseDown
- [ ] Ajustar `BeginDrag()` para não ocultar em modo "Mover Mapa"
- [ ] Adicionar `RecalcularPoligonosComDeformacao()` no MouseMove

### Fase 2: Melhorar Feedback Visual ✅
- [ ] Cursor SizeAll durante drag
- [ ] Opacidade sutil durante movimento (0.8)
- [ ] Tooltip explicativo nos botões

### Fase 3: Testar Fluxo Completo ✅
- [ ] Ativar mapa → Modo Mover → Arrastar (ver mapa em tempo real)
- [ ] Ativar mapa → Modo Calibração → Arrastar handlers (ver deformação)
- [ ] Alternar entre modos sem interferências

### Fase 4: Documentação ✅
- [ ] Atualizar `copilot-instructions.md` com novo fluxo
- [ ] Comentar código com explicação do comportamento
- [ ] Adicionar exemplos ao README

---

## 🚨 NOTAS IMPORTANTES

### Performance
- `RecalcularPoligonosComDeformacao()` é chamado frequentemente em MouseMove
- Verificar se causa lag (testar em máquina menos potente)
- Se necessário, adicionar throttling (300ms entre recálculos)

### Compatibilidade
- Manter modo calibração (handlers) funcional
- Dois modos devem ser mutuamente exclusivos (radio buttons?)
- Ou permitir ambos ativos simultaneamente (handlers + drag global)

### Debug
- Manter `DragDebugLogger` funcional para diagnóstico
- Adicionar eventos específicos para "drag em tempo real"

---

## 📊 MÉTRICAS DE SUCESSO

✅ **Fluxo simplificado**: Máximo 3 cliques para mover mapa  
✅ **Feedback visual**: Mapa visível durante 100% do drag  
✅ **Intuitivo**: Novo utilizador consegue mover sem instruções  
✅ **Performance**: Sem lag visível em máquina comum (60fps)

---

**Próximo passo**: Implementar mudanças na ordem da checklist ⬆️
