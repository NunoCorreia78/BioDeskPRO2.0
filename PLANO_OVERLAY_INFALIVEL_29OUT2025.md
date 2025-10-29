# 🎯 PLANO DE IMPLEMENTAÇÃO - Sistema Infalível de Overlay Íris

**Data**: 29 de outubro de 2025
**Objetivo**: Substituir sistema complexo de calibração/handlers/deformação por sistema 3-click + OpenCV auto-fit

---

## ✅ O QUE JÁ FOI FEITO

1. ✅ **Emgu.CV instalado** (`BioDesk.Services.csproj` - linhas 12-13)
2. ✅ **IrisOverlayService criado** (`src/BioDesk.Services/Iridology/IrisOverlayService.cs`)
   - 380 linhas
   - Sistema 3-click completo
   - Detecção OpenCV (Canny + FitEllipse)
   - Fallback manual garantido
   - CA1063 compliant (Dispose pattern correto)
   - **Compila sem erros** ✅

---

## 🗑️ O QUE SERÁ REMOVIDO

### **A. ViewModel (`IrisdiagnosticoViewModel.cs` - 3169 linhas)**

#### Propriedades para DELETAR (estimativa: ~800 linhas):

```csharp
// CALIBRAÇÃO (linhas ~120-280)
- ModoCalibracaoAtivo
- TipoCalibracaoPupila, TipoCalibracaoIris, TipoCalibracaoAmbos
- ModoMoverMapa
- HandlersPupila, HandlersIris (ObservableCollections)
- QuantidadeHandlersIris, QuantidadeHandlersPupila
- CalibrationHandler (classe interna)

// CENTROS E RAIOS (linhas ~220-260)
- CentroPupilaX, CentroPupilaY, RaioPupila
- RaioPupilaHorizontal, RaioPupilaVertical
- CentroIrisX, CentroIrisY, RaioIris
- RaioIrisHorizontal, RaioIrisVertical
- EscalaIrisX, EscalaIrisY, EscalaPupilaX, EscalaPupilaY

// CONSTANTES DE CALIBRAÇÃO (linhas ~265-275)
- RAIO_NOMINAL_PUPILA, RAIO_NOMINAL_IRIS
- PUPILA_NORMALIZED_THRESHOLD, PUPILA_TRANSITION_WIDTH
- MAPA_ZOOM_MIN, MAPA_ZOOM_MAX, MAPA_ZOOM_STEP

// AJUSTE FINO (linhas ~285-302)
- MapaOffsetX, MapaOffsetY
- AJUSTE_FINO_INCREMENTO, AJUSTE_RAPIDO_INCREMENTO

// SISTEMA MARCAÇÃO 8 PONTOS (linhas ~305-420)
- ModoMarcacaoPupila, ModoMarcacaoIris
- PontoAtual, PontosConcluidosAtual
- PontosDefinidosPupila, PontosDefinidosIris
- PontoVisual (classe), ClickFeedback (classe)

// FLAGS DE CONTROLO (linhas ~195-210)
- _atualizandoContagemHandlers
- _suspendHandlerUpdates
- _isDragging
- _lastRenderTime, RenderThrottleMs
- MostrarPoligonosDuranteArrasto
```

#### Métodos para DELETAR (estimativa: ~1500 linhas):

```csharp
// INICIALIZAÇÃO HANDLERS
- InicializarHandlersPupila()
- InicializarHandlersIris()
- EnsureHandlersInitialized()
- OnQuantidadeHandlersIrisChanged()
- OnQuantidadeHandlersPupilaChanged()

// DRAG HANDLERS
- AtualizarPosicaoHandler()
- TransladarCalibracao()
- BeginDrag(), EndDrag()

// ZOOM/ESCALA MAPA
- AjustarMapaZoom()
- AplicarEscalaMapa()
- ZoomInMapaCommand, ZoomOutMapaCommand, ResetZoomMapaCommand

// AJUSTE FINO
- MoverMapaEsquerdaCommand, MoverMapaDireitaCommand
- MoverMapaCimaCommand, MoverMapaBaixoCommand
- ResetOffsetMapaCommand

// MARCAÇÃO 8 PONTOS
- IniciarMarcacaoPupilaCommand, IniciarMarcacaoIrisCommand
- ProcessarCliqueMarcacao()
- ConcluirMarcacaoCommand, CancelarMarcacaoCommand

// DEFORMAÇÃO POLÍGONOS
- RecalcularPoligonosComDeformacao()
- CalcularCentroide()
- AplicarDeformacaoRadial()

// DEBUG
- RecordDragEvent(), TrackDragEvent()
- ConstruirContextoPadrao(), ConstruirMetricasCentros()
```

### **B. UserControl XAML (`IrisdiagnosticoUserControl.xaml` - 2430 linhas)**

#### Remover LAYER 4 completo (linhas ~482-730):

```xaml
<!-- LAYER 4: Handlers de Calibração -->
<Canvas x:Name="HandlersCanvas" ... >
  <!-- Handlers da PUPILA (8 handlers) -->
  <ItemsControl ItemsSource="{Binding HandlersPupila}">...</ItemsControl>

  <!-- Handlers da ÍRIS (8 handlers) -->
  <ItemsControl ItemsSource="{Binding HandlersIris}">...</ItemsControl>

  <!-- Handler central da PUPILA -->
  <Ellipse ... Tag="Pupila" .../>

  <!-- Handler central da ÍRIS -->
  <Ellipse ... Tag="Iris" .../>
</Canvas>
```

#### Remover controles de calibração (estimativa: ~400 linhas em painel direito):

- Botões "Modo Calibração", "Pupila", "Íris", "Ambos"
- Sliders de quantidade de handlers
- Botões Zoom In/Out Mapa
- Botões de ajuste fino (setas direcionais)
- Slider de opacidade do mapa
- Modo mover mapa toggle
- Painel de marcação 8 pontos
- Instruções de calibração

### **C. UserControl Code-Behind (`IrisdiagnosticoUserControl.xaml.cs`)**

#### Remover eventos (estimativa: ~300 linhas):

```csharp
// DRAG HANDLERS
- Handler_MouseDown()
- Handler_MouseMove()
- Handler_MouseUp()

// DRAG MAPA OVERLAY
- MapaOverlayCanvas_MouseLeftButtonDown()
- MapaOverlayCanvas_MouseMove()
- MapaOverlayCanvas_MouseLeftButtonUp()
- MapaOverlayCanvas_MouseLeave()

// HELPERS
- GetMapaPositionRelativeToHandlers()
- BuildCentroMetrics()
- BuildContext()
```

---

## ➕ O QUE SERÁ ADICIONADO

### **A. ViewModel (`IrisdiagnosticoViewModel.cs`)**

#### Novas Propriedades (~50 linhas):

```csharp
// OVERLAY SERVICE
private readonly IrisOverlayService _overlayService;

// ESTADO DO ALINHAMENTO
[ObservableProperty]
private bool _isAlignmentActive;

[ObservableProperty]
private string? _alignmentInstructionText;

[ObservableProperty]
private Transform? _overlayTransform;

// Mantém MapaZoom e TranslateX/Y para compatibilidade
```

#### Novos Comandos (~150 linhas):

```csharp
[RelayCommand]
private void StartOverlayAlignment()
{
    _overlayService.StartAlignment();
    IsAlignmentActive = true;
    AlignmentInstructionText = _overlayService.InstructionText;
}

[RelayCommand]
private async Task AutoFitOverlayAsync()
{
    if (IrisImagemSelecionada?.CaminhoImagem == null) return;

    await ExecuteWithErrorHandlingAsync(async () =>
    {
        // Carregar imagem
        var bitmap = new BitmapImage(new Uri(IrisImagemSelecionada.CaminhoImagem));

        // Auto-fit OpenCV
        bool success = await _overlayService.AutoFitAsync(bitmap);

        if (success)
        {
            OverlayTransform = _overlayService.GetCurrentTransform();
            AlignmentInstructionText = _overlayService.InstructionText;
        }
        else
        {
            AlignmentInstructionText = "⚠️ Auto-fit falhou. Use ajuste manual.";
        }
    },
    errorContext: "ao executar auto-fit do overlay",
    logger: _logger);
}

[RelayCommand]
private void ConfirmAlignment()
{
    _overlayService.ConfirmAlignment();
    IsAlignmentActive = false;
    AlignmentInstructionText = null;
}

[RelayCommand]
private void ResetAlignment()
{
    _overlayService.ResetAlignment();
    OverlayTransform = null;
    StartOverlayAlignment();
}

// Handler de clique durante 3-click phase
public void ProcessOverlayClick(Point clickPosition)
{
    bool completed = _overlayService.ProcessClick(clickPosition);
    AlignmentInstructionText = _overlayService.InstructionText;

    if (completed)
    {
        // 3 cliques completos → aplicar transformação inicial
        OverlayTransform = _overlayService.GetCurrentTransform();
    }
}
```

### **B. XAML (`IrisdiagnosticoUserControl.xaml`)**

#### Adicionar botões de alinhamento (substituir controles de calibração):

```xaml
<!-- PAINEL DE ALINHAMENTO OVERLAY (substituir controles antigos) -->
<StackPanel Margin="0,10,0,0">
  <TextBlock Text="🎯 Alinhamento Mapa Iridológico"
             Style="{StaticResource SubtituloStyle}"/>

  <!-- Botão Iniciar Alinhamento -->
  <Button Content="▶️ Iniciar Alinhamento (3 cliques)"
          Command="{Binding StartOverlayAlignmentCommand}"
          Style="{StaticResource BotaoPrimario}"
          Margin="0,8,0,0">
    <Button.Style>
      <Style TargetType="Button" BasedOn="{StaticResource BotaoPrimario}">
        <Setter Property="Visibility" Value="Visible"/>
        <Style.Triggers>
          <DataTrigger Binding="{Binding IsAlignmentActive}" Value="True">
            <Setter Property="Visibility" Value="Collapsed"/>
          </DataTrigger>
        </Style.Triggers>
      </Style>
    </Button.Style>
  </Button>

  <!-- Botão Auto-Fit -->
  <Button Content="🤖 Auto-Fit (Detecção Automática)"
          Command="{Binding AutoFitOverlayCommand}"
          Style="{StaticResource BotaoSucesso}"
          Margin="0,8,0,0">
    <Button.Style>
      <Style TargetType="Button" BasedOn="{StaticResource BotaoSucesso}">
        <Setter Property="Visibility" Value="Collapsed"/>
        <Style.Triggers>
          <DataTrigger Binding="{Binding IsAlignmentActive}" Value="True">
            <Setter Property="Visibility" Value="Visible"/>
          </DataTrigger>
        </Style.Triggers>
      </Style>
    </Button.Style>
  </Button>

  <!-- Botão Confirmar -->
  <Button Content="✓ Confirmar Alinhamento"
          Command="{Binding ConfirmAlignmentCommand}"
          Style="{StaticResource BotaoSucesso}"
          Margin="0,8,0,0">
    <Button.Style>
      <Style TargetType="Button" BasedOn="{StaticResource BotaoSucesso}">
        <Setter Property="Visibility" Value="Collapsed"/>
        <Style.Triggers>
          <DataTrigger Binding="{Binding IsAlignmentActive}" Value="True">
            <Setter Property="Visibility" Value="Visible"/>
          </DataTrigger>
        </Style.Triggers>
      </Style>
    </Button.Style>
  </Button>

  <!-- Botão Resetar -->
  <Button Content="↻ Reiniciar"
          Command="{Binding ResetAlignmentCommand}"
          Style="{StaticResource BotaoSecundario}"
          Margin="0,8,0,0">
    <Button.Style>
      <Style TargetType="Button" BasedOn="{StaticResource BotaoSecundario}">
        <Setter Property="Visibility" Value="Collapsed"/>
        <Style.Triggers>
          <DataTrigger Binding="{Binding IsAlignmentActive}" Value="True">
            <Setter Property="Visibility" Value="Visible"/>
          </DataTrigger>
        </Style.Triggers>
      </Style>
    </Button.Style>
  </Button>

  <!-- Instruções Contextuais -->
  <Border Background="#FFECB3"
          BorderBrush="#D4A849"
          BorderThickness="1"
          CornerRadius="4"
          Padding="10"
          Margin="0,12,0,0">
    <Border.Style>
      <Style TargetType="Border">
        <Setter Property="Visibility" Value="Collapsed"/>
        <Style.Triggers>
          <DataTrigger Binding="{Binding AlignmentInstructionText, Converter={StaticResource NullToVisibilityConverter}}" Value="Visible">
            <Setter Property="Visibility" Value="Visible"/>
          </DataTrigger>
        </Style.Triggers>
      </Style>
    </Border.Style>
    <TextBlock Text="{Binding AlignmentInstructionText}"
               TextWrapping="Wrap"
               FontSize="12"
               Foreground="#5A4A20"/>
  </Border>
</StackPanel>
```

#### Modificar MapaOverlayCanvas para aplicar OverlayTransform:

```xaml
<!-- LAYER 2: Mapa Iridológico -->
<Canvas x:Name="MapaOverlayCanvas"
        Width="1400" Height="1400"
        Panel.ZIndex="2"
        Background="Transparent"
        MouseLeftButtonDown="MapaOverlayCanvas_Click">  <!-- NOVO handler -->
  <Canvas.RenderTransform>
    <!-- Aplicar transformação do IrisOverlayService -->
    <Binding Path="OverlayTransform" FallbackValue="{x:Static Transform.Identity}"/>
  </Canvas.RenderTransform>

  <!-- Polígonos (mantém igual) -->
  <ItemsControl ItemsSource="{Binding PoligonosZonas}">
    ...
  </ItemsControl>
</Canvas>
```

### **C. Code-Behind (`IrisdiagnosticoUserControl.xaml.cs`)**

#### Adicionar handler de clique (substituir métodos antigos):

```csharp
/// <summary>
/// Processa clique no mapa overlay durante fase 3-click
/// </summary>
private void MapaOverlayCanvas_Click(object sender, MouseButtonEventArgs e)
{
    if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
    if (!viewModel.IsAlignmentActive) return;

    // Obter posição do clique relativa ao canvas
    var position = e.GetPosition(MapaOverlayCanvas);

    // Processar no ViewModel
    viewModel.ProcessOverlayClick(position);

    e.Handled = true;
}
```

### **D. Dependency Injection (`App.xaml.cs`)**

```csharp
// Adicionar na seção de Services (linha ~90-110)
services.AddSingleton<IrisOverlayService>();
```

---

## 📊 RESUMO DE IMPACTO

### Linhas de Código:

| Componente | Antes | Depois | Redução |
|------------|-------|--------|---------|
| `IrisdiagnosticoViewModel.cs` | 3169 linhas | ~1400 linhas | **-56%** |
| `IrisdiagnosticoUserControl.xaml` | 2430 linhas | ~2000 linhas | **-18%** |
| `IrisdiagnosticoUserControl.xaml.cs` | ~600 linhas | ~250 linhas | **-58%** |
| **NOVO**: `IrisOverlayService.cs` | - | 385 linhas | +385 |
| **TOTAL** | ~6199 linhas | ~4035 linhas | **-35%** (2164 linhas removidas) |

### Complexidade:

- **Antes**: 8-12 handlers arrastáveis + calibração manual + deformação radial + debugging extensivo
- **Depois**: 3 cliques + auto-fit OpenCV + fallback manual simples
- **User Experience**: De ~2 minutos (calibração manual) para **5 segundos** (3 cliques + aceitar)

---

## ✅ CRITÉRIOS DE SUCESSO

1. ✅ Build passa sem erros (`dotnet build`)
2. ✅ Testes passam (`dotnet test`)
3. ✅ Aplicação abre e navega para tab Íris sem crash
4. ✅ User consegue:
   - Clicar "Iniciar Alinhamento"
   - Fazer 3 cliques (centro, direita, topo)
   - Ver transformação aplicada automaticamente
   - (Opcional) Clicar "Auto-Fit" para refinamento OpenCV
   - Clicar "Confirmar" e ver mapa alinhado persistir
5. ✅ Nenhuma funcionalidade existente quebra (galeria imagens, marcações, zoom)

---

## 🚀 ORDEM DE EXECUÇÃO PROPOSTA

1. **Registar IrisOverlayService no DI** (`App.xaml.cs`)
2. **Adicionar comandos no ViewModel** (Start/AutoFit/Confirm/Reset)
3. **Remover LAYER 4 (HandlersCanvas) do XAML**
4. **Adicionar botões de alinhamento no XAML**
5. **Modificar MapaOverlayCanvas RenderTransform binding**
6. **Adicionar MapaOverlayCanvas_Click no code-behind**
7. **Remover métodos de calibração do ViewModel** (bulk delete)
8. **Remover propriedades de calibração do ViewModel** (bulk delete)
9. **Remover event handlers antigos do code-behind**
10. **Build + Test + Run**

---

## ⚠️ RISCOS E MITIGAÇÕES

| Risco | Probabilidade | Mitigação |
|-------|---------------|-----------|
| OpenCV falhar em algumas imagens | Média | **Fallback garantido**: transf. dos 3 cliques sempre funciona |
| Binding de Transform não funcionar | Baixa | Testar com Transform.Identity como fallback |
| Performance do OpenCV travar UI | Baixa | Detecção já está em `Task.Run()` (thread separada) |
| User não entender 3-click | Baixa | Instruções contextuais claras + tooltips |
| Quebrar PoligonosZonas | Baixa | PoligonosZonas não depende de handlers, só do Transform |

---

## 🎯 APROVAÇÃO

**ANTES DE EXECUTAR**, confirme:

- [ ] **Concordo com a remoção completa do sistema de calibração/handlers**
- [ ] **Entendo que o sistema 3-click + OpenCV é mais simples e user-friendly**
- [ ] **Autorizo a execução do plano acima**

---

**Aguardando aprovação explícita para proceder. Responda "APROVAR" para iniciar implementação.**
