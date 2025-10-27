# 🚀 Refatoração Íris - Quick Reference

## ✅ O Que Já Foi Feito (Fase 1)

### Método FromHandlers Adicionado ✅
```csharp
// IridologyTransform.cs - LINHA ~196
public static CalibrationEllipse FromHandlers(IEnumerable<Point> handlers)
{
    // Calcula elipse a partir de 8 pontos
    // Centro = média dos pontos
    // Raio = média das distâncias ao centro
    // Detecta elipse se variação > 15%
}
```

### Handlers Atualizados: 12 → 8 ✅
```csharp
// IrisdiagnosticoViewModel.cs
private int _quantidadeHandlersIris = 8;      // Era 12
private int _quantidadeHandlersPupila = 8;    // Era 12
```

### Validação: 6 → 8 ✅
```csharp
// InicializarHandlers
var totalIris = Math.Max(8, ...);    // Era Math.Max(6, ...)
var totalPupila = Math.Max(8, ...);  // Era Math.Max(6, ...)
```

---

## 🎯 Próximos Passos Críticos

### 1. Integrar Handler_MouseMove (CRÍTICO!)

**Localizar** em `IrisdiagnosticoUserControl.xaml.cs`:
```csharp
private void Handler_MouseMove(object sender, MouseEventArgs e)
```

**Substituir por**:
```csharp
private void Handler_MouseMove(object sender, MouseEventArgs e)
{
    if (!_isDraggingHandler || _currentHandler == null) return;
    if (DataContext is not IrisdiagnosticoViewModel viewModel) return;
    
    var position = e.GetPosition(HandlersCanvas);
    _currentHandler.X = position.X - 8;
    _currentHandler.Y = position.Y - 8;
    
    // ⭐ NOVO: Usar FromHandlers
    var pontosPupila = viewModel.HandlersPupila.Select(h => new Point(h.X + 8, h.Y + 8));
    var pontosIris = viewModel.HandlersIris.Select(h => new Point(h.X + 8, h.Y + 8));
    
    var elipsePupila = IridologyTransform.FromHandlers(pontosPupila);
    var elipseIris = IridologyTransform.FromHandlers(pontosIris);
    
    viewModel.AtualizarCalibracao(elipsePupila, elipseIris);
}
```

### 2. Adicionar AtualizarCalibracao() no ViewModel

**Adicionar** em `IrisdiagnosticoViewModel.cs`:
```csharp
public void AtualizarCalibracao(CalibrationEllipse pupila, CalibrationEllipse iris)
{
    CentroPupilaX = pupila.Center.X;
    CentroPupilaY = pupila.Center.Y;
    CentroIrisX = iris.Center.X;
    CentroIrisY = iris.Center.Y;
    
    RaioPupilaHorizontal = pupila.RadiusX;
    RaioPupilaVertical = pupila.RadiusY;
    RaioIrisHorizontal = iris.RadiusX;
    RaioIrisVertical = iris.RadiusY;
    
    AtualizarTransformacoesGlobais();
}
```

### 3. Remover Código Obsoleto (OPCIONAL)

**Métodos a remover** (~400 linhas):
- `InterpolateZoneWithHandlers()` - linha ~2270
- `RecalcularPoligonosComDeformacao()` - linha ~2192
- `RenderizarPoligonosComDeformacao()` - linha ~2236
- `InterpolateRadiusFromHandlers()` - linha ~2398

**Propriedades a remover**:
- `_modoMoverMapa`
- `_modoCalibracaoAtivo`
- `_opacidadeMapa`

**Botões XAML a remover**:
- "🔍 Mostrar Mapa" - linha ~1091
- "🖐️ Mover Mapa" - linha ~1141
- "🎯 Ajuste Fino" - linha ~1442
- "🔄 Reset Calibração" - linha ~1495

---

## 🧪 Teste Rápido

```powershell
# 1. Build
dotnet clean && dotnet build

# 2. Run
dotnet run --project src/BioDesk.App

# 3. Testar
# - Abrir aba Íris
# - Adicionar imagem
# - Arrastar handler azul → pupila move
# - Arrastar handler verde → íris move
# - Mapa atualiza em tempo real ✨
```

---

## 📊 Resultados Esperados

✅ **16 handlers** (8 azuis + 8 verdes)  
✅ **Posições fixas** (0°, 45°, 90°, 135°, 180°, 225°, 270°, 315°)  
✅ **Mapa atualiza** durante arrasto (< 50ms)  
✅ **Elipses** funcionam (não só círculos)  
✅ **Performance** fluida (> 30 FPS)

---

## 🚨 Se Algo Falhar

### Mapa não atualiza?
```csharp
// Adicionar log em Handler_MouseMove
_logger.LogDebug("Elipse pupila: {Center}, {Raio}", elipsePupila.Center, elipsePupila.RadiusX);
```

### Handlers não aparecem?
```csharp
// Verificar no ViewModel
_logger.LogInformation("Handlers inicializados: Pupila={0}, Íris={1}", 
    HandlersPupila.Count, HandlersIris.Count);
```

### Build falha?
- Verificar que `using BioDesk.Services;` existe no code-behind
- Verificar que `IridologyTransform.FromHandlers` é acessível (método public static)

---

## 📝 Ficheiros Chave

| Ficheiro | Mudança |
|----------|---------|
| `IridologyTransform.cs` | +70 linhas (FromHandlers) |
| `IrisdiagnosticoViewModel.cs` | Handlers 12→8, ~400 linhas a remover |
| `IrisdiagnosticoUserControl.xaml.cs` | Handler_MouseMove simplificado |
| `IrisdiagnosticoUserControl.xaml` | ~200 linhas a remover (botões) |

---

**Data**: 27 Out 2025  
**Status**: Fase 1 ✅, Fase 2-3 🔄  
**Guia Completo**: `REFATORACAO_IRIS_GUIA_COMPLETO.md`
