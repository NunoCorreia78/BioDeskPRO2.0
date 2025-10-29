# 🗑️ BLOCOS PARA APAGAR MANUALMENTE - Sistema Infalível Overlay
**Data:** 29 de outubro de 2025
**Ficheiro:** `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs`
**Total Estimado:** ~1800 linhas a apagar

---

## 📋 INSTRUÇÕES

1. **FAZER BACKUP PRIMEIRO**: `git add -A && git commit -m "Backup antes de apagar código antigo"`
2. **Apagar blocos PELA ORDEM INVERSA** (de baixo para cima) para não descordenar números de linha
3. **Verificar build** após cada secção grande apagada: `dotnet build`
4. **NÃO apagar** nada marcado como `⚠️ MANTER` (código ainda em uso)

---

## 🔴 BLOCO 1: Classe CalibrationHandler (Linhas ~177-194)

**Apagar TODA a classe inner**:

```csharp
// Linha 177 até ~194
public partial class CalibrationHandler : ObservableObject
{
    [ObservableProperty]
    private double _x;

    [ObservableProperty]
    private double _y;

    [ObservableProperty]
    private int _index;

    [ObservableProperty]
    private bool _isEditable = true;

    [ObservableProperty]
    private string _cor = "#FF0000";
}
```

**Total:** ~18 linhas

---

## 🔴 BLOCO 2: Propriedades de Calibração - FASE 5 (Linhas 148-310)

### 2A: Modos de Calibração (Linhas 148-175)
```csharp
[ObservableProperty]
private bool _modoCalibracaoAtivo = false;

[ObservableProperty]
private bool _tipoCalibracaoAmbos = false;

[ObservableProperty]
private bool _tipoCalibracaoPupila = false;

[ObservableProperty]
private bool _tipoCalibracaoIris = false;

[ObservableProperty]
private bool _modoMoverMapa = false;

[ObservableProperty]
private bool _mostrarBotaoResetCalibracao = false;

[ObservableProperty]
private bool _mostrarBotoesZoomMapa = true;

[ObservableProperty]
private bool _mostrarBotoesMovimentacaoMapa = true;
```

### 2B: Handlers Collections (Linhas 196-220)
```csharp
[ObservableProperty]
private ObservableCollection<CalibrationHandler> _handlersPupila = new();

[ObservableProperty]
private ObservableCollection<CalibrationHandler> _handlersIris = new();

[ObservableProperty]
private int _quantidadeHandlersIris = 12;

[ObservableProperty]
private int _quantidadeHandlersPupila = 12;

[ObservableProperty]
private double _escalaHandler = 16.0;
```

### 2C: Centro e Raio Pupila (Linhas 234-254)
```csharp
[ObservableProperty]
private double _centroPupilaX = 300;

[ObservableProperty]
private double _centroPupilaY = 300;

[ObservableProperty]
private double _raioPupila = 54;

[ObservableProperty]
private double _raioPupilaHorizontal = RAIO_NOMINAL_PUPILA;

[ObservableProperty]
private double _raioPupilaVertical = RAIO_NOMINAL_PUPILA;
```

### 2D: Centro e Raio Íris (Linhas 258-280)
```csharp
[ObservableProperty]
private double _centroIrisX = 300;

[ObservableProperty]
private double _centroIrisY = 300;

[ObservableProperty]
private double _raioIris = 270;

[ObservableProperty]
private double _raioIrisHorizontal = RAIO_NOMINAL_IRIS;

[ObservableProperty]
private double _raioIrisVertical = RAIO_NOMINAL_IRIS;
```

### 2E: Mapa Transformações (Linhas 292-310)
```csharp
[ObservableProperty]
private double _mapaOffsetX = 0;

[ObservableProperty]
private double _mapaOffsetY = 0;

[ObservableProperty]
private double _mapaRotacao = 0;

[ObservableProperty]
private double _mapaZoom = 1.0;
```

**Total Bloco 2:** ~163 linhas

---

## 🔴 BLOCO 3: Event Listeners no Construtor (Linhas ~332-333)

**Apagar dentro do construtor `IrisdiagnosticoViewModel(...)`**:

```csharp
HandlersIris.CollectionChanged += OnHandlersCollectionChanged;
HandlersPupila.CollectionChanged += OnHandlersCollectionChanged;
```

**Total:** 2 linhas

---

## 🔴 BLOCO 4: Comandos de Zoom/Movimento Mapa (Linhas ~699-739)

### 4A: Comando Aumentar Mapa (Linhas ~707-715)
```csharp
[RelayCommand]
private void AumentarMapa()
{
    if (!MostrarMapaIridologico) return;
    AjustarMapaZoom(MapaZoom + MAPA_ZOOM_STEP);
}
```

### 4B: Comando Diminuir Mapa (Linhas ~717-725)
```csharp
[RelayCommand]
private void DiminuirMapa()
{
    if (!MostrarMapaIridologico) return;
    AjustarMapaZoom(MapaZoom - MAPA_ZOOM_STEP);
}
```

### 4C: Comando Reset Mapa (Linhas ~727-739)
```csharp
[RelayCommand]
private void ResetMapa()
{
    if (!MostrarMapaIridologico) return;
    AjustarMapaZoom(1.0);
    MapaOffsetX = 0;
    MapaOffsetY = 0;
    MapaRotacao = 0;
    _logger.LogInformation("↻ Mapa resetado para defaults");
}
```

### 4D: Comandos de Movimentação (Linhas ~741-788)
```csharp
[RelayCommand]
private void MoverMapaCima()
{
    if (!MostrarMapaIridologico) return;
    MapaOffsetY -= MAPA_MOVE_STEP;
}

[RelayCommand]
private void MoverMapaBaixo()
{
    if (!MostrarMapaIridologico) return;
    MapaOffsetY += MAPA_MOVE_STEP;
}

[RelayCommand]
private void MoverMapaEsquerda()
{
    if (!MostrarMapaIridologico) return;
    MapaOffsetX -= MAPA_MOVE_STEP;
}

[RelayCommand]
private void MoverMapaDireita()
{
    if (!MostrarMapaIridologico) return;
    MapaOffsetX += MAPA_MOVE_STEP;
}

[RelayCommand]
private void RotacionarMapaHorario()
{
    if (!MostrarMapaIridologico) return;
    MapaRotacao += MAPA_ROTATE_STEP;
    if (MapaRotacao >= 360) MapaRotacao -= 360;
}

[RelayCommand]
private void RotacionarMapaAntiHorario()
{
    if (!MostrarMapaIridologico) return;
    MapaRotacao -= MAPA_ROTATE_STEP;
    if (MapaRotacao < 0) MapaRotacao += 360;
}
```

### 4E: Comando Reset Calibração (Linhas ~790-808)
```csharp
[RelayCommand]
private void ResetCalibracao()
{
    try
    {
        CentroPupilaX = 300;
        CentroPupilaY = 300;
        RaioPupila = 54;
        CentroIrisX = 300;
        CentroIrisY = 300;
        RaioIris = 270;
        InicializarHandlers();
        _logger.LogInformation("↻ Calibração resetada para defaults");
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao resetar calibração");
    }
}
```

**Total Bloco 4:** ~110 linhas

---

## 🔴 BLOCO 5: Métodos de Serialização (Linhas ~1220-1250)

### 5A: Método SerializarEstadoCalibracaoParaJson (Linhas ~1220-1237)
```csharp
private Dictionary<string, object> SerializarEstadoCalibracaoParaJson()
{
    return new Dictionary<string, object>
    {
        ["centroPupilaX"] = CentroPupilaX,
        ["centroPupilaY"] = CentroPupilaY,
        ["raioPupila"] = RaioPupila,
        ["centroIrisX"] = CentroIrisX,
        ["centroIrisY"] = CentroIrisY,
        ["raioIris"] = RaioIris
    };
}
```

### 5B: Método ObterEstadoCalibracao (Linhas ~1239-1250)
```csharp
public Dictionary<string, string> ObterEstadoCalibracao()
{
    return new Dictionary<string, string>
    {
        ["modoCalibracaoAtivo"] = ModoCalibracaoAtivo.ToString(),
        ["tipoCalibracaoPupila"] = TipoCalibracaoPupila.ToString(),
        ["tipoCalibracaoIris"] = TipoCalibracaoIris.ToString(),
        ["tipoCalibracaoAmbos"] = TipoCalibracaoAmbos.ToString()
    };
}
```

**Total Bloco 5:** ~31 linhas

---

## 🔴 BLOCO 6: Métodos de Calibração GRANDES (Linhas ~1366-1900)

### 6A: Método VerificarSeDeveRecalcularMapa (Linhas ~1366-1380)
```csharp
private bool VerificarSeDeveRecalcularMapa()
{
    if (!MostrarMapaIridologico) return false;
    if (IrisImagemSelecionada == null) return false;
    if (HandlersIris.Count > 0 && HandlersPupila.Count > 0)
    {
        return true;
    }
    return false;
}
```

### 6B: Método InicializarHandlers (Linhas ~1401-1468)
```csharp
public void InicializarHandlers(int? quantidadeIris = null, int? quantidadePupila = null)
{
    try
    {
        if (IrisImagemSelecionada == null)
        {
            _logger.LogWarning("⚠️ Tentativa de inicializar handlers sem imagem selecionada");
            return;
        }

        var totalIris = Math.Max(6, quantidadeIris ?? QuantidadeHandlersIris);
        var totalPupila = Math.Max(6, quantidadePupila ?? QuantidadeHandlersPupila);

        LimparHandlers(HandlersPupila);
        LimparHandlers(HandlersIris);

        CriarHandlers(
            HandlersPupila,
            totalPupila,
            CentroPupilaX,
            CentroPupilaY,
            raioHorizontal: RaioPupilaHorizontal,
            raioVertical: RaioPupilaVertical,
            "#FF4444"
        );
        CriarHandlers(
            HandlersIris,
            totalIris,
            CentroIrisX,
            CentroIrisY,
            raioHorizontal: RaioIrisHorizontal,
            raioVertical: RaioIrisVertical,
            "#4488FF"
        );

        if (QuantidadeHandlersIris != totalIris)
        {
            QuantidadeHandlersIris = totalIris;
        }
        if (QuantidadeHandlersPupila != totalPupila)
        {
            QuantidadeHandlersPupila = totalPupila;
        }

        _logger.LogInformation(
            "✅ Handlers inicializados: Pupila={PupilaCount}, Íris={IrisCount}",
            HandlersPupila.Count,
            HandlersIris.Count,
            totalPupila,
            totalIris
        );
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao inicializar handlers");
    }
}
```

### 6C: Partial Methods OnQuantidadeHandlers (Linhas ~1470-1525)
```csharp
partial void OnQuantidadeHandlersIrisChanged(int value)
{
    try
    {
        if (value < 6 || value > 24)
        {
            _logger.LogWarning(
                "⚠️ Quantidade de handlers íris fora do intervalo permitido: {Value}. Ajustando para 12.",
                value
            );
            var clamped = Math.Clamp(value, 6, 24);
            if (clamped != value)
            {
                QuantidadeHandlersIris = clamped;
            }
            return;
        }
        _logger.LogDebug("🔄 Quantidade handlers íris alterada para {Value}", value);
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao alterar quantidade de handlers íris");
    }
}

partial void OnQuantidadeHandlersPupilaChanged(int value)
{
    try
    {
        if (value < 6 || value > 24)
        {
            _logger.LogWarning(
                "⚠️ Quantidade de handlers pupila fora do intervalo permitido: {Value}. Ajustando para 12.",
                value
            );
            var clamped = Math.Clamp(value, 6, 24);
            if (clamped != value)
            {
                QuantidadeHandlersPupila = clamped;
            }
            return;
        }
        _logger.LogDebug("🔄 Quantidade handlers pupila alterada para {Value}", value);
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao alterar quantidade de handlers pupila");
    }
}
```

### 6D: Método CriarHandlers (Linhas ~1527-1575)
```csharp
private void CriarHandlers(
    ObservableCollection<CalibrationHandler> destino,
    int quantidade,
    double centroX,
    double centroY,
    double raioHorizontal,
    double raioVertical,
    string cor
)
{
    destino.Clear();
    double angleStep = 360.0 / quantidade;
    for (int i = 0; i < quantidade; i++)
    {
        double angleDeg = i * angleStep;
        double angleRad = angleDeg * Math.PI / 180.0;
        double x = centroX + raioHorizontal * Math.Cos(angleRad);
        double y = centroY + raioVertical * Math.Sin(angleRad);
        x = Math.Round(x - 8, 2);
        y = Math.Round(y - 8, 2);

        destino.Add(new CalibrationHandler
        {
            X = x,
            Y = y,
            Index = i,
            Cor = cor,
            IsEditable = true
        });
    }
}
```

### 6E: Método LimparHandlers (Linhas ~1577-1589)
```csharp
private void LimparHandlers(ObservableCollection<CalibrationHandler> handlers)
{
    foreach (var handler in handlers)
    {
        handler.PropertyChanged -= OnHandlerPropertyChanged;
    }
    handlers.Clear();
}
```

### 6F: Método OnHandlersCollectionChanged (Linhas ~1591-1625)
```csharp
private void OnHandlersCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
{
    if (e.Action == NotifyCollectionChangedAction.Add && e.NewItems != null)
    {
        foreach (CalibrationHandler handler in e.OldItems)
        {
            handler.PropertyChanged -= OnHandlerPropertyChanged;
        }
    }
    if (e.Action == NotifyCollectionChangedAction.Add && e.NewItems != null)
    {
        foreach (CalibrationHandler handler in e.NewItems)
        {
            handler.PropertyChanged += OnHandlerPropertyChanged;
        }
    }
    if (e.Action == NotifyCollectionChangedAction.Reset && sender is IEnumerable<CalibrationHandler> handlers)
    {
        foreach (var handler in handlers)
        {
            handler.PropertyChanged += OnHandlerPropertyChanged;
        }
    }
}
```

### 6G: Método OnHandlerPropertyChanged (Linhas ~1627-1649)
```csharp
private void OnHandlerPropertyChanged(object? sender, PropertyChangedEventArgs e)
{
    if (sender is not CalibrationHandler handler)
    {
        return;
    }
    if (e.PropertyName is nameof(CalibrationHandler.X) or nameof(CalibrationHandler.Y))
    {
        RecalcularParametrosPelosHandlers();
    }
}
```

### 6H: Método RecalcularParametrosPelosHandlers (Linhas ~1651-1700)
```csharp
private void RecalcularParametrosPelosHandlers()
{
    try
    {
        if (IrisImagemSelecionada == null)
        {
            return;
        }
        else if (ModoCalibracaoAtivo && !ModoMoverMapa)
        {
            if (TipoCalibracaoIris || TipoCalibracaoAmbos)
            {
                RecalcularCentroEraioIrisPelosHandlers();
            }
            if (TipoCalibracaoPupila || TipoCalibracaoAmbos)
            {
                RecalcularCentroEraioNormalPelosHandlers();
            }
            RecalcularPoligonosComDeformacao();
        }
        else
        {
            TransladarCalibracao();
        }
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao recalcular parâmetros pelos handlers");
    }
}
```

### 6I: Método RecalcularCentroEraioIrisPelosHandlers (Linhas ~1702-1755)
```csharp
private void RecalcularCentroEraioIrisPelosHandlers()
{
    if (HandlersIris.Count == 0)
    {
        CentroIrisX = 300;
        CentroIrisY = 300;
        RaioIrisHorizontal = RAIO_NOMINAL_IRIS;
        RaioIrisVertical = RAIO_NOMINAL_IRIS;
        RaioIris = RAIO_NOMINAL_IRIS;
        return;
    }

    var pontos = HandlersIris.Select(h => (X: h.X + 8, Y: h.Y + 8)).ToList();
    var (centroX, centroY) = CalcularCentro(pontos);
    double raioHorizontal = CalcularRaioMedio(pontos, centroX, centroY, eixoHorizontal: true);
    double raioVertical = CalcularRaioMedio(pontos, centroX, centroY, eixoHorizontal: false);
    raioHorizontal = Math.Max(raioHorizontal, 50);
    raioVertical = Math.Max(raioVertical, 50);
    centroX = Math.Round(centroX, 2);
    centroY = Math.Round(centroY, 2);
    raioHorizontal = Math.Round(raioHorizontal, 2);
    raioVertical = Math.Round(raioVertical, 2);

    _logger.LogDebug($"🟢 [ÍRIS] Centro calculado: ({centroX:F2}, {centroY:F2}) - Anterior: ({CentroIrisX:F2}, {CentroIrisY:F2})");

    CentroIrisX = centroX;
    CentroIrisY = centroY;
    RaioIrisHorizontal = raioHorizontal;
    RaioIrisVertical = raioVertical;
    RaioIris = (raioHorizontal + raioVertical) / 2.0;

    _logger.LogDebug(
        "🟢 [ÍRIS] Recalculado: Centro=({CentroX:F2}, {CentroY:F2}), Raios=({H:F2}, {V:F2})",
        CentroIrisX,
        CentroIrisY,
        raioHorizontal,
        raioVertical
    );
}
```

### 6J: Método RecalcularCentroEraioNormalPelosHandlers (Linhas ~1757-1800)
```csharp
private void RecalcularCentroEraioNormalPelosHandlers()
{
    if (HandlersPupila.Count == 0)
    {
        CentroPupilaX = 300;
        CentroPupilaY = 300;
        RaioPupilaHorizontal = RAIO_NOMINAL_PUPILA;
        RaioPupilaVertical = RAIO_NOMINAL_PUPILA;
        RaioPupila = RAIO_NOMINAL_PUPILA;
        return;
    }

    var pontos = HandlersPupila.Select(h => (X: h.X + 8, Y: h.Y + 8)).ToList();
    var (centroX, centroY) = CalcularCentro(pontos);
    double raioHorizontal = CalcularRaioMedio(pontos, centroX, centroY, eixoHorizontal: true);
    double raioVertical = CalcularRaioMedio(pontos, centroX, centroY, eixoHorizontal: false);
    raioHorizontal = Math.Max(raioHorizontal, 10);
    raioVertical = Math.Max(raioVertical, 10);
    centroX = Math.Round(centroX, 2);
    centroY = Math.Round(centroY, 2);
    raioHorizontal = Math.Round(raioHorizontal, 2);
    raioVertical = Math.Round(raioVertical, 2);

    _logger.LogDebug($"🔵 [PUPILA] Centro calculado: ({centroX:F2}, {centroY:F2}) - Anterior: ({CentroPupilaX:F2}, {CentroPupilaY:F2})");

    CentroPupilaX = centroX;
    CentroPupilaY = centroY;
    RaioPupilaHorizontal = raioHorizontal;
    RaioPupilaVertical = raioVertical;
    RaioPupila = (raioHorizontal + raioVertical) / 2.0;

    _logger.LogDebug(
        "🔵 [PUPILA] Recalculado: Centro=({CentroX:F2}, {CentroY:F2}), Raios=({H:F2}, {V:F2})",
        CentroPupilaX,
        CentroPupilaY,
        raioHorizontal,
        raioVertical
    );
}
```

### 6K: Método ResetCalibracaoInterna (Linhas ~1802-1826)
```csharp
private void ResetCalibracaoInterna()
{
    CentroPupilaX = 300;
    CentroPupilaY = 300;
    RaioPupila = 54;
    RaioPupilaHorizontal = RAIO_NOMINAL_PUPILA;
    RaioPupilaVertical = RAIO_NOMINAL_PUPILA;

    CentroIrisX = 300;
    CentroIrisY = 300;
    RaioIris = 270;
    RaioIrisHorizontal = RAIO_NOMINAL_IRIS;
    RaioIrisVertical = RAIO_NOMINAL_IRIS;

    MapaOffsetX = 0;
    MapaOffsetY = 0;
    MapaRotacao = 0;
    MapaZoom = 1.0;

    _logger.LogInformation("↻ Calibração interna resetada para valores nominais");
}
```

### 6L: Método TransladarCalibracao (Linhas ~1828-1900)
**⚠️ MUITO GRANDE - Procurar por `private void TransladarCalibracao()` e apagar TODO o método até o próximo método**

```csharp
private void TransladarCalibracao()
{
    // ... ~70 linhas de lógica de translação ...
}
```

**Total Bloco 6:** ~535 linhas

---

## 🔴 BLOCO 7: Métodos Auxiliares de Geometria (Linhas ~1902-2050)

### 7A: Método CalcularCentro (Linhas ~1902-1920)
```csharp
private (double centroX, double centroY) CalcularCentro(List<(double X, double Y)> pontos)
{
    if (pontos.Count == 0)
    {
        return (300, 300);
    }
    double somaX = 0;
    double somaY = 0;
    foreach (var ponto in pontos)
    {
        somaX += ponto.X;
        somaY += ponto.Y;
    }
    double centroX = somaX / pontos.Count;
    double centroY = somaY / pontos.Count;
    return (centroX, centroY);
}
```

### 7B: Método CalcularRaioMedio (Linhas ~1922-1960)
```csharp
private double CalcularRaioMedio(
    List<(double X, double Y)> pontos,
    double centroX,
    double centroY,
    bool eixoHorizontal
)
{
    // ... lógica de cálculo de raio ...
}
```

### 7C: Método RecalcularPoligonosComDeformacao (Linhas ~1962-2050)
**⚠️ MUITO GRANDE - Procurar e apagar TODO o método**

```csharp
private void RecalcularPoligonosComDeformacao()
{
    // ... ~90 linhas de lógica de polígonos deformados ...
}
```

**Total Bloco 7:** ~148 linhas

---

## 🔴 BLOCO 8: Métodos de Drag (BeginDrag, EndDrag) (Linhas ~2052-2120)

### 8A: Método BeginDrag (Linhas ~2052-2080)
```csharp
public void BeginDrag()
{
    if (IrisImagemSelecionada == null)
    {
        _logger.LogWarning("⚠️ Tentativa de BeginDrag sem imagem selecionada");
        return;
    }

    _dragDebugService.BeginDrag(
        ModoMoverMapa ? "MoverMapa" : "Calibração",
        CentroPupilaX,
        CentroPupilaY,
        CentroIrisX,
        CentroIrisY,
        new { ModoMoverMapa, ModoCalibracaoAtivo }
    );

    _estadoAntesDrag = new Dictionary<string, object>(SerializarEstadoCalibracaoParaJson());

    _logger.LogDebug("🚩 BeginDrag: Estado salvo");
}
```

### 8B: Método EndDrag (Linhas ~2082-2120)
```csharp
public void EndDrag()
{
    if (_estadoAntesDrag == null)
    {
        _logger.LogWarning("⚠️ EndDrag chamado sem BeginDrag prévio");
        return;
    }

    _dragDebugService.EndDrag(
        CentroPupilaX,
        CentroPupilaY,
        CentroIrisX,
        CentroIrisY
    );

    var mudancas = new Dictionary<string, (object Antes, object Depois)>();
    var estadoDepois = SerializarEstadoCalibracaoParaJson();

    foreach (var (chave, valorAntes) in _estadoAntesDrag)
    {
        if (estadoDepois.TryGetValue(chave, out var valorDepois))
        {
            if (!Equals(valorAntes, valorDepois))
            {
                mudancas[chave] = (valorAntes, valorDepois);
            }
        }
    }

    _logger.LogDebug("🏁 EndDrag: {MudancasCount} mudanças detectadas", mudancas.Count);
    _estadoAntesDrag = null;
}
```

**Total Bloco 8:** ~68 linhas

---

## 🔴 BLOCO 9: Método AjustarMapaZoom (Linhas ~2122-2180)

```csharp
private void AjustarMapaZoom(double novoZoom)
{
    try
    {
        const double MIN_ZOOM = 0.5;
        const double MAX_ZOOM = 3.0;
        novoZoom = Math.Clamp(novoZoom, MIN_ZOOM, MAX_ZOOM);

        if (Math.Abs(MapaZoom - novoZoom) < 0.001)
        {
            return;
        }

        MapaZoom = novoZoom;
        RecalcularPoligonosComDeformacao();

        _logger.LogDebug("🔍 Zoom do mapa ajustado para {Zoom:F2}x", MapaZoom);
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao ajustar zoom do mapa");
    }
}
```

**Total:** ~58 linhas

---

## ⚠️ BLOCO 10: Code-Behind - IrisdiagnosticoUserControl.xaml.cs

**Ficheiro:** `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs`

### 10A: Remover blocos `#if false ... #endif` (Linhas ~260-545)

**Apagar todos os blocos:**

1. **Handler_MouseMove** (linhas ~260-265)
2. **MapaOverlayCanvas_MouseLeftButtonDown** (linhas ~348-393)
3. **MapaOverlayCanvas_MouseMove** (linhas ~399-473)
4. **MapaOverlayCanvas_MouseLeftButtonUp** (linhas ~477-507)
5. **GetMapaPositionRelativeToHandlers** (linhas ~509-544)

**Total:** ~285 linhas

---

## 📊 RESUMO FINAL

| Bloco | Descrição | Linhas Aprox. | Ficheiro |
|-------|-----------|---------------|----------|
| 1 | Classe CalibrationHandler | 18 | ViewModel |
| 2 | Propriedades FASE 5 | 163 | ViewModel |
| 3 | Event Listeners | 2 | ViewModel |
| 4 | Comandos Zoom/Movimento | 110 | ViewModel |
| 5 | Serialização | 31 | ViewModel |
| 6 | Métodos Calibração GRANDES | 535 | ViewModel |
| 7 | Métodos Geometria | 148 | ViewModel |
| 8 | BeginDrag/EndDrag | 68 | ViewModel |
| 9 | AjustarMapaZoom | 58 | ViewModel |
| 10 | Code-behind #if false | 285 | UserControl.xaml.cs |
| **TOTAL** | | **~1418 linhas** | |

---

## ✅ CHECKLIST APÓS APAGAR

1. [ ] Apagar Bloco 10 (code-behind) - ⚡ Fazer PRIMEIRO
2. [ ] Apagar Bloco 9 (AjustarMapaZoom)
3. [ ] Apagar Bloco 8 (BeginDrag/EndDrag)
4. [ ] Apagar Bloco 7 (Métodos Geometria)
5. [ ] Apagar Bloco 6 (Métodos Calibração)
6. [ ] Apagar Bloco 5 (Serialização)
7. [ ] Apagar Bloco 4 (Comandos)
8. [ ] Apagar Bloco 3 (Event Listeners no construtor)
9. [ ] Apagar Bloco 2 (Propriedades)
10. [ ] Apagar Bloco 1 (Classe CalibrationHandler)
11. [ ] **Build Final:** `dotnet clean && dotnet build`
12. [ ] **Commit:** `git add -A && git commit -m "Sistema Infalível: Código antigo removido (1418 linhas)"`
13. [ ] **Testar App:** `dotnet run --project src/BioDesk.App`

---

## 🎯 OBJETIVO FINAL

Após remoção:
- ✅ Apenas **Sistema Infalível** (3-click + OpenCV) permanece
- ✅ ~1418 linhas de código antigo removidas
- ✅ 0 referências a HandlersPupila, HandlersIris, CalibrationHandler
- ✅ Build succeeded sem warnings
- ✅ App executa normalmente

---

**BOM TRABALHO! 🚀**
