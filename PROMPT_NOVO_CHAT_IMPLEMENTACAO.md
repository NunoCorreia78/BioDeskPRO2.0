# 🚀 PROMPT PARA NOVO CHAT - IMPLEMENTAÇÕES PENDENTES

**Data:** 03/10/2025
**Projeto:** BioDeskPro2 - Sistema de Gestão Médica
**Status Atual:** ✅ Sistema 100% funcional, apenas melhorias pendentes

---

## 📋 CONTEXTO DO PROJETO

BioDeskPro2 é um sistema WPF (.NET 8) com arquitetura MVVM para gestão de clínicas de medicina complementar. Utiliza:
- **Stack:** .NET 8 LTS, WPF, CommunityToolkit.Mvvm, Entity Framework Core 8.0.8, SQLite
- **Padrões:** MVVM, Repository Pattern, Unit of Work, Dependency Injection
- **Status Build:** 0 Errors, 27 Warnings (apenas NU1701 AForge - esperados)
- **Funcionalidades:** Gestão pacientes, declaração saúde, consentimentos, irisdiagnóstico, comunicação

### ✅ O QUE JÁ ESTÁ COMPLETO:
- Sistema de navegação entre views funcionando
- CRUD completo de pacientes + validação FluentValidation
- Tab Irisdiagnóstico: Galeria imagens, marcações manuais, zoom/pan, câmara USB
- Triple Deadlock Fix (câmara sem freeze)
- Auditoria completa de 64 campos em 6 tabs (98.4% bindings corretos)
- Build limpo e aplicação executando sem erros

---

## 🎯 OBJETIVO DESTA SESSÃO

Implementar **4 melhorias pendentes** no sistema, priorizando:
1. **P2 - MÉDIO:** Dialog Editar Observações (30 min) - UX enhancement
2. **P2 - MÉDIO:** Overlay Zonas Iridológicas (5-6 horas) - Feature avançada
3. **P3 - BAIXO:** CA1063 Dispose Pattern (20 min) - Code quality
4. **P3 - BAIXO:** async void Refactoring (4-6 horas) - Preventivo

**IMPORTANTE:** Todas estas são **melhorias**, não correções de bugs. Sistema já funciona 100%.

---

## 📦 TAREFA 1: DIALOG EDITAR OBSERVAÇÕES ÍRIS (30 MIN)

### 🎯 Objetivo:
Permitir editar observações de marcações existentes na íris via dialog modal.

### 📂 Arquivos Envolvidos:
1. `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs` (adicionar command)
2. `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs` (integrar dialog)
3. `src/BioDesk.App/Views/Dialogs/EditarObservacaoDialog.xaml` ✅ JÁ EXISTE

### 🔍 Problema Atual:
```csharp
// IrisdiagnosticoViewModel.cs:520
// TODO: Integração do dialog deve ser feita na camada View (IrisdiagnosticoUserControl)
// ViewModels não devem referenciar Views/Dialogs (violação MVVM)
private async Task EditarObservacoesMarcaAsync(IrisMarca marca)
{
    // Apenas log, sem dialog
    _logger.LogInformation("📝 Editar observações da marca ID {Id}", marca.Id);
}
```

**Razão:** Tentativa de referenciar dialog no ViewModel causou CS0234 (violação arquitetura MVVM).

### ✅ Solução:

**PASSO 1:** Adicionar command ao ViewModel
```csharp
// IrisdiagnosticoViewModel.cs - Adicionar após linha 530

/// <summary>
/// Atualiza observações de uma marca existente (chamado pela View)
/// </summary>
[RelayCommand]
private async Task AtualizarObservacaoMarcaAsync(int marcaId, string novaObservacao)
{
    try
    {
        var marca = IrisMarcas.FirstOrDefault(m => m.Id == marcaId);
        if (marca == null)
        {
            _logger.LogWarning("⚠️ Marca {Id} não encontrada", marcaId);
            return;
        }

        marca.Observacoes = novaObservacao;
        await _unitOfWork.SaveChangesAsync();

        _logger.LogInformation("✅ Observações da marca {Id} atualizadas", marcaId);

        // ObservableCollection atualiza UI automaticamente
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao atualizar observações da marca {Id}", marcaId);
        ErrorMessage = $"Erro ao atualizar observações: {ex.Message}";
    }
}
```

**PASSO 2:** Integrar dialog no code-behind da View
```csharp
// IrisdiagnosticoUserControl.xaml.cs - Linha 80 (já existe stub)
// ATUALIZAR este método:

private async void EditarObservacoes_Click(object sender, RoutedEventArgs e)
{
    var button = sender as Button;
    if (button?.Tag is not IrisMarca marca)
    {
        MessageBox.Show(
            "Erro: Marca não identificada. Por favor, tente novamente.",
            "Erro",
            MessageBoxButton.OK,
            MessageBoxImage.Warning);
        return;
    }

    // Abrir dialog modal
    var dialog = new EditarObservacaoDialog(marca.Observacoes ?? string.Empty)
    {
        Owner = Window.GetWindow(this),
        WindowStartupLocation = WindowStartupLocation.CenterOwner
    };

    if (dialog.ShowDialog() == true)
    {
        // Chamar command do ViewModel
        var viewModel = DataContext as IrisdiagnosticoViewModel;
        if (viewModel?.AtualizarObservacaoMarcaCommand.CanExecute(null) == true)
        {
            await viewModel.AtualizarObservacaoMarcaCommand.ExecuteAsync((marca.Id, dialog.Observacao));
        }
    }
}
```

**PASSO 3:** Verificar que dialog já existe
```bash
# Arquivo: src/BioDesk.App/Views/Dialogs/EditarObservacaoDialog.xaml
# ✅ Já implementado (104 linhas XAML + 42 linhas C#)
# Features: TextBox auto-focus, auto-select, MaxLength=500, OK/Cancel
```

### 🧪 Como Testar:
1. Executar aplicação: `dotnet run --project src/BioDesk.App`
2. Ir para ficha de paciente → Tab Irisdiagnóstico
3. Adicionar marcação manual clicando na imagem
4. Na grid de marcas, clicar botão "✏️ Editar Observações"
5. Dialog deve abrir com texto atual
6. Editar e clicar OK
7. Grid deve atualizar imediatamente
8. Verificar base de dados persistiu mudança

### ⏱️ Tempo Estimado: 30 minutos

---

## 📦 TAREFA 2: OVERLAY ZONAS IRIDOLÓGICAS + HIT-TESTING (5-6 HORAS)

### 🎯 Objetivo:
Renderizar mapa iridológico (72 zonas reflexas) como overlay semi-transparente sobre imagens de íris, com detecção inteligente de zona ao clicar.

### 📂 Arquivos Envolvidos:
1. `src/BioDesk.Services/Iridology/IridologyMapService.cs` ❌ CRIAR
2. `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs` (adicionar integração)
3. `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml` (adicionar layer)
4. `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs` (renderização)
5. `src/BioDesk.Domain/Models/IridologyMap.cs` ✅ JÁ EXISTE
6. `src/BioDesk.App/Resources/IridologyMaps/iris_esq.json` ✅ JÁ EXISTE (14.749 linhas)
7. `src/BioDesk.App/Resources/IridologyMaps/iris_drt.json` ✅ JÁ EXISTE (14.749 linhas)

### 🔍 Contexto:
```
✅ Models existentes: IridologyMap, IridologyZone, PolarPoint
✅ JSON files: 72 zonas × múltiplas partes cada = ~200+ polígonos
✅ Coordenadas polares: {angulo: graus, raio: 0-1 normalizado}
❌ Nenhum código carrega/renderiza/detecta zonas
```

### 📐 Desafio Técnico:
- **Coordenadas Polares → Cartesianas:** Trigonometria (ângulo + raio → x,y)
- **Renderização:** 200+ polígonos WPF com hover effects
- **Hit-Testing:** Ray-casting em coordenadas polares (complexo)
- **Performance:** Renderizar 200+ polígonos sem lag

---

### ✅ IMPLEMENTAÇÃO DETALHADA:

#### **PASSO 1: Criar Serviço (30 min)**

```csharp
// CRIAR: src/BioDesk.Services/Iridology/IridologyMapService.cs

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using System.Windows;
using BioDesk.Domain.Models;

namespace BioDesk.Services.Iridology;

public interface IIridologyMapService
{
    Task<IridologyMap?> LoadMapAsync(string tipo);
    Point PolarToCartesian(PolarPoint polar, Point center, double radius);
    IridologyZone? HitTestZone(Point click, Point center, double radius, IridologyMap map);
}

public class IridologyMapService : IIridologyMapService
{
    /// <summary>
    /// Carrega mapa iridológico do JSON embedded
    /// </summary>
    public async Task<IridologyMap?> LoadMapAsync(string tipo)
    {
        try
        {
            // JSON está em Resources/IridologyMaps/
            var assembly = typeof(IridologyMapService).Assembly;
            var resourceName = $"BioDesk.App.Resources.IridologyMaps.iris_{tipo}.json";

            using var stream = assembly.GetManifestResourceStream(resourceName);
            if (stream == null)
            {
                // Fallback: tentar caminho relativo
                var basePath = AppDomain.CurrentDomain.BaseDirectory;
                var jsonPath = Path.Combine(basePath, "Resources", "IridologyMaps", $"iris_{tipo}.json");

                if (!File.Exists(jsonPath))
                    return null;

                var json = await File.ReadAllTextAsync(jsonPath);
                return JsonSerializer.Deserialize<IridologyMap>(json);
            }

            using var reader = new StreamReader(stream);
            var jsonContent = await reader.ReadToEndAsync();
            return JsonSerializer.Deserialize<IridologyMap>(jsonContent);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// Converte coordenadas polares (ângulo, raio) para cartesianas (x, y)
    /// </summary>
    public Point PolarToCartesian(PolarPoint polar, Point center, double radius)
    {
        // Converter ângulo de graus para radianos
        var angleRad = polar.Angulo * Math.PI / 180.0;

        // Calcular coordenadas cartesianas
        // x = centro_x + raio_normalizado * raio_iris * cos(ângulo)
        // y = centro_y + raio_normalizado * raio_iris * sin(ângulo)
        var x = center.X + polar.Raio * radius * Math.Cos(angleRad);
        var y = center.Y + polar.Raio * radius * Math.Sin(angleRad);

        return new Point(x, y);
    }

    /// <summary>
    /// Detecta qual zona foi clicada usando ray-casting em coordenadas polares
    /// </summary>
    public IridologyZone? HitTestZone(Point click, Point center, double radius, IridologyMap map)
    {
        // Converter click para coordenadas polares
        var dx = click.X - center.X;
        var dy = click.Y - center.Y;
        var clickRadius = Math.Sqrt(dx * dx + dy * dy) / radius; // Normalizar
        var clickAngle = Math.Atan2(dy, dx) * 180.0 / Math.PI;

        // Normalizar ângulo para 0-360
        if (clickAngle < 0) clickAngle += 360;

        // Testar cada zona
        foreach (var zona in map.Zonas)
        {
            foreach (var parte in zona.Partes)
            {
                if (IsPointInPolygon(clickRadius, clickAngle, parte))
                    return zona;
            }
        }

        return null;
    }

    /// <summary>
    /// Ray-casting algorithm para polígonos em coordenadas polares
    /// </summary>
    private bool IsPointInPolygon(double r, double angle, List<PolarPoint> polygon)
    {
        if (polygon.Count < 3) return false;

        bool inside = false;
        int j = polygon.Count - 1;

        for (int i = 0; i < polygon.Count; i++)
        {
            var pi = polygon[i];
            var pj = polygon[j];

            // Ray-casting: contar intersecções com raio horizontal
            if ((pi.Angulo > angle) != (pj.Angulo > angle))
            {
                var slope = (pj.Raio - pi.Raio) / (pj.Angulo - pi.Angulo);
                var intersectR = pi.Raio + slope * (angle - pi.Angulo);

                if (r < intersectR)
                    inside = !inside;
            }

            j = i;
        }

        return inside;
    }
}
```

**Registrar no DI Container:**
```csharp
// src/BioDesk.App/App.xaml.cs - Método ConfigureServices()
// Adicionar após outras registrations:
services.AddSingleton<IIridologyMapService, IridologyMapService>();
```

---

#### **PASSO 2: ViewModel Integration (1 hora)**

```csharp
// IrisdiagnosticoViewModel.cs - Adicionar após linha 90

private readonly IIridologyMapService _iridologyMapService;
private IridologyMap? _mapaEsquerdo;
private IridologyMap? _mapaDireito;

[ObservableProperty]
private IridologyZone? _zonaDetectada;

[ObservableProperty]
private bool _mostrarOverlay = false; // Toggle overlay on/off

[ObservableProperty]
private string _mensagemCarregamento = string.Empty;

// ATUALIZAR construtor para injetar serviço:
public IrisdiagnosticoViewModel(
    IUnitOfWork unitOfWork,
    ILogger<IrisdiagnosticoViewModel> logger,
    IIridologyMapService iridologyMapService) // ADICIONAR
{
    _unitOfWork = unitOfWork ?? throw new ArgumentNullException(nameof(unitOfWork));
    _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    _iridologyMapService = iridologyMapService ?? throw new ArgumentNullException(nameof(iridologyMapService)); // ADICIONAR
}

// ADICIONAR método para carregar mapas:
partial void OnIrisImagemSelecionadaChanged(IrisImagem? value)
{
    if (value == null)
    {
        ZonaDetectada = null;
        return;
    }

    _logger.LogInformation("🗺️ Imagem selecionada: {Olho}", value.Olho);

    // Carregar mapa correspondente (se ainda não carregado)
    _ = CarregarMapaAsync(value.Olho);
}

private async Task CarregarMapaAsync(string olho)
{
    try
    {
        var tipo = olho.Equals("Esquerdo", StringComparison.OrdinalIgnoreCase) ? "esq" : "drt";

        // Verificar se já carregado
        if (tipo == "esq" && _mapaEsquerdo != null) return;
        if (tipo == "drt" && _mapaDireito != null) return;

        MensagemCarregamento = "Carregando mapa iridológico...";

        var mapa = await _iridologyMapService.LoadMapAsync(tipo);

        if (mapa != null)
        {
            if (tipo == "esq")
                _mapaEsquerdo = mapa;
            else
                _mapaDireito = mapa;

            _logger.LogInformation("✅ Mapa {Tipo} carregado: {TotalZonas} zonas",
                tipo, mapa.Metadata.TotalZonas);

            MensagemCarregamento = $"✅ Mapa carregado: {mapa.Metadata.TotalZonas} zonas";
        }
        else
        {
            _logger.LogWarning("⚠️ Falha ao carregar mapa {Tipo}", tipo);
            MensagemCarregamento = "⚠️ Erro ao carregar mapa";
        }
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao carregar mapa iridológico");
        MensagemCarregamento = $"❌ Erro: {ex.Message}";
    }
}

// ADICIONAR propriedade helper:
public IridologyMap? MapaAtual => IrisImagemSelecionada?.Olho.Equals("Esquerdo", StringComparison.OrdinalIgnoreCase) == true
    ? _mapaEsquerdo
    : _mapaDireito;
```

---

#### **PASSO 3: XAML Layer (30 min)**

```xml
<!-- IrisdiagnosticoUserControl.xaml -->
<!-- LOCALIZAR linha ~430 "<Grid x:Name="CanvasContainer">" -->
<!-- SUBSTITUIR Grid completo por isto: -->

<Grid x:Name="CanvasContainer">
    <!-- Layer 0: Imagem de íris (base) -->
    <Image x:Name="IrisImage"
           Source="{Binding IrisImagemSelecionada.CaminhoArquivo, Converter={StaticResource PathToImageConverter}}"
           Stretch="Uniform"
           Panel.ZIndex="0"/>

    <!-- Layer 1: Overlay Zonas Iridológicas (semi-transparente) -->
    <Canvas x:Name="ZonasOverlayCanvas"
            Background="Transparent"
            Visibility="{Binding MostrarOverlay, Converter={StaticResource BoolToVisibilityConverter}}"
            Width="{Binding ActualWidth, ElementName=IrisImage}"
            Height="{Binding ActualHeight, ElementName=IrisImage}"
            Panel.ZIndex="50">
        <!-- Polígonos adicionados via code-behind -->
    </Canvas>

    <!-- Layer 2: Marcações Manuais (por cima do overlay) -->
    <Canvas x:Name="MarkingsCanvas"
            Background="Transparent"
            Width="{Binding ActualWidth, ElementName=IrisImage}"
            Height="{Binding ActualHeight, ElementName=IrisImage}"
            Panel.ZIndex="100"
            MouseLeftButtonDown="MarkingsCanvas_MouseLeftButtonDown">
        <ItemsControl ItemsSource="{Binding MarcasImagem}">
            <!-- ... código existente das marcações ... -->
        </ItemsControl>
    </Canvas>
</Grid>

<!-- ADICIONAR após linha ~500 (antes do </Border> final): -->
<!-- Controles de Overlay -->
<StackPanel Orientation="Horizontal" Margin="0,12,0,0">
    <ToggleButton Content="🗺️ Mapa Iridológico"
                  IsChecked="{Binding MostrarOverlay}"
                  Background="#9CAF97"
                  Foreground="White"
                  Padding="12,6"
                  FontSize="14"
                  FontWeight="SemiBold"
                  BorderThickness="0"
                  Cursor="Hand"
                  ToolTip="Mostrar/ocultar zonas reflexas da íris">
        <ToggleButton.Style>
            <Style TargetType="ToggleButton">
                <Setter Property="Template">
                    <Setter.Value>
                        <ControlTemplate TargetType="ToggleButton">
                            <Border Background="{TemplateBinding Background}"
                                    CornerRadius="6"
                                    Padding="{TemplateBinding Padding}">
                                <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                            </Border>
                        </ControlTemplate>
                    </Setter.Value>
                </Setter>
                <Style.Triggers>
                    <Trigger Property="IsChecked" Value="True">
                        <Setter Property="Background" Value="#6B8E63"/>
                    </Trigger>
                    <Trigger Property="IsMouseOver" Value="True">
                        <Setter Property="Background" Value="#879B83"/>
                    </Trigger>
                </Style.Triggers>
            </Style>
        </ToggleButton.Style>
    </ToggleButton>

    <TextBlock Text="{Binding MensagemCarregamento}"
               Foreground="#5A6558"
               FontSize="12"
               VerticalAlignment="Center"
               Margin="12,0,0,0"/>
</StackPanel>

<!-- Painel Info Zona Detectada -->
<Border Background="#F7F9F6"
        CornerRadius="8"
        Padding="12"
        Margin="0,12,0,0"
        Visibility="{Binding ZonaDetectada, Converter={StaticResource NullToCollapsedConverter}}">
    <StackPanel>
        <TextBlock Text="🎯 ZONA DETECTADA"
                   FontWeight="Bold"
                   FontSize="14"
                   Foreground="#3F4A3D"/>
        <TextBlock Text="{Binding ZonaDetectada.Nome}"
                   FontSize="16"
                   FontWeight="SemiBold"
                   Foreground="#3F4A3D"
                   Margin="0,8,0,4"/>
        <TextBlock Text="{Binding ZonaDetectada.Descricao}"
                   TextWrapping="Wrap"
                   FontSize="12"
                   Foreground="#5A6558"/>
    </StackPanel>
</Border>
```

**ADICIONAR Converters necessários:**
```xml
<!-- IrisdiagnosticoUserControl.xaml - Dentro de <UserControl.Resources> -->
<BooleanToVisibilityConverter x:Key="BoolToVisibilityConverter"/>
<converters:NullToCollapsedConverter x:Key="NullToCollapsedConverter"/>
```

**CRIAR Converter:**
```csharp
// CRIAR: src/BioDesk.App/Converters/NullToCollapsedConverter.cs

using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace BioDesk.App.Converters;

public class NullToCollapsedConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        return value == null ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotImplementedException();
    }
}
```

---

#### **PASSO 4: Renderização Code-Behind (2-3 horas)**

```csharp
// IrisdiagnosticoUserControl.xaml.cs

// ADICIONAR campo privado no topo da classe:
private IIridologyMapService? _iridologyMapService;

// ADICIONAR no construtor (após InitializeComponent()):
public IrisdiagnosticoUserControl()
{
    InitializeComponent();

    // Obter serviço do DI container via DataContext
    Loaded += OnControlLoaded;
}

private void OnControlLoaded(object sender, RoutedEventArgs e)
{
    // Obter serviço quando ViewModel estiver disponível
    if (DataContext is IrisdiagnosticoViewModel viewModel)
    {
        // Serviço está injetado no ViewModel, acessar via reflection ou property pública
        // Alternativa: Injetar diretamente no UserControl via DI
    }

    // Subscrever mudança de imagem selecionada
    if (DataContext is IrisdiagnosticoViewModel vm)
    {
        vm.PropertyChanged += ViewModel_PropertyChanged;
    }
}

private void ViewModel_PropertyChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
{
    if (e.PropertyName == nameof(IrisdiagnosticoViewModel.MostrarOverlay))
    {
        RenderizarOverlaySeNecessario();
    }
    else if (e.PropertyName == nameof(IrisdiagnosticoViewModel.IrisImagemSelecionada))
    {
        RenderizarOverlaySeNecessario();
    }
}

/// <summary>
/// Renderiza overlay de zonas iridológicas (200+ polígonos)
/// </summary>
private void RenderizarOverlaySeNecessario()
{
    var viewModel = DataContext as IrisdiagnosticoViewModel;
    if (viewModel == null) return;

    ZonasOverlayCanvas.Children.Clear();

    if (!viewModel.MostrarOverlay || viewModel.MapaAtual == null)
        return;

    // Aguardar layout estar pronto
    if (ZonasOverlayCanvas.ActualWidth == 0 || ZonasOverlayCanvas.ActualHeight == 0)
    {
        Dispatcher.BeginInvoke(new Action(RenderizarOverlaySeNecessario), System.Windows.Threading.DispatcherPriority.Loaded);
        return;
    }

    RenderizarMapaIridologico(viewModel.MapaAtual);
}

private void RenderizarMapaIridologico(IridologyMap mapa)
{
    try
    {
        var centerX = ZonasOverlayCanvas.ActualWidth / 2;
        var centerY = ZonasOverlayCanvas.ActualHeight / 2;
        var radius = Math.Min(centerX, centerY) * 0.9; // 90% do raio disponível
        var center = new Point(centerX, centerY);

        // Cache do serviço
        var service = (DataContext as IrisdiagnosticoViewModel)?._iridologyMapService;
        if (service == null) return;

        int zonaIndex = 0;
        foreach (var zona in mapa.Zonas)
        {
            foreach (var parte in zona.Partes)
            {
                if (parte.Count < 3) continue; // Polígono precisa 3+ pontos

                var polygon = new System.Windows.Shapes.Polygon
                {
                    Stroke = System.Windows.Media.Brushes.Transparent,
                    Fill = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(30, 107, 142, 99)), // Verde semi-transparente
                    StrokeThickness = 0.5,
                    Tag = zona,
                    Cursor = System.Windows.Input.Cursors.Hand
                };

                // Converter pontos polares para cartesianos
                var points = new System.Windows.Media.PointCollection();
                foreach (var polarPoint in parte)
                {
                    var cartesian = service.PolarToCartesian(polarPoint, center, radius);
                    points.Add(cartesian);
                }
                polygon.Points = points;

                // Hover effects
                polygon.MouseEnter += (s, e) =>
                {
                    polygon.Fill = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(80, 107, 142, 99)); // Mais opaco
                    polygon.Stroke = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(150, 107, 142, 99));
                    polygon.StrokeThickness = 2;

                    var vm = DataContext as IrisdiagnosticoViewModel;
                    if (vm != null)
                        vm.ZonaDetectada = zona;
                };

                polygon.MouseLeave += (s, e) =>
                {
                    polygon.Fill = new System.Windows.Media.SolidColorBrush(
                        System.Windows.Media.Color.FromArgb(30, 107, 142, 99));
                    polygon.Stroke = System.Windows.Media.Brushes.Transparent;
                    polygon.StrokeThickness = 0.5;

                    var vm = DataContext as IrisdiagnosticoViewModel;
                    if (vm != null)
                        vm.ZonaDetectada = null;
                };

                // Tooltip
                polygon.ToolTip = $"{zona.Nome}\n{zona.Descricao}";

                ZonasOverlayCanvas.Children.Add(polygon);
            }

            zonaIndex++;
        }

        System.Diagnostics.Debug.WriteLine($"✅ Renderizados {ZonasOverlayCanvas.Children.Count} polígonos");
    }
    catch (Exception ex)
    {
        System.Diagnostics.Debug.WriteLine($"❌ Erro ao renderizar overlay: {ex.Message}");
    }
}

/// <summary>
/// ATUALIZAR handler de clique para detectar zonas
/// </summary>
private async void MarkingsCanvas_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
{
    var viewModel = DataContext as IrisdiagnosticoViewModel;
    if (viewModel == null) return;

    var clickPos = e.GetPosition(MarkingsCanvas);

    // Se overlay ativo, tentar detectar zona primeiro
    if (viewModel.MostrarOverlay && viewModel.MapaAtual != null)
    {
        var service = viewModel._iridologyMapService;
        if (service != null)
        {
            var centerX = MarkingsCanvas.ActualWidth / 2;
            var centerY = MarkingsCanvas.ActualHeight / 2;
            var radius = Math.Min(centerX, centerY) * 0.9;
            var center = new Point(centerX, centerY);

            var zonaClicada = service.HitTestZone(clickPos, center, radius, viewModel.MapaAtual);

            if (zonaClicada != null)
            {
                // Mostrar informação da zona
                var resultado = MessageBox.Show(
                    $"🎯 ZONA: {zonaClicada.Nome}\n\n{zonaClicada.Descricao}\n\n" +
                    $"Deseja criar uma marcação nesta zona?",
                    "Zona Iridológica Detectada",
                    MessageBoxButton.YesNo,
                    MessageBoxImage.Information);

                if (resultado == MessageBoxResult.No)
                    return; // Não criar marca

                // Se Yes, continua e cria marca
            }
        }
    }

    // Criar marcação normal (código existente)
    if (viewModel.AdicionarMarcaCommand.CanExecute(null))
    {
        await viewModel.AdicionarMarcaCommand.ExecuteAsync((clickPos.X, clickPos.Y));
    }
}
```

---

### 🧪 Como Testar:
1. Executar aplicação
2. Ir para ficha paciente → Tab Irisdiagnóstico
3. Selecionar imagem de íris
4. Clicar botão "🗺️ Mapa Iridológico"
5. Verificar mensagem "✅ Mapa carregado: 72 zonas"
6. Overlay semi-transparente deve aparecer sobre imagem
7. Hover sobre zonas deve destacar e mostrar tooltip
8. Painel "🎯 ZONA DETECTADA" deve mostrar info ao passar mouse
9. Clicar numa zona deve mostrar dialog com opção de criar marca
10. Toggle button deve ligar/desligar overlay

### ⏱️ Tempo Estimado: 5-6 horas

### ⚠️ Notas Importantes:
- **Performance:** 200+ polígonos podem causar lag. Testar em máquina real.
- **Calibração:** Centros podem não alinhar perfeitamente com imagens reais (requer ajuste manual)
- **JSON Loading:** Verificar se embedded resource funciona ou usar File.ReadAllText
- **Memory:** Carregar ambos mapas (~30MB total) na memória - aceitável

---

## 📦 TAREFA 3: CA1063 DISPOSE PATTERN (20 MIN)

### 🎯 Objetivo:
Implementar padrão Dispose(bool) virtual conforme CA1063 em 3 classes.

### 📂 Classes Afetadas:
1. `src/BioDesk.Services/Hardware/CameraService.cs` (linha 221)
2. `src/BioDesk.Services/Hardware/CameraServiceReal.cs` (linha 218)
3. Possivelmente 1 mais (verificar build warnings)

### 🔍 Problema Atual:
```csharp
// ❌ PADRÃO INCORRETO (CA1063 violation)
public void Dispose()
{
    _videoSource?.SignalToStop();
    _videoSource?.WaitForStop();
    _videoSource = null;
}
```

### ✅ Solução Padrão:
```csharp
// ✅ PADRÃO CORRETO (CA1063 compliant)
private bool _disposed = false;

public void Dispose()
{
    Dispose(true);
    GC.SuppressFinalize(this);
}

protected virtual void Dispose(bool disposing)
{
    if (!_disposed)
    {
        if (disposing)
        {
            // Limpar recursos managed
            _videoSource?.SignalToStop();
            _videoSource?.WaitForStop();
            _videoSource = null;
        }

        // Aqui entrariam recursos unmanaged (se houvesse)

        _disposed = true;
    }
}

// Opcional: Finalizer apenas se houver recursos unmanaged
// ~CameraService() { Dispose(false); }
```

### 📝 Passos:
1. Abrir cada classe com warning CA1063
2. Adicionar campo `private bool _disposed = false;`
3. Refatorar método `Dispose()` para chamar `Dispose(true)` + `GC.SuppressFinalize(this)`
4. Criar método virtual `protected virtual void Dispose(bool disposing)`
5. Mover lógica de limpeza para dentro do `if (disposing)`
6. Executar build e verificar 0 warnings CA1063

### ⏱️ Tempo: 20 minutos (5-7 min por classe)

---

## 📦 TAREFA 4: ASYNC VOID REFACTORING (4-6 HORAS)

### 🎯 Objetivo:
Refatorar 15 event handlers `async void` para usar `AsyncEventHandlerHelper` (já existe).

### 📂 Arquivos Afetados:
1. `src/BioDesk.App/App.xaml.cs` → OnStartup (1 handler)
2. `src/BioDesk.App/Dialogs/CameraCaptureWindow.xaml.cs` → 4 handlers
3. `src/BioDesk.App/Views/ListaPacientesView.xaml.cs` → OnLoaded (1 handler)
4. `src/BioDesk.App/Views/FichaPacienteView.xaml.cs` → 2 handlers
5. `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs` → 4 handlers
6. `src/BioDesk.App/Views/Abas/RegistoConsultasUserControl.xaml.cs` → 1 handler

### 🔍 Problema:
```csharp
// ❌ UNSAFE: Exceções não capturadas crasham app
private async void Button_Click(object sender, RoutedEventArgs e)
{
    await SomeAsyncOperation(); // Se throw, app crash!
}
```

### ✅ Solução (Helper JÁ EXISTE!):
```csharp
// ✅ SAFE: Exceções capturadas e logadas
private async void Button_Click(object sender, RoutedEventArgs e)
{
    await AsyncEventHandlerHelper.HandleAsync(async () =>
    {
        await SomeAsyncOperation(); // Protegido
    });
}
```

### 📝 Template de Refactoring:

**ANTES:**
```csharp
private async void StartPreviewButton_Click(object sender, RoutedEventArgs e)
{
    if (_cameraService == null) return;

    IsProcessing = true;
    StartPreviewButton.IsEnabled = false;

    try
    {
        await _cameraService.StartPreviewAsync(PreviewImage);
        CaptureButton.IsEnabled = true;
    }
    catch (Exception ex)
    {
        MessageBox.Show($"Erro: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
    }
    finally
    {
        IsProcessing = false;
    }
}
```

**DEPOIS:**
```csharp
private async void StartPreviewButton_Click(object sender, RoutedEventArgs e)
{
    await AsyncEventHandlerHelper.HandleAsync(async () =>
    {
        if (_cameraService == null) return;

        IsProcessing = true;
        StartPreviewButton.IsEnabled = false;

        try
        {
            await _cameraService.StartPreviewAsync(PreviewImage);
            CaptureButton.IsEnabled = true;
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Erro: {ex.Message}", "Erro", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsProcessing = false;
        }
    }, "StartPreviewButton_Click");
}
```

### 📝 Checklist (15 handlers):
```
□ App.xaml.cs → OnStartup
□ CameraCaptureWindow.xaml.cs → StartPreviewButton_Click
□ CameraCaptureWindow.xaml.cs → CaptureButton_Click
□ CameraCaptureWindow.xaml.cs → CancelButton_Click
□ CameraCaptureWindow.xaml.cs → CameraSelector_SelectionChanged
□ ListaPacientesView.xaml.cs → OnLoaded
□ FichaPacienteView.xaml.cs → OnDataContextChanged
□ FichaPacienteView.xaml.cs → AtualizarVisibilidadeAbas
□ IrisdiagnosticoUserControl.xaml.cs → MarkingsCanvas_MouseLeftButtonDown
□ IrisdiagnosticoUserControl.xaml.cs → MudarCor_Click
□ IrisdiagnosticoUserControl.xaml.cs → EditarObservacoes_Click (TAREFA 1)
□ IrisdiagnosticoUserControl.xaml.cs → CapturarDaCameraButton_Click
□ RegistoConsultasUserControl.xaml.cs → BtnGerarPdf_Click
```

### ⏱️ Tempo: 4-6 horas (15-20 min por handler)

### 🎯 Prioridade: P3 - BAIXO
**Razão:** App não tem crashes reportados, é preventivo.

---

## 📋 ORDEM DE EXECUÇÃO RECOMENDADA

### **SPRINT 1.5 - Quick Wins (1 hora)**
1. ✅ **TAREFA 1:** Dialog Editar Observações (30 min)
   - Impacto: Alto (UX visível)
   - Complexidade: Baixa
   - ROI: Excelente
2. ✅ **TAREFA 3:** CA1063 Dispose Pattern (20 min)
   - Impacto: Médio (code quality)
   - Complexidade: Baixa
   - ROI: Bom

### **SPRINT 2 - Feature Avançada (5-6 horas)**
3. ⏳ **TAREFA 2:** Overlay Zonas Iridológicas (5-6 horas)
   - Impacto: Alto (diferenciação mercado)
   - Complexidade: Alta
   - ROI: Médio (feature científica)
   - **Decisão:** Implementar APENAS se cliente solicitar

### **SPRINT 3 - Preventivo (4-6 horas)**
4. ⏸️ **TAREFA 4:** async void Refactoring (4-6 horas)
   - Impacto: Baixo (preventivo)
   - Complexidade: Média
   - ROI: Baixo (sem bugs reportados)
   - **Decisão:** DEIXAR PARA DEPOIS (não urgente)

---

## 🧪 TESTING CHECKLIST FINAL

Após cada implementação, verificar:

### ✅ Build:
```bash
dotnet clean
dotnet restore
dotnet build --no-incremental
# Deve ter: 0 Errors, 27 Warnings (apenas NU1701 AForge)
```

### ✅ Funcionalidade:
- [ ] Dialog observações: Abre, edita, salva, atualiza grid
- [ ] Overlay zonas: Liga/desliga, hover funciona, hit-test detecta
- [ ] Dispose: Nenhum memory leak (testar fechar/abrir múltiplas vezes)
- [ ] async void: Nenhum crash ao forçar erros

### ✅ Performance:
- [ ] Overlay renderiza em < 2 segundos
- [ ] Sem lag ao fazer hover sobre zonas
- [ ] Marcações manuais ainda funcionam normalmente

### ✅ UX:
- [ ] Mensagens de erro amigáveis
- [ ] Loading states visíveis
- [ ] Tooltips informativos
- [ ] Interface responsiva

---

## 📞 QUANDO PEDIR AJUDA

### 🔴 Blockers Críticos:
- CS0234 errors (violações MVVM)
- JSON não carrega (embedded resources)
- Polígonos não renderizam (coordenadas incorretas)
- Memory leak (Dispose não funciona)

### 🟡 Consultas Normais:
- Performance lenta (otimização de 200+ polígonos)
- Calibração zonas desalinhadas (ajuste manual)
- Hit-testing impreciso (algoritmo ray-casting)

### 🟢 Low Priority:
- Code style / formatação
- Warnings cosméticos
- Tooltips / mensagens UI

---

## 🎯 CRITÉRIOS DE SUCESSO

### **TAREFA 1 - Dialog:** ✅ COMPLETO quando:
- [ ] Dialog abre ao clicar "✏️ Editar Observações"
- [ ] Texto atual carrega no TextBox
- [ ] Editar + OK atualiza grid imediatamente
- [ ] Mudança persiste no banco de dados
- [ ] Build: 0 errors

### **TAREFA 2 - Overlay:** ✅ COMPLETO quando:
- [ ] Toggle button liga/desliga overlay
- [ ] 72 zonas renderizam sobre imagem
- [ ] Hover destaca zona + mostra tooltip
- [ ] Clicar zona mostra dialog de confirmação
- [ ] Marcações manuais ainda funcionam
- [ ] Painel "🎯 ZONA DETECTADA" atualiza
- [ ] Build: 0 errors

### **TAREFA 3 - Dispose:** ✅ COMPLETO quando:
- [ ] 3 classes implementam padrão virtual
- [ ] Build: 0 warnings CA1063
- [ ] Camera para corretamente ao fechar

### **TAREFA 4 - async void:** ✅ COMPLETO quando:
- [ ] 15 handlers usam AsyncEventHandlerHelper
- [ ] Nenhum crash ao forçar exceptions
- [ ] Logs mostram exceções capturadas
- [ ] Build: 0 errors

---

## 🎁 BONUS: FEATURES OPCIONAIS

Se sobrar tempo, considerar:

1. **Persistência Estado Abas** (1-2 horas)
   - Salvar último tab ativo por paciente
   - Restaurar ao reabrir ficha

2. **CA1416 Platform Attributes** (10 min)
   - Adicionar `[SupportedOSPlatform("windows")]`
   - Eliminar 42 warnings CA1416

3. **Export Mapa para PDF** (2-3 horas)
   - Gerar PDF da íris com overlay de zonas
   - Incluir em relatórios de consulta

4. **Biblioteca Zonas Personalizadas** (3-4 horas)
   - Interface para editar zonas manualmente
   - Salvar mapas customizados por terapeuta

---

## 📚 REFERÊNCIAS TÉCNICAS

### Arquitetura:
- MVVM: ViewModels não referenciam Views (CS0234 se tentar)
- DI: Serviços injetados via construtor
- Async: Sempre usar await, nunca .Wait() ou .Result

### WPF:
- Layers: Panel.ZIndex (0=base, 50=overlay, 100=marcas)
- Converters: IValueConverter para binding complexos
- Canvas: Coordenadas absolutas (Left, Top)
- Polygon: PointCollection para Path Data

### Coordenadas Polares:
- Ângulo: 0-360° (0° = direita, 90° = baixo)
- Raio: 0-1 normalizado (0 = centro, 1 = borda)
- Conversão: x = cx + r*cos(θ), y = cy + r*sin(θ)

### JSON:
- System.Text.Json (não Newtonsoft)
- [JsonPropertyName("campo")] para mapeamento
- Embedded resources: assembly.GetManifestResourceStream()

---

## ✅ CHECKLIST FINAL PRÉ-ENTREGA

Antes de marcar como completo:

- [ ] `dotnet build` = 0 Errors, apenas NU1701 warnings
- [ ] Aplicação executa sem crashes
- [ ] Todas funcionalidades testadas manualmente
- [ ] Código comentado com XML docs
- [ ] Git commit com mensagem descritiva
- [ ] README atualizado (se aplicável)
- [ ] Documentação técnica criada (este ficheiro)

---

**BOA SORTE! 🚀**

Se tiveres dúvidas, consulta:
- `TODO_IRISDIAGNOSTICO_E_OTIMIZACAO.md` (análise detalhada)
- `.github/copilot-instructions.md` (regras do projeto)
- `PLANO_DESENVOLVIMENTO_RESTANTE.md` (contexto completo)
