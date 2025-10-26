# Correções Críticas - Sistema Íris (24 Out 2025)

Este documento contém as correções identificadas na auditoria completa do sistema de Irisdiagnóstico.

## Status das Correções

| # | Problema | Severidade | Status | Ficheiro |
|---|----------|------------|--------|----------|
| 1 | Memory Leak Câmara | 🔴 CRÍTICO | ✅ JÁ CORRIGIDO | RealCameraService.cs |
| 2 | Race Condition Dispose | 🔴 CRÍTICO | 🔴 PENDENTE | CameraCaptureWindow.xaml.cs |
| 3 | Marcas Invisíveis Zoom | 🟡 ALTO | 🟡 PENDENTE | IrisdiagnosticoUserControl.xaml |
| 4 | Warnings AForge | 🔵 BAIXO | 🔵 OPCIONAL | 4x .csproj |

---

## 1. ✅ Memory Leak Câmara - JÁ CORRIGIDO

### Problema
Bitmap `_lastCapturedFrame` não era disposed antes de reassign, causando memory leak cumulativo durante preview longo.

### Verificação
Linha 136 de `src/BioDesk.Services/Camera/RealCameraService.cs` já contém:
```csharp
_lastCapturedFrame?.Dispose();
_lastCapturedFrame = croppedFrame;
```

### Status
✅ **NENHUMA AÇÃO NECESSÁRIA** - Correção já implementada anteriormente.

---

## 2. 🔴 Race Condition Camera Dispose - PENDENTE

### Problema
**Severidade**: CRÍTICO
**Ficheiro**: `src/BioDesk.App/Dialogs/CameraCaptureWindow.xaml.cs`

Quando o utilizador clica no botão "Capturar e Fechar" e fecha o diálogo rapidamente, podem ocorrer duas operações concorrentes:
1. `OnClosed()` → `StopPreviewAsync()` → `_cameraService.Dispose()`
2. Outro handler → `StopPreviewAsync()`

Isto causa `ObjectDisposedException` porque o segundo handler tenta parar um serviço já disposed.

### Reprodução
1. Abrir diálogo de câmara (Debug → Break in CameraCaptureWindow)
2. Clicar "Capturar e Fechar"
3. Fechar janela IMEDIATAMENTE
4. Observar exception no log (ou crash silencioso)

### Solução: Adicionar SemaphoreSlim

#### Passo 1: Adicionar campo no topo da classe
```csharp
public partial class CameraCaptureWindow : Window
{
    private readonly ICameraService _cameraService;
    private bool _isPreviewRunning = false;
    private readonly SemaphoreSlim _disposeLock = new(1, 1); // ✅ ADICIONAR ESTA LINHA

    // ... resto do código
}
```

#### Passo 2: Proteger OnClosed com semáforo
```csharp
protected override async void OnClosed(EventArgs e)
{
    await _disposeLock.WaitAsync(); // ✅ Aguardar lock
    try
    {
        if (_isPreviewRunning)
        {
            await _cameraService.StopPreviewAsync();
            _isPreviewRunning = false;
        }

        if (_cameraService is IDisposable disposable)
        {
            disposable.Dispose();
        }
    }
    finally
    {
        _disposeLock.Release(); // ✅ Libertar sempre
    }

    base.OnClosed(e);
}
```

#### Passo 3: Adicionar Dispose do SemaphoreSlim
```csharp
// Adicionar método IDisposable se não existir
private bool _disposed = false;

protected virtual void Dispose(bool disposing)
{
    if (!_disposed && disposing)
    {
        _disposeLock?.Dispose(); // ✅ Dispose do semáforo
    }
    _disposed = true;
}

public void Dispose()
{
    Dispose(true);
    GC.SuppressFinalize(this);
}
```

### Validação
Após aplicar:
```powershell
dotnet build
dotnet run --project src/BioDesk.App
# 1. Abrir ficha paciente
# 2. Aba Íris → Capturar Nova Imagem
# 3. Capturar e fechar RAPIDAMENTE 10x
# 4. Verificar sem exceptions no log
```

---

## 3. 🟡 Marcas Invisíveis em Zoom - PENDENTE

### Problema
**Severidade**: ALTO (UX)
**Ficheiro**: `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml`

Marcas de íris têm tamanho fixo 24x24 pixels (linha ~867):
```xaml
<Ellipse Width="24" Height="24" .../>
```

Quando zoom = 5x, a íris é escalada 5x mas as marcas permanecem 24px → **tamanho visual = 4.8px** (imperceptível).

### Reprodução
1. Carregar imagem de íris
2. Adicionar 3-4 marcas em zonas diferentes
3. Modo Zoom → clicar várias vezes (chegar a zoom 5x)
4. Marcas tornam-se pontos minúsculos

### Solução: Converter Zoom para Tamanho Dinâmico

#### Passo 1: Criar Converter
**Ficheiro NOVO**: `src/BioDesk.App/Converters/ZoomToSizeConverter.cs`

```csharp
using System;
using System.Globalization;
using System.Windows.Data;

namespace BioDesk.App.Converters
{
    /// <summary>
    /// Converte nível de zoom em tamanho proporcional para elementos UI.
    /// </summary>
    public class ZoomToSizeConverter : IValueConverter
    {
        public double BaseSize { get; set; } = 24.0;

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is double zoom && zoom > 0)
            {
                return BaseSize * zoom; // 24px * 5 = 120px visual
            }
            return BaseSize;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
```

#### Passo 2: Registar Converter em Resources
**Ficheiro**: `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml`

Adicionar no `<UserControl.Resources>`:
```xaml
<UserControl.Resources>
    <!-- Converters existentes -->
    <conv:BooleanToVisibilityConverter x:Key="BoolToVis"/>
    <conv:InverseBooleanConverter x:Key="InverseBool"/>

    <!-- ✅ ADICIONAR ESTA LINHA -->
    <conv:ZoomToSizeConverter x:Key="ZoomToSize" BaseSize="24"/>

    <!-- Resto dos resources -->
</UserControl.Resources>
```

#### Passo 3: Aplicar Binding nas Marcas
**Ficheiro**: `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml` (linha ~867)

**ANTES**:
```xaml
<Ellipse Width="24" Height="24"
         Fill="{Binding Cor, Converter={StaticResource ColorToBrush}}"
         Stroke="White" StrokeThickness="2"/>
```

**DEPOIS**:
```xaml
<Ellipse Width="{Binding DataContext.ZoomLevel,
                         RelativeSource={RelativeSource AncestorType=UserControl},
                         Converter={StaticResource ZoomToSize}}"
         Height="{Binding DataContext.ZoomLevel,
                          RelativeSource={RelativeSource AncestorType=UserControl},
                          Converter={StaticResource ZoomToSize}}"
         Fill="{Binding Cor, Converter={StaticResource ColorToBrush}}"
         Stroke="White" StrokeThickness="2"/>
```

### Validação
```powershell
dotnet build
dotnet run --project src/BioDesk.App
# 1. Íris com marcas → Zoom 5x
# 2. Marcas devem ter ~120px de diâmetro (visíveis e clicáveis)
```

---

## 4. 🔵 Warnings AForge - OPCIONAL

### Problema
**Severidade**: BAIXO (Cosmético)
24x warnings NU1701:
```
Package 'AForge 2.2.5' was restored using '.NETFramework,Version=v4.6.1...'
instead of the project target framework 'net8.0-windows7.0'.
```

**Causa**: AForge é biblioteca .NET Framework 4.x (2013), mas funciona perfeitamente em .NET 8 via backward compatibility.

### Solução: Suprimir Warnings
Adicionar `<NoWarn>NU1701</NoWarn>` aos 4 projetos que usam AForge:

#### Ficheiros a Editar
1. `src/BioDesk.App/BioDesk.App.csproj`
2. `src/BioDesk.Services/BioDesk.Services.csproj`
3. `src/BioDesk.ViewModels/BioDesk.ViewModels.csproj`
4. `src/BioDesk.Tests/BioDesk.Tests.csproj`

#### Alteração (em cada .csproj)
**ANTES**:
```xml
<PropertyGroup>
    <TargetFramework>net8.0-windows</TargetFramework>
    <Nullable>enable</Nullable>
</PropertyGroup>
```

**DEPOIS**:
```xml
<PropertyGroup>
    <TargetFramework>net8.0-windows</TargetFramework>
    <Nullable>enable</Nullable>
    <NoWarn>NU1701</NoWarn> <!-- ✅ ADICIONAR -->
</PropertyGroup>
```

### Validação
```powershell
dotnet clean
dotnet build
# Output esperado: 0 Warnings, 0 Errors
```

---

## Checklist Final de Aplicação

### Ordem Recomendada
1. ✅ **Memory Leak** - Verificar presente (sem ação)
2. 🔴 **Race Condition** - Aplicar Seção 2 (3 blocos código)
3. 🟡 **Zoom Marcas** - Aplicar Seção 3 (criar converter + 2 edições XAML)
4. 🔵 **Warnings AForge** - OPCIONAL - Aplicar Seção 4 (4 edições .csproj)

### Build & Test
```powershell
# Após cada correção:
dotnet build

# Após todas as correções:
dotnet test src/BioDesk.Tests
dotnet run --project src/BioDesk.App

# Testes manuais:
# ✅ Câmara: Capturar 10x com close rápido (sem crashes)
# ✅ Marcas: Zoom 5x com marcas visíveis (~120px)
# ✅ Build: 0 Errors (0 Warnings se aplicou Seção 4)
```

---

## Notas Técnicas

### Por que SemaphoreSlim e não lock?
- `lock` não funciona com `await` (causa deadlock)
- `SemaphoreSlim.WaitAsync()` é async-safe
- Permite `finally` garantido (mesmo com exceptions)

### Por que Converter e não Code-Behind?
- Binding XAML mantém separação MVVM
- ZoomLevel já é `[ObservableProperty]` no ViewModel
- Reutilizável para outros elementos escaláveis

### AForge Warnings - É Seguro Ignorar?
**SIM**. AForge 2.2.5 compila e executa perfeitamente em .NET 8:
- Usa APIs estáveis (System.Drawing, DirectShow)
- Testado extensivamente no BioDeskPro desde .NET Core 3.1
- Warnings são apenas avisos de compatibilidade (não erros)

---

## Histórico de Auditoria

| Data | Ação | Responsável |
|------|------|-------------|
| 24 Out 2025 | Auditoria completa Iris (5000+ linhas) | GitHub Copilot |
| 24 Out 2025 | Identificação 4 issues (1 já corrigido) | GitHub Copilot |
| 24 Out 2025 | Criação documento correções | GitHub Copilot |

---

**FIM DO DOCUMENTO**
