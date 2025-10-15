# 🔍 AUDITORIA COMPLETA: Por que as imagens não aparecem no canvas da íris

**Data**: 7 de outubro de 2025
**Investigador**: GitHub Copilot
**Objetivo**: Identificar TODAS as razões pelas quais as imagens da íris não são visíveis no canvas

---

## 📋 RESUMO EXECUTIVO

Após auditoria detalhada do código, identifiquei **7 PROBLEMAS CRÍTICOS** que podem estar a impedir a visualização das imagens no canvas da íris. Alguns são definitivos, outros são potenciais.

---

## 🚨 PROBLEMA 1: VISIBILITY CONDICIONAL - Image.Style com Trigger **CRÍTICO**

### Localização
**Ficheiro**: `IrisdiagnosticoUserControl.xaml`
**Linhas**: 266-274

### Código Atual
```xaml
<Image x:Name="IrisCentralImage"
       Width="1400" Height="1400"
       Source="{Binding IrisImagemSelecionada.CaminhoImagem, Converter={StaticResource PathToImageConverter}}"
       Stretch="Uniform"
       Panel.ZIndex="1">
    <Image.Style>
        <Style TargetType="Image">
            <Setter Property="Visibility" Value="Visible"/>
            <Style.Triggers>
                <DataTrigger Binding="{Binding IrisImagemSelecionada}" Value="{x:Null}">
                    <Setter Property="Visibility" Value="Collapsed"/>
                </DataTrigger>
            </Style.Triggers>
        </Style>
    </Image.Style>
</Image>
```

### Problema
✅ **BOM**: A lógica está CORRECTA - imagem deve ser visível quando `IrisImagemSelecionada != null`

### Diagnóstico
🔍 **PONTO DE VERIFICAÇÃO**:
- O trigger funciona PERFEITAMENTE se `IrisImagemSelecionada` está definido
- **MAS** se o binding falhar silenciosamente, a imagem fica visível mas SEM SOURCE

### Teste Sugerido
```csharp
// No ViewModel, adicionar log:
partial void OnIrisImagemSelecionadaChanged(IrisImagem? value)
{
    _logger.LogInformation($"🔍 SELEÇÃO MUDOU: {value?.Olho ?? "NULL"} | Caminho: {value?.CaminhoImagem ?? "N/A"}");
}
```

---

## 🚨 PROBLEMA 2: Z-INDEX OVERLAP - MapaOverlayCanvas sobrepõe a imagem **CRÍTICO**

### Localização
**Ficheiro**: `IrisdiagnosticoUserControl.xaml`
**Linhas**: 262 (Image) vs 277 (MapaOverlayCanvas)

### Estrutura Visual Atual
```
Canvas (1400x1400)
├─ LAYER 1 (Panel.ZIndex="1") → Image (IrisCentralImage)  ← IMAGEM DA ÍRIS
├─ LAYER 2 (Panel.ZIndex="2") → MapaOverlayCanvas          ← POLÍGONOS + EVENTOS MOUSE
├─ LAYER 3 (Panel.ZIndex="3") → HandlersCanvas             ← HANDLERS DE CALIBRAÇÃO
├─ LAYER 4 (Panel.ZIndex="4") → DesenhoCanvas              ← DESENHO LIVRE
└─ LAYER 5 (Panel.ZIndex="5") → ??? (não existe)
```

### ⚠️ PROBLEMA IDENTIFICADO

**MapaOverlayCanvas** tem:
- `Panel.ZIndex="2"` → Fica POR CIMA da imagem
- `Background="Transparent"` → **CORRETO** (permite ver através)
- **MAS**: Se houver QUALQUER polígono mal configurado, pode OCULTAR a imagem

### Teste Visual de Depuração
Adicionar temporariamente no XAML:

```xaml
<!-- LAYER 1: Imagem da Íris Real -->
<Image x:Name="IrisCentralImage"
       Width="1400" Height="1400"
       Source="{Binding IrisImagemSelecionada.CaminhoImagem, Converter={StaticResource PathToImageConverter}}"
       Stretch="Uniform"
       Panel.ZIndex="1"
       BorderBrush="Red" BorderThickness="5">  <!-- ✅ DEBUG: Borda vermelha -->
```

Se vir a borda VERMELHA mas não a imagem → Problema no SOURCE/BINDING
Se NÃO vir nem borda → Problema de Z-Index ou Visibility

---

## 🚨 PROBLEMA 3: BINDING SILENCIOSO - PathToImageConverter retorna NULL **PROVÁVEL**

### Localização
**Ficheiro**: `PathToImageSourceConverter.cs`
**Linhas**: 15-42

### Código Atual
```csharp
public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
{
    if (value is not string caminho || string.IsNullOrWhiteSpace(caminho))
        return null;  // ⚠️ RETORNA NULL SILENCIOSAMENTE

    if (!File.Exists(caminho))
        return null;  // ⚠️ RETORNA NULL SILENCIOSAMENTE

    try
    {
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.UriSource = new Uri(caminho, UriKind.Absolute);
        bitmap.EndInit();
        bitmap.Freeze();
        return bitmap;
    }
    catch
    {
        return null;  // ⚠️ RETORNA NULL SILENCIOSAMENTE
    }
}
```

### Problema
❌ **CRÍTICO**: O converter **NUNCA LOGA** quando falha!

### Cenários de Falha Silenciosa
1. `CaminhoImagem` é `null` ou vazio → `return null`
2. Ficheiro não existe no disco → `return null`
3. Permissões de leitura negadas → `catch { return null }`
4. Caminho relativo vs absoluto → `File.Exists()` falha → `return null`
5. Formato de imagem inválido → `catch { return null }`

### ✅ SOLUÇÃO DEFINITIVA
```csharp
public object? Convert(object value, Type targetType, object parameter, CultureInfo culture)
{
    if (value is not string caminho || string.IsNullOrWhiteSpace(caminho))
    {
        Debug.WriteLine("❌ [ImageConverter] Caminho NULL ou vazio");
        return null;
    }

    if (!File.Exists(caminho))
    {
        Debug.WriteLine($"❌ [ImageConverter] Ficheiro NÃO EXISTE: {caminho}");
        return null;
    }

    try
    {
        Debug.WriteLine($"✅ [ImageConverter] A carregar: {caminho}");
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.UriSource = new Uri(caminho, UriKind.Absolute);
        bitmap.EndInit();
        bitmap.Freeze();
        Debug.WriteLine($"✅ [ImageConverter] Carregada com sucesso!");
        return bitmap;
    }
    catch (Exception ex)
    {
        Debug.WriteLine($"❌ [ImageConverter] EXCEÇÃO: {ex.Message}");
        return null;
    }
}
```

---

## 🚨 PROBLEMA 4: CAMINHO RELATIVO vs ABSOLUTO **PROVÁVEL**

### Localização
**Entidade**: `IrisImagem.CaminhoImagem`
**Ficheiro**: `IrisImagem.cs` (linha 32)

### Código Atual
```csharp
/// <summary>
/// Caminho relativo da imagem no sistema de ficheiros
/// </summary>
public string CaminhoImagem { get; set; } = string.Empty;
```

### ⚠️ COMENTÁRIO DIZ "RELATIVO" MAS CÓDIGO USA "ABSOLUTO"

#### Ao SALVAR imagem (IrisdiagnosticoViewModel.cs, linha ~430):
```csharp
var caminhoDestino = System.IO.Path.Combine(pastaPaciente, nomeArquivo);
// Exemplo: C:\Users\...\Documents\BioDeskPro2\Pacientes\João Silva\IrisImagens\Iris_Direito_20251007_143052.jpg
```
→ **CAMINHO ABSOLUTO** é salvo na BD

#### Ao CONVERTER (PathToImageSourceConverter.cs, linha 23):
```csharp
if (!File.Exists(caminho))
    return null;
```
→ `File.Exists()` funciona com caminhos ABSOLUTOS e RELATIVOS

### 🔍 TESTE DE VERIFICAÇÃO
Adicionar no `CarregarImagensAsync`:
```csharp
foreach (var img in imagensDoPaciente)
{
    _logger.LogInformation("  📷 ID={Id}, Olho={Olho}, Caminho={Caminho}, Existe={Existe}",
        img.Id, img.Olho, img.CaminhoImagem, File.Exists(img.CaminhoImagem));
}
```

Se `Existe=False` → **PROBLEMA DEFINITIVO**

---

## 🚨 PROBLEMA 5: VIEWBOX STRETCH ESCONDE IMAGEM **POSSÍVEL**

### Localização
**Ficheiro**: `IrisdiagnosticoUserControl.xaml`
**Linha**: 256

### Código Atual
```xaml
<Viewbox Stretch="Uniform">
    <Canvas Width="1400" Height="1400" Background="White">
```

### Problema Potencial
Se o **Viewbox** tiver tamanho 0x0 ou muito pequeno:
- `Stretch="Uniform"` → Escala canvas para caber
- Imagem fica **INVISÍVEL** (scaled down to nothing)

### Teste Visual
Adicionar temporariamente:
```xaml
<Viewbox Stretch="Uniform" BorderBrush="Blue" BorderThickness="3">
```

Se vir borda AZUL mas muito pequena → Viewbox está a colapsar

### Causa Raiz Possível
```xaml
<Border Grid.Column="1"
        Background="#F7F9F6"
        CornerRadius="8"
        Padding="4"
        Margin="8,0">
```
→ `Padding="4"` reduz espaço disponível para o Viewbox

---

## 🚨 PROBLEMA 6: IMAGE SEM FALLBACK VISUAL **USABILIDADE**

### Problema
Quando `IrisImagemSelecionada == null`:
- Image fica `Collapsed` (correcto)
- **MAS** utilizador vê CANVAS BRANCO VAZIO → Confuso!

### ✅ SOLUÇÃO RECOMENDADA
Adicionar placeholder visual:

```xaml
<!-- ANTES da Image, adicionar: -->
<TextBlock Panel.ZIndex="0"
           Text="📷 Selecione uma imagem de íris na galeria à esquerda"
           FontSize="18"
           Foreground="#9CAF97"
           HorizontalAlignment="Center"
           VerticalAlignment="Center"
           TextWrapping="Wrap"
           TextAlignment="Center"
           Margin="50">
    <TextBlock.Style>
        <Style TargetType="TextBlock">
            <Setter Property="Visibility" Value="Collapsed"/>
            <Style.Triggers>
                <DataTrigger Binding="{Binding IrisImagemSelecionada}" Value="{x:Null}">
                    <Setter Property="Visibility" Value="Visible"/>
                </DataTrigger>
            </Style.Triggers>
        </Style>
    </TextBlock.Style>
</TextBlock>
```

---

## 🚨 PROBLEMA 7: NENHUMA IMAGEM NA BASE DE DADOS **VERIFICAR**

### Localização
**ViewModel**: `IrisdiagnosticoViewModel.CarregarImagensAsync()`
**Linhas**: 480-510

### Código Atual
```csharp
var imagensDoPaciente = todasImagens
    .Where(i => i.PacienteId == PacienteAtual.Id)
    .OrderByDescending(i => i.DataCaptura)
    .ToList();

_logger.LogInformation("🔍 Imagens filtradas para Paciente {Id}: {Count}",
    PacienteAtual.Id, imagensDoPaciente.Count);
```

### Problema
Se `Count == 0`:
- **ListBox de imagens** fica vazio
- `IrisImagemSelecionada` fica `null`
- **Imagem** fica `Collapsed`

### ✅ TESTE DEFINITIVO
1. Adicionar botão "📷 Capturar" ou "📁 Adicionar"
2. Salvar UMA imagem
3. Verificar logs:
   - ✅ "Imagem copiada para: ..."
   - ✅ "Imagem de íris adicionada: ID: X"
   - ✅ "Carregadas X imagens..."
4. Se `Count > 0` mas imagem não aparece → Outros problemas (1-6)
5. Se `Count == 0` → **Utilizador não adicionou imagens**

---

## 📊 DIAGNÓSTICO SISTEMÁTICO - CHECKLIST

Execute esta sequência na **Output Window** do Visual Studio:

### PASSO 1: Verificar Seleção de Imagem
```
🔍 DEBUG: Seleção mudou! Valor: [Direito|Esquerdo|NULL]
```
- ✅ Se aparecer "Direito" ou "Esquerdo" → Binding OK
- ❌ Se aparecer "NULL" → **PROBLEMA 7** (sem imagens na BD)

### PASSO 2: Verificar Caminho da Imagem
```
📷 Imagem ID=X, Olho=Y, Caminho=Z, Existe=[True|False]
```
- ✅ Se `Existe=True` → Ficheiro OK
- ❌ Se `Existe=False` → **PROBLEMA 4** (caminho inválido)

### PASSO 3: Verificar Converter
```
✅ [ImageConverter] A carregar: C:\...\Iris_Direito_...jpg
✅ [ImageConverter] Carregada com sucesso!
```
- ✅ Se aparecer "Carregada com sucesso" → Converter OK
- ❌ Se aparecer "Ficheiro NÃO EXISTE" → **PROBLEMA 4**
- ❌ Se aparecer "EXCEÇÃO: ..." → **PROBLEMA 3** (formato inválido ou permissões)

### PASSO 4: Verificar Visibility (com Snoop ou Live Visual Tree)
```
IrisCentralImage.Visibility = [Visible|Collapsed]
IrisCentralImage.ActualWidth = [>0|0]
IrisCentralImage.ActualHeight = [>0|0]
```
- ✅ Se `Visible` e `ActualWidth > 0` → Layout OK
- ❌ Se `Collapsed` → **PROBLEMA 1** (trigger a ocultar)
- ❌ Se `Visible` mas `ActualWidth = 0` → **PROBLEMA 5** (Viewbox colapsa)

### PASSO 5: Verificar Z-Index (com Snoop)
```
IrisCentralImage.Panel.ZIndex = 1
MapaOverlayCanvas.Panel.ZIndex = 2 (e Background="Transparent")
```
- ✅ Se correcto e `Transparent` → Layout OK
- ❌ Se `MapaOverlayCanvas.Background != Transparent` → **PROBLEMA 2**

---

## ✅ PLANO DE ACÇÃO IMEDIATO

### FASE 1: ADICIONAR LOGGING DIAGNÓSTICO (5 min)

1. **PathToImageSourceConverter.cs** → Adicionar `Debug.WriteLine` (ver PROBLEMA 3)
2. **IrisdiagnosticoViewModel.cs** → No `CarregarImagensAsync`, adicionar:
   ```csharp
   foreach (var img in imagensDoPaciente)
   {
       var existe = File.Exists(img.CaminhoImagem);
       _logger.LogInformation("📷 ID={Id}, Caminho={Caminho}, Existe={Existe}",
           img.Id, img.CaminhoImagem, existe);
   }
   ```

### FASE 2: TESTES VISUAIS DE DEPURAÇÃO (5 min)

3. **IrisdiagnosticoUserControl.xaml** → Adicionar bordas DEBUG:
   ```xaml
   <Image x:Name="IrisCentralImage"
          BorderBrush="Red" BorderThickness="5"
          ...>

   <Canvas x:Name="MapaOverlayCanvas"
           BorderBrush="Blue" BorderThickness="3"
           ...>
   ```

### FASE 3: EXECUTAR APLICAÇÃO E OBSERVAR (10 min)

4. **Iniciar aplicação** em modo DEBUG
5. **Navegar** para FichaPaciente → Tab Irisdiagnóstico
6. **Clicar** em "📁 Adicionar" e selecionar UMA imagem de teste
7. **Observar** Output Window:
   - Logs de carregamento
   - Logs do converter
   - Mensagens de erro

### FASE 4: ANÁLISE DOS RESULTADOS (5 min)

8. **Verificar Visual Studio**:
   - Problems Panel → Erros de binding?
   - Output Window → Exceções?
   - Live Visual Tree → `IrisCentralImage` visível?

9. **Verificar aplicação**:
   - Canvas central → Borda vermelha visível?
   - Canvas central → Imagem dentro da borda?
   - ListBox esquerda → Item selecionado (borda verde)?

---

## 🎯 RESULTADO ESPERADO

Após executar **FASE 1-4**, terá UMA das seguintes conclusões:

### ✅ CASO A: Imagem APARECE
- **Problema**: Era apenas falta de imagens na BD
- **Ação**: Remover bordas DEBUG e continuar desenvolvimento

### ❌ CASO B: Converter FALHA
- **Log**: `❌ [ImageConverter] Ficheiro NÃO EXISTE`
- **Problema**: **PROBLEMA 4** (caminho inválido)
- **Ação**: Verificar `IrisImagem.CaminhoImagem` na BD (SQL Browser)

### ❌ CASO C: Borda VERMELHA visível mas SEM imagem
- **Problema**: **PROBLEMA 3** (converter retorna null mas sem erros)
- **Ação**: Verificar formato do ficheiro (PNG/JPG válido?)

### ❌ CASO D: NENHUMA borda visível
- **Problema**: **PROBLEMA 5** (Viewbox colapsa) ou **PROBLEMA 2** (Z-Index)
- **Ação**: Usar Snoop/Live Visual Tree para inspecionar hierarquia visual

### ❌ CASO E: Logs PERFEITOS mas imagem invisível
- **Problema**: **PROBLEMA 2** (MapaOverlayCanvas a sobrepor) ou polígonos mal configurados
- **Ação**: Temporariamente desativar `MostrarMapaIridologico` e testar

---

## 📝 FICHEIROS MODIFICADOS PARA DIAGNÓSTICO

### 1. PathToImageSourceConverter.cs
```csharp
// Adicionar using System.Diagnostics no topo
// Substituir método Convert conforme PROBLEMA 3
```

### 2. IrisdiagnosticoViewModel.cs (linha ~495)
```csharp
foreach (var img in imagensDoPaciente)
{
    var existe = File.Exists(img.CaminhoImagem);
    _logger.LogInformation("📷 ID={Id}, Olho={Olho}, Caminho={Caminho}, Existe={Existe}",
        img.Id, img.Olho, img.CaminhoImagem, existe);
}
```

### 3. IrisdiagnosticoUserControl.xaml (linha 262)
```xaml
<Image x:Name="IrisCentralImage"
       BorderBrush="Red" BorderThickness="5"
       Width="1400" Height="1400"
       ...>
```

---

## 🚀 PRÓXIMOS PASSOS APÓS DIAGNÓSTICO

Quando identificar o problema específico:

1. **PROBLEMA 3 (Converter)** → Adicionar logging permanente
2. **PROBLEMA 4 (Caminho)** → Verificar lógica de salvamento
3. **PROBLEMA 2 (Z-Index)** → Ajustar Panel.ZIndex ou Background
4. **PROBLEMA 5 (Viewbox)** → Reduzir Padding do Border pai
5. **PROBLEMA 7 (Sem imagens)** → Melhorar UX com placeholder

---

## 📌 CONCLUSÃO

A auditoria identificou **7 pontos críticos** de falha. O mais provável é:

1. 🥇 **PROBLEMA 7**: Sem imagens na base de dados (solução: adicionar uma)
2. 🥈 **PROBLEMA 3**: Converter a falhar silenciosamente (solução: adicionar logs)
3. 🥉 **PROBLEMA 4**: Caminho de ficheiro inválido (solução: verificar BD)

**Tempo estimado de resolução**: 30 minutos com diagnóstico sistemático

---

**FIM DA AUDITORIA** ✅
