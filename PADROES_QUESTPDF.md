# 📐 PADRÕES QUESTPDF - Guia de Referência Rápida

**Projeto**: BioDeskPro 2.0
**Biblioteca**: QuestPDF Community
**Data**: 2025-10-01

---

## 🎯 REGRA DE OURO

> **"`.Height(fixo)` + `.FitHeight()` = EXCEPTION"**
>
> QuestPDF não permite constraints conflituosos na mesma chain.

---

## ✅ PADRÕES CORRETOS

### 1. Imagem com Altura Fixa e Centralização
```csharp
col.Item()
    .Border(1)
    .BorderColor(Colors.Grey.Lighten2)
    .Padding(5)
    .Height(80)         // Container fixo
    .AlignCenter()      // Horizontal ✅
    .AlignMiddle()      // Vertical ✅
    .Image(bytes)       // Conteúdo
    .FitArea();         // Ajuste proporcional ✅
```

### 2. Imagem com Largura Fixa
```csharp
col.Item()
    .Width(200)
    .AlignCenter()
    .AlignMiddle()
    .Image(bytes)
    .FitWidth();        // ✅ OK com Width()
```

### 3. Imagem Responsiva (Sem Constraints)
```csharp
col.Item()
    .AlignCenter()
    .Image(bytes)
    .FitArea();         // ✅ Ajusta automaticamente
```

### 4. Imagem em Background
```csharp
col.Item()
    .Background(Colors.Grey.Lighten3)
    .Height(100)
    .AlignCenter()
    .AlignMiddle()
    .Image(bytes)
    .FitArea();
```

---

## ❌ ANTI-PATTERNS (NUNCA USAR)

### 1. Height + FitHeight (CRASH!)
```csharp
// ❌ EXCEPTION: conflicting size constraints
col.Item()
    .Height(80)         // Fixa altura
    .Image(bytes)
    .FitHeight();       // ❌ Tenta ajustar altura - CONFLITO!
```

### 2. Width + FitWidth com MaxWidth (CRASH!)
```csharp
// ❌ EXCEPTION: conflicting constraints
col.Item()
    .Width(200)
    .MaxWidth(300)      // ❌ Conflito!
    .Image(bytes)
    .FitWidth();
```

### 3. AlignCenter DEPOIS de Image
```csharp
// ❌ ERRADO: ordem incorreta
col.Item()
    .Image(bytes)
    .AlignCenter();     // ❌ Não funciona aqui!
```

### 4. Múltiplos Aligns no Mesmo Eixo
```csharp
// ❌ REDUNDANTE e confuso
col.Item()
    .AlignCenter()
    .AlignLeft()        // ❌ Anula o AlignCenter
    .Image(bytes);
```

---

## 📏 MÉTODOS DE ALINHAMENTO

### Horizontal
```csharp
.AlignLeft()        // Alinha à esquerda
.AlignCenter()      // Centraliza horizontalmente ✅
.AlignRight()       // Alinha à direita
```

### Vertical
```csharp
.AlignTop()         // Alinha ao topo
.AlignMiddle()      // Centraliza verticalmente ✅
.AlignBottom()      // Alinha ao fundo
```

### Combinados (Mais Usados)
```csharp
.AlignCenter().AlignMiddle()    // Centro absoluto ✅
.AlignLeft().AlignTop()         // Canto superior esquerdo
.AlignRight().AlignBottom()     // Canto inferior direito
```

---

## 🖼️ MÉTODOS DE AJUSTE DE IMAGEM

### FitArea() - RECOMENDADO ✅
```csharp
.Image(bytes).FitArea()
// Ajusta proporcionalmente dentro do container
// Mantém aspect ratio
// Nunca distorce
```

### FitWidth()
```csharp
.Width(200).Image(bytes).FitWidth()
// Ajusta largura, altura proporcional
// ✅ OK com Width() fixo
// ❌ NUNCA com Height() fixo
```

### FitHeight()
```csharp
.Height(100).Image(bytes).FitHeight()
// ❌ EVITAR - causa conflitos
// Use .AlignMiddle() + .FitArea() em vez
```

---

## 🎨 BORDERS & PADDING

### Pattern Recomendado
```csharp
col.Item()
    .Border(1)                          // Borda 1pt
    .BorderColor(Colors.Grey.Lighten2)  // Cor suave
    .Padding(5)                         // Espaço interno
    .Height(80)
    .AlignCenter()
    .AlignMiddle()
    .Image(bytes)
    .FitArea();
```

### Bordas Customizadas
```csharp
.BorderVertical(2)      // Apenas vertical
.BorderHorizontal(1)    // Apenas horizontal
.BorderTop(3)           // Apenas topo
.BorderBottom(2)        // Apenas fundo
.BorderLeft(1)          // Apenas esquerda
.BorderRight(1)         // Apenas direita
```

---

## 📦 CONTAINERS E LAYOUT

### Row com 2 Colunas (50/50)
```csharp
row.RelativeItem().Column(col =>
{
    col.Item().Text("Coluna 1");
});

row.ConstantItem(50);  // Espaço entre colunas

row.RelativeItem().Column(col =>
{
    col.Item().Text("Coluna 2");
});
```

### Column com Items
```csharp
column.Item().Text("Header");
column.Item().PaddingTop(10).Text("Body");
column.Item().PaddingTop(5).Image(bytes).FitArea();
```

---

## 🚨 ERROR HANDLING

### Pattern Obrigatório para Imagens
```csharp
if (!string.IsNullOrEmpty(base64String))
{
    try
    {
        byte[] imageBytes = Convert.FromBase64String(base64String);
        col.Item()
            .Border(1)
            .BorderColor(Colors.Grey.Lighten2)
            .Padding(5)
            .Height(80)
            .AlignCenter()
            .AlignMiddle()
            .Image(imageBytes)
            .FitArea();
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao renderizar imagem");

        // Fallback: linha horizontal
        col.Item().LineHorizontal(1).LineColor(Colors.Black);

        col.Item()
            .PaddingTop(5)
            .AlignCenter()
            .Text("[Erro ao carregar imagem]")
            .FontSize(8)
            .Italic()
            .FontColor(Colors.Red.Medium);
    }
}
else
{
    // Fallback: linha horizontal
    col.Item().LineHorizontal(1).LineColor(Colors.Black);
}
```

---

## 🔍 DEBUGGING TIPS

### Visualizar Borders Durante Debug
```csharp
// Adicionar temporariamente durante desenvolvimento:
.Border(2)
.BorderColor(Colors.Red.Medium)  // Vermelho para debug
```

### Log de Dimensões
```csharp
_logger.LogDebug("Image size: {Width}x{Height}", width, height);
_logger.LogDebug("Container height: 80px");
```

### Validar Base64 Antes de Renderizar
```csharp
if (!string.IsNullOrEmpty(base64))
{
    try
    {
        byte[] test = Convert.FromBase64String(base64);
        _logger.LogDebug("Base64 valid, {Bytes} bytes", test.Length);
    }
    catch
    {
        _logger.LogError("Invalid Base64 string");
    }
}
```

---

## 📚 CHEAT SHEET RÁPIDO

| Cenário | Pattern |
|---------|---------|
| **Assinatura 80px altura** | `.Height(80).AlignCenter().AlignMiddle().Image().FitArea()` |
| **Logo responsivo** | `.AlignCenter().Image().FitArea()` |
| **Imagem largura fixa** | `.Width(200).Image().FitWidth()` |
| **Border + Padding** | `.Border(1).BorderColor().Padding(5)` |
| **Espaço entre items** | `.PaddingTop(10)` ou `.PaddingBottom(10)` |
| **Linha horizontal** | `.LineHorizontal(1).LineColor(Colors.Black)` |
| **Texto centralizado** | `.AlignCenter().Text("...")` |
| **Row 2 colunas** | `.RelativeItem()` + `.ConstantItem(espaço)` + `.RelativeItem()` |

---

## 🎯 PATTERNS ESPECÍFICOS DO BIODESKPRO

### Assinatura do Paciente (Base64)
```csharp
if (!string.IsNullOrEmpty(dados.AssinaturaPacienteBase64))
{
    try
    {
        byte[] imageBytes = Convert.FromBase64String(dados.AssinaturaPacienteBase64);
        col.Item()
            .Border(1).BorderColor(Colors.Grey.Lighten2)
            .Padding(5)
            .Height(80)
            .AlignCenter().AlignMiddle()
            .Image(imageBytes)
            .FitArea();
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao renderizar assinatura paciente");
        col.Item().LineHorizontal(1).LineColor(Colors.Black);
    }
}
else
{
    col.Item().LineHorizontal(1).LineColor(Colors.Black);
}
```

### Assinatura do Terapeuta (Path Fixo)
```csharp
string caminhoAssinatura = Path.Combine(
    AppDomain.CurrentDomain.BaseDirectory,
    "Assets", "Images", "assinatura.png"
);

if (File.Exists(caminhoAssinatura))
{
    try
    {
        byte[] assinaturaTerapeuta = File.ReadAllBytes(caminhoAssinatura);
        col.Item()
            .Border(1).BorderColor(Colors.Grey.Lighten2)
            .Padding(5)
            .Height(80)
            .AlignCenter().AlignMiddle()
            .Image(assinaturaTerapeuta)
            .FitArea();
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao carregar assinatura: {Path}", caminhoAssinatura);
        col.Item().LineHorizontal(1).LineColor(Colors.Black);
    }
}
else
{
    _logger.LogWarning("⚠️ Assinatura não encontrada: {Path}", caminhoAssinatura);
    col.Item().LineHorizontal(1).LineColor(Colors.Black);
}
```

---

**✅ DOCUMENTO COMPLETO E TESTADO**

*Baseado em correções reais do projeto BioDeskPro 2.0*
*Última atualização: 2025-10-01*
