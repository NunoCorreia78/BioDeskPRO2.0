# 📝 SignatureCanvasControl - Guia de Uso

## 📋 Descrição
UserControl reutilizável para captura de assinatura digital em WPF. Converte a assinatura desenhada para imagem PNG em Base64, pronta para ser incluída em PDFs ou armazenada.

## 🎯 Funcionalidades
- ✍️ Desenho livre com mouse ou toque
- 🗑️ Botão de limpar canvas
- ✅ Botão de confirmar assinatura
- 🖼️ Conversão automática para PNG Base64
- 📢 Evento `SignatureConfirmed` com assinatura capturada

---

## 🚀 Como Usar

### 1. Adicionar ao XAML

```xaml
<Window ...
        xmlns:controls="clr-namespace:BioDesk.App.Controls">

    <StackPanel>
        <controls:SignatureCanvasControl 
            x:Name="SignatureCanvas"
            SignatureConfirmed="SignatureCanvas_SignatureConfirmed"/>
    </StackPanel>
</Window>
```

### 2. Subscrever ao Evento (Code-Behind)

```csharp
using BioDesk.App.Controls;

namespace MyApp
{
    public partial class MyWindow : Window
    {
        private string? _assinaturaBase64;

        public MyWindow()
        {
            InitializeComponent();
        }

        private void SignatureCanvas_SignatureConfirmed(object sender, SignatureConfirmedEventArgs e)
        {
            // Guardar assinatura capturada
            _assinaturaBase64 = e.SignatureBase64;
            
            // Usar na geração de PDF, por exemplo
            GerarPdfComAssinatura(_assinaturaBase64);
        }

        private void GerarPdfComAssinatura(string assinaturaBase64)
        {
            // Exemplo: usar com DeclaracaoSaudePdfService
            var dados = new DadosDeclaracaoSaude
            {
                NomePaciente = "João Silva",
                AssinaturaPacienteBase64 = assinaturaBase64,
                // ... outros campos
            };

            var pdfService = new DeclaracaoSaudePdfService(logger);
            string caminhoP df = pdfService.GerarPdfDeclaracaoSaude(dados);
            pdfService.AbrirPdf(caminhoPdf);
        }
    }
}
```

---

## 🎨 Personalização

### Alterar Cor da Caneta
Editar `SignatureCanvasControl.xaml.cs`, linha ~48:

```csharp
Stroke = new SolidColorBrush(Color.FromRgb(63, 74, 61)), // Sua cor RGB
```

### Alterar Espessura do Traço
Editar `SignatureCanvasControl.xaml.cs`, linha ~49:

```csharp
StrokeThickness = 2.5, // Sua espessura
```

### Alterar Altura do Canvas
Editar `SignatureCanvasControl.xaml`, linha ~26:

```xaml
Height="120" <!-- Sua altura -->
```

---

## 📖 API Pública

### Eventos

#### `SignatureConfirmed`
Disparado quando o usuário clica em "✅ Confirmar Assinatura".

**Argumentos:**
```csharp
public class SignatureConfirmedEventArgs : EventArgs
{
    public string SignatureBase64 { get; } // PNG Base64
}
```

### Métodos

#### `LimparAssinatura()`
Limpa o canvas e reseta o estado.

```csharp
SignatureCanvas.LimparAssinatura();
```

#### `TemAssinatura()` → `bool`
Verifica se há assinatura desenhada no canvas.

```csharp
if (SignatureCanvas.TemAssinatura())
{
    // Canvas tem conteúdo
}
```

---

## 🔗 Integração com PDF Services

### DeclaracaoSaudePdfService

```csharp
private void SignatureCanvas_SignatureConfirmed(object sender, SignatureConfirmedEventArgs e)
{
    var dados = new DadosDeclaracaoSaude
    {
        NomePaciente = pacienteAtual.NomeCompleto,
        AssinaturaPacienteBase64 = e.SignatureBase64, // ⬅️ Assinatura capturada
        MotivoConsulta = "...",
        HistoriaClinica = "...",
        // ... outros campos
    };

    var pdfService = serviceProvider.GetRequiredService<DeclaracaoSaudePdfService>();
    string caminhoPdf = pdfService.GerarPdfDeclaracaoSaude(dados);
    pdfService.AbrirPdf(caminhoPdf);
}
```

### ConsentimentoPdfService

```csharp
private void SignatureCanvas_SignatureConfirmed(object sender, SignatureConfirmedEventArgs e)
{
    var dados = new DadosConsentimento
    {
        NomePaciente = pacienteAtual.NomeCompleto,
        TipoTratamento = "Naturopatia",
        DescricaoTratamento = "...",
        AssinaturaDigitalBase64 = e.SignatureBase64, // ⬅️ Assinatura capturada
        // ... outros campos
    };

    var pdfService = serviceProvider.GetRequiredService<ConsentimentoPdfService>();
    string caminhoPdf = pdfService.GerarPdfConsentimento(dados);
    pdfService.AbrirPdf(caminhoPdf);
}
```

---

## ⚠️ Notas Importantes

1. **Formato da Assinatura:** PNG Base64 pronto para uso direto
2. **Tamanho do Canvas:** 600x120 pixels por padrão (ajustável no XAML)
3. **Resolução:** 96 DPI (adequado para PDFs)
4. **Limpeza Automática:** Canvas limpa automaticamente após confirmação
5. **Validação:** Botão "Confirmar" só ativa quando há traços desenhados

---

## 🐛 Troubleshooting

### Assinatura não aparece no PDF
- Verificar se `AssinaturaBase64` não está vazio
- Confirmar que o serviço PDF está a usar o campo correto

### Canvas não responde ao mouse
- Verificar se `Background="Transparent"` está no Canvas
- Confirmar que eventos MouseDown/Move/Up estão registados

### Imagem PNG corrompida
- Verificar se `ActualWidth` e `ActualHeight` do Canvas são > 0
- Usar `RenderTargetBitmap` com DPI correto (96)

---

## 📊 Exemplo Completo (MVVM)

### ViewModel

```csharp
public class DeclaracaoSaudeViewModel : ObservableObject
{
    [ObservableProperty]
    private string? _assinaturaPacienteBase64;

    [RelayCommand]
    private async Task GerarPdfAsync()
    {
        if (string.IsNullOrEmpty(AssinaturaPacienteBase64))
        {
            MessageBox.Show("Por favor, assine o documento primeiro.");
            return;
        }

        var dados = new DadosDeclaracaoSaude
        {
            NomePaciente = NomePaciente,
            AssinaturaPacienteBase64 = AssinaturaPacienteBase64,
            // ... outros campos do questionário
        };

        var pdfService = _serviceProvider.GetRequiredService<DeclaracaoSaudePdfService>();
        string caminhoPdf = pdfService.GerarPdfDeclaracaoSaude(dados);
        pdfService.AbrirPdf(caminhoPdf);
    }
}
```

### View

```xaml
<UserControl xmlns:controls="clr-namespace:BioDesk.App.Controls"
             DataContext="{Binding DeclaracaoSaudeViewModel}">
    
    <StackPanel>
        <!-- Questionário de saúde -->
        <TextBox Text="{Binding MotivoConsulta}"/>
        <!-- ... outros campos -->

        <!-- Canvas de Assinatura -->
        <controls:SignatureCanvasControl 
            x:Name="SignatureCanvas"
            SignatureConfirmed="OnSignatureConfirmed"/>

        <!-- Botão Gerar PDF -->
        <Button Content="📄 Gerar PDF"
                Command="{Binding GerarPdfCommand}"/>
    </StackPanel>
</UserControl>
```

### Code-Behind

```csharp
private void OnSignatureConfirmed(object sender, SignatureConfirmedEventArgs e)
{
    var viewModel = (DeclaracaoSaudeViewModel)DataContext;
    viewModel.AssinaturaPacienteBase64 = e.SignatureBase64;
}
```

---

## 📦 Ficheiros do Componente

- `SignatureCanvasControl.xaml` - Layout do controlo
- `SignatureCanvasControl.xaml.cs` - Lógica de captura
- `SignatureConfirmedEventArgs.cs` - Argumentos do evento (inline)

---

## ✅ Checklist de Uso

□ Adicionar `xmlns:controls` no XAML  
□ Adicionar `<controls:SignatureCanvasControl>` na view  
□ Subscrever ao evento `SignatureConfirmed`  
□ Guardar `e.SignatureBase64` numa variável/propriedade  
□ Passar Base64 para o PDF Service  
□ Testar geração de PDF com assinatura  

---

**Criado:** 01 de Outubro de 2025  
**Versão:** 1.0  
**Autor:** BioDeskPro2 Development Team
