# ✅ CONFIGURAÇÃO PDF DE PRESCRIÇÃO - SUCESSO!

## 🎉 STATUS: PDF GERADO COM SUCESSO!

### ✅ O QUE JÁ FUNCIONA:
- Geração de PDF de prescrição
- Tabela de suplementos
- Dados do paciente
- Duração do tratamento (30 dias)
- Abertura automática no visualizador

---

## 📋 PRÓXIMOS PASSOS PARA PERSONALIZAÇÃO:

### 1️⃣ **ADICIONAR LOGO DA CLÍNICA**

**Localização:** `src/BioDesk.App/Assets/Images/logo.png`

**Como adicionar:**
1. Copia a tua imagem de logo (PNG, JPG)
2. Renomeia para `logo.png`
3. Cola em `src/BioDesk.App/Assets/Images/`
4. Clica direito no ficheiro em Visual Studio → Properties → Build Action: **Resource**

---

### 2️⃣ **ADICIONAR ASSINATURA DIGITAL**

**Localização:** `src/BioDesk.App/Assets/Images/assinatura.png`

**Como adicionar:**
1. Cria uma imagem da tua assinatura (PNG transparente recomendado)
2. Renomeia para `assinatura.png`
3. Cola em `src/BioDesk.App/Assets/Images/`
4. Clica direito no ficheiro → Properties → Build Action: **Resource**

---

### 3️⃣ **PERSONALIZAR INFORMAÇÕES DA CLÍNICA**

**Ficheiro:** `src/BioDesk.Services/Pdf/PrescricaoPdfService.cs`

**Linha 111-117:** Alterar texto do cabeçalho
```csharp
column.Item().Text("🌿 BioDeskPro 2.0")  // ← ALTERAR AQUI
    .FontSize(20)
    .Bold()
    .FontColor(Colors.Grey.Darken3);

column.Item().Text("Prescrição de Medicina Complementar")  // ← ALTERAR AQUI
    .FontSize(10)
```

**Exemplo de personalização:**
```csharp
column.Item().Text("NUNO CORREIA")
    .FontSize(20)
    .Bold()
    .FontColor(Colors.Grey.Darken3);

column.Item().Text("Naturopatia & Osteopatia | Tel: 912 345 678")
    .FontSize(10)
```

---

### 4️⃣ **ALTERAR DURAÇÃO DO TRATAMENTO**

**Ficheiro:** `src/BioDesk.Services/Pdf/PrescricaoPdfService.cs`

**Linha ~198:** Alterar "30 dias" para valor dinâmico
```csharp
// ATUAL (fixo):
.Text("⏱ Duração do Tratamento: 30 dias")

// SUGESTÃO (dinâmico):
.Text($"⏱ Duração do Tratamento: {dados.DuracaoTratamento} dias")
```

E adicionar propriedade na classe `DadosPrescricao`:
```csharp
public int DuracaoTratamento { get; set; } = 30;
```

---

## 🔧 CORREÇÕES APLICADAS NESTA SESSÃO:

### ✅ Problema 1: Command Binding não funcionava
**Causa:** Source Generator não estava a criar comando devido a acesso circular
**Solução:** Usar Click handler + Reflexão para invocar método diretamente

### ✅ Problema 2: Modal não aparecia
**Causa:** Visibility hardcoded em "Collapsed"
**Solução:** Binding `Visibility="{Binding MostrarPrescricao, Converter={StaticResource BoolToVis}}"`

### ✅ Problema 3: DataContext não propagava no modal
**Causa:** Inner Border sem DataContext explícito
**Solução:** `DataContext="{Binding DataContext, RelativeSource={RelativeSource AncestorType=UserControl}}"`

### ✅ Problema 4: Erro QuestPDF "multiple child elements"
**Causa:** Container usado múltiplas vezes (Row + BorderBottom no mesmo nível)
**Solução:** Envolver tudo num Column para permitir múltiplos itens

---

## 📁 ESTRUTURA DE ASSETS ESPERADA:

```
src/BioDesk.App/Assets/Images/
├── logo.png           ← Logo da clínica (aparece no modal e PDF)
└── assinatura.png     ← Assinatura digital (aparece no modal e PDF)
```

---

## 🚀 COMANDOS ÚTEIS:

### Recompilar e executar:
```powershell
cd src/BioDesk.App
dotnet run
```

### Verificar erros de build:
```powershell
dotnet build --verbosity normal
```

---

## ⚠️ NOTA IMPORTANTE:

O botão "Gerar PDF" está atualmente a usar **Click handler** em vez de **Command binding** porque o Source Generator do CommunityToolkit.Mvvm teve problemas.

**Código atual (funcional):**
```csharp
private async void BtnGerarPdf_Click(object sender, RoutedEventArgs e)
{
    if (DataContext is RegistoConsultasViewModel vm)
    {
        var method = vm.GetType().GetMethod("GerarPdfPrescricaoAsync", ...);
        await (Task)(method.Invoke(vm, null) ?? Task.CompletedTask);
    }
}
```

Isto é um **workaround temporário** mas **100% funcional**. Futuramente, quando descobrirmos porque o Command binding falha, podemos voltar ao padrão MVVM puro.

---

## 📊 RESULTADO FINAL:

✅ **PDF gerado com sucesso!**
✅ **Abre automaticamente no visualizador**
✅ **Tabela de suplementos funcional**
✅ **Modal com borda vermelha removida (cleanup)**
✅ **Diagnósticos removidos (cleanup)**
✅ **Código limpo e funcional**

🎯 **Próximo passo:** Adicionar logo.png e assinatura.png nas pastas corretas!
