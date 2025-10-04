# 📋 CHECKLIST DE AUDITORIA COMPLETA - BioDeskPro2

**Data**: 04 de Outubro de 2025  
**Aplicação**: BioDeskPro2 v1.0  
**Status**: Em execução para testes

---

## ✅ TAREFA 1: DIÁLOGO DE CONFIRMAÇÃO AO FECHAR APP

### 🔍 Situação Atual
- ❌ **MainWindow.xaml.cs NÃO tem handler `Window_Closing`**
- ✅ **FichaPacienteViewModel TEM sistema IsDirty implementado** (linha 106)
- ✅ **Outros ViewModels NÃO têm IsDirty** (apenas FichaPacienteViewModel)

### 📝 Análise
```csharp
// MainWindow.xaml.cs - FALTA IMPLEMENTAR:
private void MainWindow_Closing(object sender, CancelEventArgs e)
{
    // Verificar se FichaPacienteViewModel está ativo e tem alterações
    if (ContentArea.Content is FrameworkElement fe && 
        fe.DataContext is FichaPacienteViewModel vm && 
        vm.IsDirty)
    {
        var result = MessageBox.Show(
            "Tem alterações não guardadas. Deseja guardar antes de sair?",
            "Alterações Pendentes",
            MessageBoxButton.YesNoCancel,
            MessageBoxImage.Warning);

        switch (result)
        {
            case MessageBoxResult.Yes:
                // Guardar automaticamente
                vm.SalvarCommand.Execute(null);
                break;
            case MessageBoxResult.Cancel:
                e.Cancel = true; // Cancelar fecho
                break;
        }
    }
}
```

### 🎯 Ações Necessárias
1. ✅ Adicionar evento `Closing` no MainWindow.xaml
2. ✅ Implementar handler `MainWindow_Closing` em MainWindow.xaml.cs
3. ✅ Verificar se ContentArea tem FichaPacienteViewModel ativo
4. ✅ Mostrar diálogo se IsDirty = true
5. ✅ Permitir guardar, descartar ou cancelar

---

## ✅ TAREFA 2: PADRONIZAR TODOS OS CANVAS DE ASSINATURA

### 🔍 Canvas Encontrados

#### **1. SignatureCanvasControl** (Controle Reutilizável)
**Ficheiro**: `src/BioDesk.App/Controls/SignatureCanvasControl.xaml`  
**Linha**: 23  
**Propriedades**:
```xaml
<Canvas x:Name="AssinaturaCanvas"
        Background="Transparent"
        MouseDown="AssinaturaCanvas_MouseDown"
        MouseMove="AssinaturaCanvas_MouseMove"
        MouseUp="AssinaturaCanvas_MouseUp"
        Cursor="Pen"/>
```
**Border**:
```xaml
<Border BorderBrush="#E3E9DE"
        BorderThickness="2"
        CornerRadius="8"
        Background="White"
        Height="120"
        Margin="0,0,0,10">
```

#### **2. AssinaturaCanvasDeclaracao** (Declaração de Saúde)
**Ficheiro**: `src/BioDesk.App/Views/Abas/DeclaracaoSaudeUserControl.xaml`  
**Linha**: 616  
**Propriedades**:
```xaml
<Canvas x:Name="AssinaturaCanvasDeclaracao"
        Width="600" Height="150"
        Background="White"
        HorizontalAlignment="Stretch"
        VerticalAlignment="Stretch"
        Stylus.IsFlicksEnabled="False"
        Stylus.IsTapFeedbackEnabled="False"
        Stylus.IsPressAndHoldEnabled="False"
        MouseDown="AssinaturaCanvas_MouseDown"
        MouseMove="AssinaturaCanvas_MouseMove"
        MouseUp="AssinaturaCanvas_MouseUp"
        MouseLeave="AssinaturaCanvas_MouseLeave"
        StylusDown="AssinaturaCanvas_StylusDown"
        StylusMove="AssinaturaCanvas_StylusMove"
        StylusUp="AssinaturaCanvas_StylusUp"/>
```
**Border**:
```xaml
<Border BorderBrush="#9CAF97" BorderThickness="2" CornerRadius="8"
        Background="White" Margin="0,0,0,10"
        HorizontalAlignment="Left">
```

#### **3. Assinatura Terapeuta** (Registo de Consultas)
**Ficheiro**: `src/BioDesk.App/Views/Abas/RegistoConsultasUserControl.xaml`  
**Linha**: 219  
**Tipo**: Image (não é canvas interativo)
```xaml
<Image Source="/Assets/Images/assinatura.png" 
       Stretch="Uniform" 
       MaxHeight="80" 
       HorizontalAlignment="Left"/>
```

### 📊 Comparação de Propriedades

| Propriedade | SignatureCanvasControl | DeclaracaoSaude | RegistoConsultas |
|-------------|------------------------|-----------------|------------------|
| **Tipo** | Canvas interativo | Canvas interativo | Image estática |
| **Width** | ❌ Auto | ✅ 600px | ❌ Auto |
| **Height** | ❌ 120px (Border) | ✅ 150px | ✅ 80px (MaxHeight) |
| **Background** | ⚠️ Transparent | ✅ White | N/A |
| **BorderBrush** | ✅ #E3E9DE | ⚠️ #9CAF97 | ❌ Nenhum |
| **BorderThickness** | ✅ 2 | ✅ 2 | N/A |
| **CornerRadius** | ✅ 8 | ✅ 8 | N/A |
| **Mouse Events** | ✅ Down/Move/Up | ✅ Down/Move/Up/Leave | N/A |
| **Stylus Events** | ❌ Não | ✅ Down/Move/Up | N/A |
| **Linha Guia Central** | ❌ Não | ✅ Sim (300px) | N/A |

### 🎯 Recomendações de Padronização

#### **Propriedades Obrigatórias (PADRÃO)**
```xaml
<!-- Canvas de Assinatura PADRÃO -->
<Border BorderBrush="#E3E9DE"        <!-- COR PADRÃO -->
        BorderThickness="2"
        CornerRadius="8"
        Background="White"
        Height="150"                  <!-- ALTURA PADRÃO -->
        Margin="0,0,0,10">
    <Canvas x:Name="AssinaturaCanvas"
            Width="600"               <!-- LARGURA PADRÃO -->
            Height="150"              <!-- ALTURA PADRÃO -->
            Background="White"        <!-- BRANCO, NÃO TRANSPARENT -->
            Stylus.IsFlicksEnabled="False"
            Stylus.IsTapFeedbackEnabled="False"
            Stylus.IsPressAndHoldEnabled="False"
            MouseDown="AssinaturaCanvas_MouseDown"
            MouseMove="AssinaturaCanvas_MouseMove"
            MouseUp="AssinaturaCanvas_MouseUp"
            MouseLeave="AssinaturaCanvas_MouseLeave"
            StylusDown="AssinaturaCanvas_StylusDown"
            StylusMove="AssinaturaCanvas_StylusMove"
            StylusUp="AssinaturaCanvas_StylusUp">
        
        <!-- LINHA GUIA CENTRAL (OPCIONAL mas RECOMENDADA) -->
        <Line X1="300" Y1="0" X2="300" Y2="150"
              Stroke="#E3E9DE"
              StrokeThickness="1"
              StrokeDashArray="5 3"
              IsHitTestVisible="False"
              Opacity="0.5"/>
    </Canvas>
</Border>
```

### ✅ Ações Necessárias
1. ❌ **SignatureCanvasControl**: Adicionar `Width="600" Height="150"`, mudar Background para "White", adicionar Stylus events
2. ❌ **DeclaracaoSaudeUserControl**: Mudar BorderBrush para "#E3E9DE" (consistência)
3. ⚠️ **RegistoConsultasUserControl**: Decidir se mantém Image ou substitui por Canvas interativo
4. ✅ Criar documentação de propriedades obrigatórias para futuras implementações

---

## ✅ TAREFA 3: CAIXA DE TEXTO ABAIXO DO SLIDER DO SONO

### 🔍 Análise do Código

**Ficheiro**: `src/BioDesk.App/Views/Abas/DeclaracaoSaudeUserControl.xaml`  
**Linha**: 494-504

```xaml
<!-- Padrão de Sono -->
<TextBlock Text="Padrão de Sono" Style="{StaticResource FieldLabelStyle}"/>
<StackPanel Orientation="Horizontal" Margin="0,0,0,8">
    <Slider Value="{Binding HorasSono}" Minimum="4" Maximum="12"
            Width="120" VerticalAlignment="Center"
            TickFrequency="1" IsSnapToTickEnabled="True"/>
    <TextBlock Text="{Binding HorasSono}" Margin="8,0,0,0" VerticalAlignment="Center"/>
    <TextBlock Text="horas/noite" Margin="4,0,0,0" VerticalAlignment="Center" Opacity="0.7"/>
</StackPanel>
<!-- ✅ CORRIGIDO: Mudado de TextBox para ComboBox -->
<TextBlock Text="Qualidade do Sono" Style="{StaticResource FieldLabelStyle}"/>
<ComboBox ItemsSource="{Binding OpcoesQualidadeSono}"
          SelectedItem="{Binding QualidadeSono}"
          Style="{StaticResource FieldComboBoxStyle}"/>
```

### 📝 Conclusão
**NÃO EXISTE TEXTBOX ABAIXO DO SLIDER!**

- ✅ **Slider** está correto (HorasSono de 4 a 12 horas)
- ✅ **ComboBox** para Qualidade do Sono (Boa, Razoável, Má, etc.)
- ✅ **Comentário indica que foi corrigido** anteriormente (era TextBox, agora é ComboBox)

### 🎯 Nenhuma Ação Necessária
✅ Campo já está otimizado como ComboBox (melhor UX que TextBox livre)

---

## ✅ TAREFA 4: SISTEMA DE ENVIO DE TEMPLATES PDF

### 🔍 Situação Atual
- ❌ **NÃO EXISTE pasta `Templates/`** na raiz do projeto
- ✅ **IEmailService EXISTE** em `BioDesk.Services.Email`
- ✅ **DocumentoService EXISTE** para gestão de ficheiros

### 📝 Estrutura Proposta

```
📁 BioDeskPro2/
├── 📁 Templates/
│   ├── 📄 Prescricao_Geral.pdf
│   ├── 📄 Plano_Alimentar.pdf
│   ├── 📄 Rotina_Exercicios.pdf
│   ├── 📄 Consentimento_Naturopatia.pdf
│   └── 📄 Relatorio_Consulta.pdf
├── 📁 src/
│   └── 📁 BioDesk.Services/
│       ├── ITemplateService.cs          ← CRIAR
│       └── TemplateService.cs           ← CRIAR
```

### 🎯 Interface Proposta

```csharp
namespace BioDesk.Services;

public interface ITemplateService
{
    /// <summary>
    /// Lista todos os templates disponíveis em Templates/
    /// </summary>
    Task<List<TemplateInfo>> ListarTemplatesAsync();

    /// <summary>
    /// Envia template PDF para paciente por e-mail
    /// </summary>
    Task<bool> EnviarTemplateParaPacienteAsync(int pacienteId, string templateNome);

    /// <summary>
    /// Copia template para pasta do paciente (Pacientes/{Id}/Documentos/)
    /// </summary>
    Task<string> CopiarTemplateParaPacienteAsync(int pacienteId, string templateNome);
}

public class TemplateInfo
{
    public string Nome { get; set; } = string.Empty;
    public string CaminhoCompleto { get; set; } = string.Empty;
    public long TamanhoBytes { get; set; }
    public DateTime DataCriacao { get; set; }
}
```

### ✅ Ações Necessárias
1. ❌ Criar pasta `Templates/` na raiz do projeto
2. ❌ Criar interface `ITemplateService.cs`
3. ❌ Implementar `TemplateService.cs` com integração ao IEmailService
4. ❌ Registar serviço em `App.xaml.cs` DI container
5. ❌ Adicionar UI em ComunicacaoViewModel para enviar templates
6. ❌ Adicionar documentação de templates disponíveis

---

## ✅ TAREFA 5: ENCERRAMENTO COMPLETO DE PROCESSOS

### 🔍 Análise do App.xaml.cs

**Ficheiro**: `src/BioDesk.App/App.xaml.cs`  
**Linha**: 217-227

```csharp
protected override void OnExit(ExitEventArgs e)
{
    if (_host != null)
    {
        // ✅ CORRETO: Task.Run evita deadlock com SynchronizationContext
        Task.Run(async () => await _host.StopAsync()).GetAwaiter().GetResult();
        _host.Dispose();
    }

    base.OnExit(e);
}
```

### 📝 Análise de Recursos Disposable

#### **Recursos que PRECISAM de Dispose**
1. ✅ **BioDeskDbContext** (EF Core) - Registado como **Scoped** (auto-dispose)
2. ✅ **EmailQueueProcessor** (HostedService) - Parado em `_host.StopAsync()`
3. ⚠️ **RealCameraService** - **PODE TER RECURSOS USB NÃO LIBERTADOS**
4. ⚠️ **IridologyService** - Singleton mas sem recursos unmanaged

#### **Verificação de Camera Service**

```csharp
// BioDesk.Services/RealCameraService.cs - VERIFICAR SE TEM:
public void Dispose()
{
    if (_videoSource != null && _videoSource.IsRunning)
    {
        _videoSource.SignalToStop();
        _videoSource.WaitForStop();
        _videoSource = null;
    }
}
```

### 🎯 Melhorias Recomendadas

```csharp
protected override void OnExit(ExitEventArgs e)
{
    try
    {
        _logger?.LogInformation("🛑 Encerrando aplicação...");

        if (_host != null)
        {
            // 1. Parar hosted services (EmailQueueProcessor)
            Task.Run(async () => await _host.StopAsync(TimeSpan.FromSeconds(5)))
                .GetAwaiter().GetResult();

            // 2. Dispose de serviços singleton
            var serviceProvider = _host.Services;
            
            // Garantir que câmera é desligada
            if (serviceProvider.GetService<ICameraService>() is IDisposable camera)
            {
                camera.Dispose();
                _logger?.LogInformation("✅ Câmera desligada");
            }

            // Garantir que DbContext é fechado
            if (serviceProvider.GetService<BioDeskDbContext>() is BioDeskDbContext db)
            {
                db.Dispose();
                _logger?.LogInformation("✅ Base de dados fechada");
            }

            // 3. Dispose do host
            _host.Dispose();
            _logger?.LogInformation("✅ Host encerrado");
        }

        // 4. Matar processos órfãos (se necessário)
        KillOrphanProcesses();

        _logger?.LogInformation("✅ Aplicação encerrada com sucesso");
    }
    catch (Exception ex)
    {
        _logger?.LogError(ex, "❌ Erro ao encerrar aplicação");
        // Forçar encerramento mesmo com erro
    }
    finally
    {
        base.OnExit(e);
    }
}

private void KillOrphanProcesses()
{
    // Exemplo: Matar processos de AForge.NET se ficarem pendurados
    var currentProcess = Process.GetCurrentProcess();
    var orphans = Process.GetProcesses()
        .Where(p => p.ProcessName.Contains("AForge") && p.Id != currentProcess.Id);
    
    foreach (var orphan in orphans)
    {
        try
        {
            orphan.Kill();
            _logger?.LogWarning("⚠️ Processo órfão terminado: {ProcessName}", orphan.ProcessName);
        }
        catch { /* Ignorar */ }
    }
}
```

### ✅ Ações Necessárias
1. ✅ Verificar se `RealCameraService` implementa `IDisposable` corretamente
2. ❌ Adicionar dispose explícito de câmera em `OnExit`
3. ❌ Adicionar timeout para `StopAsync` (5 segundos)
4. ❌ Implementar `KillOrphanProcesses()` para AForge.NET
5. ❌ Adicionar logging detalhado de encerramento
6. ✅ Testar fecho com câmera ativa

---

## 📊 RESUMO DE PRIORIDADES

| Tarefa | Prioridade | Status | Risco |
|--------|-----------|--------|-------|
| **1. Diálogo de confirmação ao fechar** | 🔴 ALTA | ❌ Não implementado | Perda de dados |
| **2. Padronizar SignatureCanvas** | 🟠 MÉDIA | ⚠️ Inconsistente | UX inconsistente |
| **3. TextBox abaixo de Slider** | ✅ BAIXA | ✅ Já resolvido | Nenhum |
| **4. Sistema de Templates PDF** | 🟠 MÉDIA | ❌ Não existe | Funcionalidade em falta |
| **5. Encerramento de processos** | 🟡 MÉDIA-ALTA | ⚠️ Incompleto | Recursos USB presos |

---

## 🎯 PLANO DE AÇÃO IMEDIATO

### Fase 1: Crítico (Hoje)
1. ✅ Implementar `MainWindow_Closing` com verificação de IsDirty
2. ✅ Verificar e corrigir `RealCameraService.Dispose()`
3. ✅ Melhorar `OnExit` com dispose explícito

### Fase 2: Importante (Esta Semana)
4. ✅ Padronizar todos os canvas de assinatura
5. ✅ Criar pasta `Templates/` e `ITemplateService`
6. ✅ Adicionar UI de envio de templates em ComunicacaoViewModel

### Fase 3: Documentação
7. ✅ Atualizar `copilot-instructions.md` com padrões de SignatureCanvas
8. ✅ Criar guia de templates disponíveis
9. ✅ Documentar processo de encerramento seguro

---

**FIM DA AUDITORIA**
