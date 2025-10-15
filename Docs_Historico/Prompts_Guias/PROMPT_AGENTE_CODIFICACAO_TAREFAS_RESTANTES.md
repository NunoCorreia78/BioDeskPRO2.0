# 🤖 PROMPT PARA AGENTE DE CODIFICAÇÃO - TAREFAS RESTANTES

**Data**: 07 de Outubro de 2025
**Projeto**: BioDeskPro2 - Sistema de Gestão Médica
**Branch**: main
**Último Commit**: `39ba159` - Dashboard 4x2 final + Validações nullable DateTime

---

## 🎯 OBJETIVO GERAL

Completar as tarefas pendentes do sistema BioDeskPro2 E realizar auditoria completa do código para identificar e corrigir:
- Duplicações
- Redundâncias
- Dead code
- Padrões inconsistentes
- Otimizações possíveis

---

## ⚠️ REGRAS CRÍTICAS - LER ANTES DE COMEÇAR

### 🚨 PRINCÍPIO FUNDAMENTAL
**"Se está a funcionar e os testes passam, NÃO ALTERES!"**

### ✅ PODE FAZER
- ✅ Adicionar NOVAS funcionalidades (botão eliminar, tabs configurações)
- ✅ Remover código CLARAMENTE duplicado (copiar-colar evidente)
- ✅ Consolidar métodos com 100% de código idêntico
- ✅ Remover `using` statements não utilizados
- ✅ Atualizar comentários obsoletos

### ❌ NÃO PODE FAZER
- ❌ "Refatorar" código que funciona perfeitamente
- ❌ Alterar arquitetura MVVM existente (está funcional)
- ❌ Mudar padrões de naming que já estão estabelecidos
- ❌ Tocar em ViewModels que estão funcionais
- ❌ Alterar bindings XAML que funcionam

### 🛡️ VERIFICAÇÃO OBRIGATÓRIA
Antes de CADA alteração:
```bash
# 1. Build limpo ANTES
dotnet clean
dotnet build --no-incremental

# 2. Fazer alteração

# 3. Build limpo DEPOIS
dotnet clean
dotnet build --no-incremental

# 4. SE FALHAR → REVERTER IMEDIATAMENTE
```

---

## 📋 TAREFAS PRIORITÁRIAS (EM ORDEM)

### 🔴 PRIORIDADE MÁXIMA

#### ✅ TAREFA 1: Botão Eliminar na Lista de Pacientes
**Status**: ❌ NÃO FEITO
**Tempo Estimado**: 20 minutos
**Risco**: BAIXO (adiciona funcionalidade nova)

**Implementação**:

1. **Ficheiro**: `src/BioDesk.App/Views/ListaPacientesView.xaml`

```xaml
<!-- Adicionar APÓS as colunas existentes, ANTES de </DataGrid> -->
<DataGridTemplateColumn Header="Ações" Width="120" IsReadOnly="True">
    <DataGridTemplateColumn.CellTemplate>
        <DataTemplate>
            <Button Content="🗑️ Eliminar"
                    Command="{Binding DataContext.EliminarPacienteCommand,
                              RelativeSource={RelativeSource AncestorType=DataGrid}}"
                    CommandParameter="{Binding}"
                    Background="#EF4444"
                    Foreground="White"
                    Padding="10,5"
                    BorderThickness="0"
                    Cursor="Hand"
                    ToolTip="Eliminar paciente da base de dados (IRREVERSÍVEL!)">
                <Button.Style>
                    <Style TargetType="Button">
                        <Setter Property="Opacity" Value="1"/>
                        <Style.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#DC2626"/>
                            </Trigger>
                        </Style.Triggers>
                    </Style>
                </Button.Style>
            </Button>
        </DataTemplate>
    </DataGridTemplateColumn.CellTemplate>
</DataGridTemplateColumn>
```

2. **Ficheiro**: `src/BioDesk.ViewModels/ListaPacientesViewModel.cs`

```csharp
// Adicionar APÓS os comandos existentes
[RelayCommand]
private async Task EliminarPaciente(Paciente? paciente)
{
    if (paciente == null)
    {
        _logger.LogWarning("⚠️ Tentativa de eliminar paciente nulo");
        return;
    }

    // Diálogo de confirmação OBRIGATÓRIO
    var result = MessageBox.Show(
        $"Tem a certeza que deseja eliminar o paciente:\n\n" +
        $"👤 {paciente.NomeCompleto}\n" +
        $"📋 Processo: {paciente.NumeroProcesso}\n\n" +
        $"⚠️ ATENÇÃO: Esta ação é IRREVERSÍVEL!\n" +
        $"Todos os dados associados (consultas, emails, documentos) serão perdidos.",
        "⚠️ Confirmar Eliminação",
        MessageBoxButton.YesNo,
        MessageBoxImage.Warning,
        MessageBoxResult.No);

    if (result == MessageBoxResult.Yes)
    {
        try
        {
            IsLoading = true;
            _logger.LogWarning("🗑️ Eliminando paciente {Id}: {Nome}", paciente.Id, paciente.NomeCompleto);

            // Eliminar da BD via repository
            await _unitOfWork.Pacientes.DeleteAsync(paciente.Id);
            await _unitOfWork.SaveChangesAsync();

            // Remover da ObservableCollection
            Pacientes.Remove(paciente);

            _logger.LogInformation("✅ Paciente {Nome} eliminado com sucesso", paciente.NomeCompleto);

            MessageBox.Show(
                $"Paciente '{paciente.NomeCompleto}' eliminado com sucesso.",
                "✅ Eliminação Concluída",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Erro ao eliminar paciente {Id}", paciente.Id);

            MessageBox.Show(
                $"Erro ao eliminar paciente:\n\n{ex.Message}",
                "❌ Erro de Eliminação",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            IsLoading = false;
        }
    }
    else
    {
        _logger.LogInformation("ℹ️ Eliminação de paciente cancelada pelo utilizador");
    }
}
```

**Verificação**:
```bash
# 1. Build
dotnet build

# 2. Executar aplicação
dotnet run --project src/BioDesk.App

# 3. Testar:
#    - Ir para Lista Pacientes
#    - Ver coluna "Ações" com botão vermelho "🗑️ Eliminar"
#    - Clicar → Deve aparecer diálogo de confirmação
#    - Clicar "Não" → Nada acontece
#    - Clicar "Sim" → Paciente desaparece da lista + mensagem sucesso
```

---

#### ✅ TAREFA 2: Tabs Configurações com Templates PDF
**Status**: ❌ NÃO FEITO
**Tempo Estimado**: 45 minutos
**Risco**: MÉDIO (altera View de Configurações)

**Implementação**:

1. **Ficheiro**: `src/BioDesk.App/Views/ConfiguracoesView.xaml`

**OBJETIVO**: Criar sistema de tabs verticais com 4 secções:
- 📧 Email (já existe)
- 📄 Templates PDF (NOVO)
- 🎨 Preferências (NOVO)
- 🔧 Sistema (NOVO)

**ATENÇÃO**:
- ⚠️ **NÃO APAGAR** o conteúdo existente da tab Email!
- ⚠️ **MANTER** todos os campos EmailRemetente, Password, etc.
- ✅ **ADICIONAR** apenas as novas tabs

```xaml
<!-- SUBSTITUIR o Grid existente por este TabControl -->
<TabControl TabStripPlacement="Left" Margin="20">
    <TabControl.Resources>
        <Style TargetType="TabItem">
            <Setter Property="HeaderTemplate">
                <Setter.Value>
                    <DataTemplate>
                        <TextBlock Text="{Binding}"
                                   FontSize="14"
                                   Padding="20,15"/>
                    </DataTemplate>
                </Setter.Value>
            </Setter>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderBrush" Value="#E3E9DE"/>
            <Setter Property="BorderThickness" Value="0,0,1,0"/>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#9CAF97"/>
                    <Setter Property="Foreground" Value="White"/>
                    <Setter Property="FontWeight" Value="SemiBold"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </TabControl.Resources>

    <!-- TAB 1: EMAIL (MANTER CONTEÚDO EXISTENTE!) -->
    <TabItem Header="📧 Email">
        <!-- ⚠️ COPIAR AQUI o conteúdo atual da ConfiguracoesView.xaml -->
        <!-- TODOS os StackPanels com EmailRemetente, Password, etc. -->
    </TabItem>

    <!-- TAB 2: TEMPLATES PDF (NOVO) -->
    <TabItem Header="📄 Templates PDF">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="30">
                <TextBlock Text="📄 Gestão de Templates PDF"
                           FontSize="20"
                           FontWeight="SemiBold"
                           Foreground="#3F4A3D"
                           Margin="0,0,0,20"/>

                <TextBlock Text="Templates disponíveis para prescrições e documentos"
                           FontSize="13"
                           Foreground="#5A6558"
                           Margin="0,0,0,30"/>

                <!-- Botão Adicionar Novo Template -->
                <Button Command="{Binding AdicionarNovoTemplatePdfCommand}"
                        Background="#9CAF97"
                        Foreground="White"
                        Padding="15,10"
                        Margin="0,0,0,20"
                        HorizontalAlignment="Left"
                        ToolTip="Copiar ficheiro PDF para a pasta Templates">
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="➕" FontSize="16" Margin="0,0,8,0"/>
                        <TextBlock Text="Adicionar Template PDF" FontSize="14"/>
                    </StackPanel>
                </Button>

                <!-- Lista de Templates (binding futuro) -->
                <Border Background="White"
                        BorderBrush="#E3E9DE"
                        BorderThickness="1"
                        CornerRadius="8"
                        Padding="20">
                    <StackPanel>
                        <TextBlock Text="📂 Templates Encontrados:"
                                   FontWeight="SemiBold"
                                   Margin="0,0,0,10"/>

                        <!-- TODO: Adicionar ListBox com binding a TemplatesPdf -->
                        <TextBlock Text="(Lista de templates será implementada em versão futura)"
                                   FontStyle="Italic"
                                   Foreground="#999"/>
                    </StackPanel>
                </Border>
            </StackPanel>
        </ScrollViewer>
    </TabItem>

    <!-- TAB 3: PREFERÊNCIAS (NOVO) -->
    <TabItem Header="🎨 Preferências">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="30">
                <TextBlock Text="🎨 Preferências do Sistema"
                           FontSize="20"
                           FontWeight="SemiBold"
                           Foreground="#3F4A3D"
                           Margin="0,0,0,20"/>

                <TextBlock Text="(Funcionalidades futuras: Temas, Idioma, Formato de Data)"
                           FontStyle="Italic"
                           Foreground="#999"/>
            </StackPanel>
        </ScrollViewer>
    </TabItem>

    <!-- TAB 4: SISTEMA (NOVO) -->
    <TabItem Header="🔧 Sistema">
        <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="30">
                <TextBlock Text="🔧 Informações do Sistema"
                           FontSize="20"
                           FontWeight="SemiBold"
                           Foreground="#3F4A3D"
                           Margin="0,0,0,20"/>

                <!-- Informações de Versão -->
                <Border Background="White"
                        BorderBrush="#E3E9DE"
                        BorderThickness="1"
                        CornerRadius="8"
                        Padding="20"
                        Margin="0,0,0,15">
                    <StackPanel>
                        <TextBlock Text="💻 Versão"
                                   FontWeight="SemiBold"
                                   Margin="0,0,0,10"/>
                        <TextBlock Text="BioDeskPro2 v1.0.0"
                                   FontSize="14"/>
                        <TextBlock Text=".NET 8.0 | WPF | SQLite"
                                   FontSize="12"
                                   Foreground="#999"
                                   Margin="0,5,0,0"/>
                    </StackPanel>
                </Border>

                <!-- Base de Dados -->
                <Border Background="White"
                        BorderBrush="#E3E9DE"
                        BorderThickness="1"
                        CornerRadius="8"
                        Padding="20">
                    <StackPanel>
                        <TextBlock Text="💾 Base de Dados"
                                   FontWeight="SemiBold"
                                   Margin="0,0,0,10"/>
                        <TextBlock Text="biodesk.db (SQLite)"
                                   FontSize="14"/>
                        <Button Content="📂 Abrir Pasta"
                                Padding="10,5"
                                HorizontalAlignment="Left"
                                Margin="0,10,0,0"
                                ToolTip="Abrir pasta com ficheiro da base de dados"/>
                    </StackPanel>
                </Border>
            </StackPanel>
        </ScrollViewer>
    </TabItem>
</TabControl>
```

2. **Ficheiro**: `src/BioDesk.ViewModels/ConfiguracoesViewModel.cs`

```csharp
// Adicionar comando para Templates PDF
[RelayCommand]
private async Task AdicionarNovoTemplatePdf()
{
    try
    {
        // OpenFileDialog para selecionar PDF
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Selecionar Template PDF",
            Filter = "Ficheiros PDF (*.pdf)|*.pdf",
            Multiselect = false
        };

        if (dialog.ShowDialog() == true)
        {
            // Copiar para pasta Templates
            var templatesFolder = Path.Combine(
                AppDomain.CurrentDomain.BaseDirectory,
                "Templates");

            Directory.CreateDirectory(templatesFolder);

            var fileName = Path.GetFileName(dialog.FileName);
            var destinationPath = Path.Combine(templatesFolder, fileName);

            File.Copy(dialog.FileName, destinationPath, overwrite: true);

            _logger.LogInformation("✅ Template PDF copiado: {FileName}", fileName);

            MessageBox.Show(
                $"Template '{fileName}' adicionado com sucesso!",
                "✅ Template Adicionado",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, "❌ Erro ao adicionar template PDF");
        MessageBox.Show(
            $"Erro ao adicionar template:\n\n{ex.Message}",
            "❌ Erro",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }
}
```

**Verificação**:
```bash
# 1. Build
dotnet build

# 2. Executar
dotnet run --project src/BioDesk.App

# 3. Testar:
#    - Dashboard → Botão "⚙️ Configurações"
#    - Ver 4 tabs verticais à esquerda (Email, Templates PDF, Preferências, Sistema)
#    - Clicar cada tab → conteúdo muda
#    - Tab "Templates PDF" → Botão "➕ Adicionar Template PDF"
#    - Clicar botão → Abrir diálogo de ficheiro
#    - Selecionar PDF → Copiar para pasta Templates + mensagem sucesso
```

---

### 🟡 PRIORIDADE MÉDIA

#### ✅ TAREFA 3: Auditoria de Duplicações e Redundâncias
**Status**: ❌ NÃO FEITO
**Tempo Estimado**: 1-2 horas
**Risco**: ALTO (pode quebrar funcionalidades)

**⚠️ ATENÇÃO CRÍTICA**:
- Esta tarefa é **DELICADA** e requer **PRUDÊNCIA MÁXIMA**
- Cada alteração deve ser **testada individualmente**
- Se algo quebrar → **REVERTER IMEDIATAMENTE**

**Procedimento OBRIGATÓRIO**:

1. **IDENTIFICAÇÃO** (NÃO ALTERAR AINDA)
```bash
# Procurar duplicações óbvias
cd src/BioDesk.ViewModels
grep -r "ExecuteWithErrorHandlingAsync" .

# Procurar using statements não utilizados
# (VS Code já indica com cinzento)
```

2. **CATEGORIZAÇÃO**
   - ✅ **SEGURO REMOVER**:
     * `using` statements cinzentos não utilizados
     * Comentários obsoletos com datas antigas
     * Ficheiros `.bak` ou `.old`

   - ⚠️ **AVALIAR CUIDADOSAMENTE**:
     * Métodos aparentemente duplicados (podem ter diferenças subtis!)
     * ViewModels com código similar (podem ter contextos diferentes)

   - ❌ **NÃO TOCAR**:
     * Código que funciona e tem testes a passar
     * ViewModels estabelecidos (DashboardViewModel, FichaPacienteViewModel)
     * Converters XAML (podem ser usados em múltiplos lugares)

3. **ALTERAÇÕES SEGURAS** (fazer UMA de cada vez):

**3.1. Remover `using` não utilizados**
```csharp
// VS Code mostra em cinzento - pode apagar com segurança
// Exemplo em FichaPacienteViewModel.cs:
// using System.IO;  // ← Se cinzento, apagar
```

**3.2. Consolidar `ExecuteWithErrorHandlingAsync`**
```csharp
// SE encontrar este método duplicado em múltiplos ViewModels:
// → Mover para ViewModelBase (se não existe lá)
// → Remover duplicatas

// ANTES (em FichaPacienteViewModel.cs):
private async Task ExecuteWithErrorHandlingAsync(...)
{
    // ... implementação ...
}

// DEPOIS:
// Remover de FichaPacienteViewModel
// Garantir que existe em ViewModelBase
```

**3.3. Remover Comentários Obsoletos**
```csharp
// PODE REMOVER comentários tipo:
// TODO: Implementar validação (← SE JÁ ESTÁ IMPLEMENTADO)
// FIXME: Corrigir bug X (← SE JÁ ESTÁ CORRIGIDO)
// Versão antiga comentada (← SE NOVO CÓDIGO FUNCIONA)
```

**VERIFICAÇÃO APÓS CADA ALTERAÇÃO**:
```bash
# 1. Build
dotnet build

# 2. SE FALHAR:
git restore <ficheiro alterado>

# 3. SE PASSAR:
# Testar funcionalidade relacionada MANUALMENTE
# Só fazer commit se tudo funcionar
```

4. **RELATÓRIO FINAL**
Criar ficheiro `AUDITORIA_CODIGO_COMPLETA.md` com:
```markdown
# 🔍 AUDITORIA DE CÓDIGO COMPLETA

## Resumo
- **Ficheiros Analisados**: X
- **Alterações Seguras Aplicadas**: Y
- **Duplicações Identificadas (Não Alteradas)**: Z

## Alterações Aplicadas
### Using Statements Removidos
- `FichaPacienteViewModel.cs`: 3 usings não utilizados
- `DashboardViewModel.cs`: 1 using não utilizado

### Comentários Obsoletos Removidos
- 5 TODOs já implementados
- 2 FIXMEs já corrigidos

## Duplicações Identificadas (NÃO ALTERADAS - Requerem Análise)
1. **`ValidarNIF()` em múltiplos ViewModels**
   - Localização: FichaPacienteViewModel.cs, NovoPacienteViewModel.cs
   - Motivo para não consolidar: Pode ter regras de negócio diferentes
   - Recomendação: Avaliar se faz sentido criar um `NifValidator` separado

## Build Status
✅ Build passou após todas as alterações
✅ Aplicação executa sem erros
✅ Funcionalidades testadas: [lista]
```

---

## 🧪 CHECKLIST DE VERIFICAÇÃO FINAL

Antes de considerar QUALQUER tarefa como concluída:

```bash
# 1. BUILD LIMPO
dotnet clean
dotnet build --no-incremental --verbosity normal

# Resultado esperado: 0 Errors, ~39 Warnings (apenas AForge)
```

```bash
# 2. EXECUTAR APLICAÇÃO
dotnet run --project src/BioDesk.App

# Resultado esperado: Dashboard abre sem exceções
```

```bash
# 3. TESTAR FUNCIONALIDADES CRÍTICAS
# - Dashboard → Ver estatísticas corretas
# - Novo Paciente → Criar e guardar
# - Lista Pacientes → Ver lista + pesquisar
# - [SE TAREFA 1] Eliminar paciente → Confirmar funciona
# - [SE TAREFA 2] Configurações → Ver tabs + adicionar template
```

```bash
# 4. VERIFICAR INTELLISENSE
# - Abrir ficheiros .cs no VS Code
# - NENHUM squiggle vermelho deve aparecer
# - Warnings são OK (AForge compatibility)
```

```bash
# 5. COMMIT INCREMENTAL
git add <ficheiros alterados>
git commit -m "✅ [Tarefa X]: Descrição curta"
git push
```

---

## 📊 ORDEM DE EXECUÇÃO RECOMENDADA

1. ✅ **Tarefa 1** (Botão Eliminar) → Baixo risco, alta prioridade
2. ✅ **Tarefa 2** (Tabs Configurações) → Médio risco, alta prioridade
3. ⚠️ **Tarefa 3** (Auditoria Código) → Alto risco, fazer NO FINAL

**PRINCÍPIO**: Adicionar funcionalidades ANTES de limpar código!

---

## 🚨 QUANDO PARAR E PEDIR AJUDA

Se qualquer um destes acontecer:

1. ❌ Build falha após alteração
2. ❌ Aplicação crasha ao executar
3. ❌ IntelliSense mostra squiggles vermelhos novos
4. ❌ Funcionalidade que funcionava deixa de funcionar
5. ⚠️ Após 3 tentativas de corrigir o mesmo erro

**AÇÃO**:
```bash
git restore <ficheiros problemáticos>
git status
# Reportar problema com:
# - O que tentou fazer
# - Erro exato que apareceu
# - Output completo do build
```

---

## 📝 NOTAS TÉCNICAS IMPORTANTES

### Arquitetura Atual (NÃO ALTERAR)
- **MVVM Pattern**: ViewModels → Views (binding XAML)
- **Repository Pattern**: IUnitOfWork → Repositories
- **Dependency Injection**: Configurado em `App.xaml.cs`
- **Observable Pattern**: CommunityToolkit.Mvvm (`[ObservableProperty]`)

### Convenções de Código Estabelecidas
- **ViewModels**: Sufixo `ViewModel` (ex: `DashboardViewModel`)
- **Commands**: Sufixo `Command` (ex: `SalvarPacienteCommand`)
- **Propriedades Observáveis**: `[ObservableProperty]` privado → público gerado
- **Logging**: `_logger.LogInformation("✅ Mensagem")` com emojis

### Bindings XAML Críticos (NÃO QUEBRAR)
- `DataContext` herdado de Window para UserControls
- `RelativeSource AncestorType` para comandos em DataGrid
- `Converter={StaticResource ...}` para formatação

---

## 🎯 RESULTADO ESPERADO FINAL

Após completar TODAS as tarefas:

### ✅ Funcionalidades Adicionadas
1. Botão "🗑️ Eliminar" funcional na lista de pacientes
2. Tabs Configurações com 4 secções (Email, Templates, Preferências, Sistema)
3. Botão "➕ Adicionar Template PDF" funcional

### ✅ Código Limpo
4. Zero `using` statements não utilizados
5. Zero comentários obsoletos
6. Relatório de auditoria completo

### ✅ Build e Testes
7. Build: 0 Errors, ~39 Warnings (apenas AForge compatibility)
8. Aplicação executa sem crashes
9. Todas as funcionalidades testadas manualmente

---

## 📚 REFERÊNCIAS

### Documentos Críticos
- `.github/copilot-instructions.md` → Regras de desenvolvimento
- `CHECKLIST_ANTI_ERRO_UI.md` → UI/Binding best practices
- `RESUMO_SESSAO_07OUT2025.md` → Últimas alterações

### Ficheiros Importantes
- `src/BioDesk.ViewModels/ListaPacientesViewModel.cs` → Para Tarefa 1
- `src/BioDesk.App/Views/ConfiguracoesView.xaml` → Para Tarefa 2
- `src/BioDesk.ViewModels/Base/ViewModelBase.cs` → Base de todos os ViewModels

---

## 🎉 BOA SORTE!

**Lembra-te**:
- **Prudência** > Velocidade
- **Testes** > Elegância de código
- **Funcional** > Perfeito

Se tiveres dúvidas → **PARA e PERGUNTA** antes de continuar!

---

**FIM DO PROMPT** 🤖
