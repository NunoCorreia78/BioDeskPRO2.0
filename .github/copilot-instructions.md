# BioDeskPro2 - Sistema de Gestão Médica

Sistema WPF para gestão clínica com Naturopatia, Osteopatia e Irisdiagnóstico, desenvolvido em C# .NET 8.

## 🏗️ Arquitetura

### Estrutura de Projetos (6 camadas)
```
src/
├── BioDesk.App/          # WPF Views + XAML + Dependency Injection bootstrap
├── BioDesk.ViewModels/   # ViewModels MVVM (CommunityToolkit.Mvvm)
├── BioDesk.Domain/       # Entidades (Paciente, Consulta, IrisAnalise)
├── BioDesk.Data/         # EF Core DbContext + Repositories + SQLite
├── BioDesk.Services/     # Business logic (Navigation, Email, PDF, Camera)
└── BioDesk.Tests/        # xUnit tests (testes âncora)
```

### Tecnologias-Chave
- **.NET 8 LTS** fixo via `global.json` (8.0.403)
- **WPF** com TargetFramework `net8.0-windows`, Nullable enabled
- **CommunityToolkit.Mvvm** para `[ObservableProperty]` e `[RelayCommand]`
- **Entity Framework Core** com SQLite (arquivo: `biodesk.db`)
- **FluentValidation** para regras de negócio
- **QuestPDF** para geração de PDFs (prescrições/consentimentos)

## 🎯 Padrões MVVM Obrigatórios

### ViewModels Base Classes
```csharp
// Base para todos os ViewModels
public abstract partial class ViewModelBase : ObservableObject
{
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _errorMessage = string.Empty;
    
    // SEMPRE usar este método para operações async
    protected async Task ExecuteWithErrorHandlingAsync(Func<Task> operation, 
        string errorContext = "", ILogger? logger = null) { }
}

// Para ViewModels que navegam entre views
public abstract class NavigationViewModelBase : ViewModelBase
{
    protected readonly INavigationService _navigationService;
}
```

### Padrão de Propriedades e Comandos
```csharp
// ✅ CORRETO - CommunityToolkit.Mvvm
[ObservableProperty]
private string _pesquisarTexto = string.Empty;

[RelayCommand]
private async Task PesquisarAsync() { }

// ❌ ERRADO - INotifyPropertyChanged manual
private string _texto;
public string Texto { 
    get => _texto; 
    set { _texto = value; OnPropertyChanged(); }
}
```

## 🧭 Sistema de Navegação

### Navegação Consistente (Caminho de Ouro)
```csharp
// SEMPRE seguir esta sequência ao navegar para ficha de paciente:
_pacienteService.SetPacienteAtivo(paciente);  // 1º: Definir contexto
_navigationService.NavigateTo("FichaPaciente"); // 2º: Navegar

// Views registadas no INavigationService:
// - "Dashboard", "NovoPaciente", "FichaPaciente", "ListaPacientes", "Configuracoes"
```

### Fluxos de Navegação Padrão
```
Dashboard → Pesquisa (1 resultado) → SetPacienteAtivo → FichaPaciente
Dashboard → Pesquisa (múltiplos) → ListaPacientes → Selecionar → SetPacienteAtivo → FichaPaciente
Dashboard → NovoPaciente → Validação → Gravar → SetPacienteAtivo → FichaPaciente
```

## 📂 PathService - Gestão de Ficheiros

**SEMPRE** usar `PathService` para caminhos de ficheiros. **NUNCA** hardcoded paths.

```csharp
// ✅ CORRETO
var dbPath = PathService.DatabasePath;
var templatesPath = PathService.TemplatesPath;
var consentimentoPath = PathService.GetConsentimentoPath(tipo, nome, data);

// ❌ ERRADO
var path = @"C:\Documentos\Templates";
var path = Path.Combine(Directory.GetCurrentDirectory(), "Templates");
```

**Modo Debug vs Release**:
- **Debug** (VS Code attached): Usa pasta do projeto (`BioDeskPro2/`)
- **Release** (instalado): Usa `C:\ProgramData\BioDeskPro2\`

Pastas geridas: `Documentos/`, `Templates/`, `Backups/`, `Logs/`, `Pacientes/`, `Prescricoes/`, `Consentimentos/`

## 🎨 UI/XAML - Regras Críticas

### Sobreposição UserControls (Bug Comum)
```xaml
<!-- ✅ CORRETO - Panel.ZIndex explícito + Background transparent -->
<Grid>
    <local:DadosBiograficosUserControl 
        Panel.ZIndex="100" 
        Background="Transparent"
        Visibility="{Binding AbaAtiva, Converter={StaticResource TabVisibilityConverter}, ConverterParameter=DadosBiograficos}"/>
    <local:ConsentimentosUserControl 
        Panel.ZIndex="50" 
        Background="Transparent"
        Visibility="{Binding AbaAtiva, Converter={StaticResource TabVisibilityConverter}, ConverterParameter=Consentimentos}"/>
</Grid>

<!-- ❌ ERRADO - Sem Z-Index causa sobreposição visual -->
<Grid>
    <local:UserControl1 Visibility="..."/>
    <local:UserControl2 Visibility="..."/>  <!-- Sempre fica por cima! -->
</Grid>
```

**Regra de Ouro**: Quando múltiplos UserControls no mesmo Grid, **SEMPRE** definir `Panel.ZIndex` e `Background="Transparent"`.

### Design-Time DataContext
```xaml
<!-- SEMPRE adicionar d:DataContext para IntelliSense no XAML -->
<UserControl xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
             d:DataContext="{d:DesignInstance Type=vm:FichaPacienteViewModel}">
```

### Paleta de Cores (Terroso Pastel)
```xml
<Color x:Key="FundoPrincipal">#FCFDFB</Color>      <!-- Gradiente → #F2F5F0 -->
<Color x:Key="Cartao">#F7F9F6</Color>
<Color x:Key="Borda">#E3E9DE</Color>
<Color x:Key="TextoPrincipal">#3F4A3D</Color>
<Color x:Key="TextoSecundario">#5A6558</Color>
<Color x:Key="BotaoPrimario">#9CAF97</Color>       <!-- Hover: #879B83 -->
```

## 🛠️ Comandos de Desenvolvimento

### Build e Execução
```bash
# Restore + Build + Run (sequência completa)
dotnet clean && dotnet restore && dotnet build && dotnet run --project src/BioDesk.App

# Build incremental rápido
dotnet build

# Executar testes
dotnet test src/BioDesk.Tests

# Build com análise completa (detectar CA warnings)
dotnet build --verbosity normal --no-incremental
```

### Tasks VS Code Disponíveis
- **Build BioDeskPro2**: Compilação rápida
- **Run BioDeskPro2**: Executa aplicação (dependsOn Build)
- **Test BioDeskPro2**: Executa testes xUnit
- **Analyze Code - Full Solution**: Build verboso com CA analyzers
- **Restore + Clean + Build**: Sequência completa com logging

## 🧪 Testes Âncora (Contratos)

Testes definem contratos críticos - **NUNCA** alterar testes para esconder erros:

```csharp
// BioDesk.Tests/Services/PacienteServiceTests.cs
[Fact] public async Task SearchAsync_DevolveResultados() { }
[Fact] public async Task GravarPaciente_PermiteSetPacienteAtivo() { }
[Fact] public async Task GetRecentesAsync_DevolvePacientesOrdenadosPorDataAtualizacao() { }
[Fact] public void SetPacienteAtivo_DisparaEvento() { }
```

## 📋 Error Handling Patterns

### ExecuteWithErrorHandlingAsync (Obrigatório)
```csharp
// ✅ CORRETO - Em ViewModels
[RelayCommand]
private async Task PesquisarAsync()
{
    await ExecuteWithErrorHandlingAsync(async () =>
    {
        // 1. Validar inputs
        if (string.IsNullOrWhiteSpace(PesquisarTexto))
            return;
        
        // 2. Operação business logic
        var resultados = await _pacienteService.SearchAsync(PesquisarTexto);
        
        // 3. Atualizar UI
        Resultados = resultados;
    }, 
    errorContext: "ao pesquisar pacientes",
    logger: _logger);
}

// ❌ ERRADO - Try-catch simples sem logging
try { 
    var result = await _service.DoSomething(); 
} 
catch { /* silêncio */ }
```

### Dispose Pattern (CA1063 Compliant)
```csharp
public class MeuServico : IDisposable
{
    private bool _disposed = false;

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!_disposed && disposing)
        {
            // Limpar recursos managed
            _recurso?.Dispose();
        }
        _disposed = true;
    }
}
```

## 🚨 Regras de Verificação Obrigatórias

### NUNCA Fazer
1. **NUNCA** dizer "problema resolvido" sem executar `dotnet build` + `dotnet test`
2. **NUNCA** adaptar testes para esconder erros
3. **NUNCA** ignorar squiggles vermelhos no VS Code
4. **NUNCA** usar try-catch para silenciar problemas
5. **NUNCA** alterar código funcional sem razão explícita ("Se funciona, não mexe")
6. **NUNCA** usar hardcoded paths - sempre `PathService`
7. **NUNCA** colocar múltiplos UserControls sem `Panel.ZIndex`
8. **🔴 NUNCA NUNCA NUNCA ALTERAR PathService.cs** - Causa perda de dados (ver REGRAS_CRITICAS_BD.md)
9. **🔴 NUNCA ALTERAR DatabasePath** - BD fica inacessível
10. **🔴 NUNCA ALTERAR App.xaml.cs linha DbContext** - Cria BD nova vazia

### SEMPRE Fazer
1. **SEMPRE** verificar build antes e depois: `dotnet clean && dotnet build`
2. **SEMPRE** usar `ExecuteWithErrorHandlingAsync` para operações async
3. **SEMPRE** validar com FluentValidation antes de gravar
4. **SEMPRE** usar `SetPacienteAtivo` antes de `NavigateTo("FichaPaciente")`
5. **SEMPRE** implementar Dispose pattern completo (CA1063)
6. **SEMPRE** testar navegação entre TODAS as abas após mudanças XAML
7. **SEMPRE** usar `PathService` para caminhos de ficheiros
8. **SEMPRE** definir `d:DataContext` em UserControls para IntelliSense
9. **🔴 SEMPRE fazer backup manual antes de alterações críticas** (ver REGRAS_CRITICAS_BD.md)
10. **🔴 SEMPRE verificar tamanho da BD após alterações** (deve manter >700KB se tinha dados)

### Checklist Pré-Commit
```bash
# 1. Build limpo
dotnet clean && dotnet restore && dotnet build
# Verificar: 0 Errors, warnings apenas AForge (compatibilidade)

# 2. Testes passam
dotnet test
# Verificar: Todos green

# 3. VS Code limpo
# Verificar: Sem squiggles vermelhos no Problems Panel

# 4. Executar aplicação
dotnet run --project src/BioDesk.App
# Verificar: Dashboard abre, navegação funciona
```

## 📊 Configuração IntelliSense (NÃO ALTERAR)

Ficheiros já configurados e funcionais:
- **`.vscode/settings.json`**: Problems Panel em tree view, analyzers habilitados
- **`omnisharp.json`**: Roslyn analyzers, inlay hints, import completion
- **`.editorconfig`**: 88 regras CA configuradas

**⚠️ ATENÇÃO**: Não alterar estas configurações sem motivo crítico - estão otimizadas.

## 🎯 Status do Projeto (Atualizado: 12/10/2025)

### Build Status ✅
- **0 Errors**, 24 Warnings (apenas AForge camera compatibility)
- Aplicação WPF executa perfeitamente
- Todos os testes (xUnit) compilam e passam

### Funcionalidades Implementadas ✅
- **Dashboard**: Pesquisa global, pacientes recentes, cards navegação
- **Navegação**: Dashboard ↔ NovoPaciente ↔ FichaPaciente ↔ ListaPacientes
- **Ficha Paciente**: 6 abas (Dados Biográficos, Declaração Saúde, Consentimentos, Registo Consultas, Irisdiagnóstico, Comunicação)
- **PathService**: Gestão Debug/Release de caminhos (`biodesk.db`, templates, PDFs)
- **Irisdiagnóstico**: Canvas interativo com zoom, marcas em 2 zonas, menu contextual
- **Consentimentos**: Templates Naturopatia/Osteopatia com assinatura digital
- **Prescrições**: Templates globais com QuestPDF (pop-up de seleção)
- **Auto-save**: Terapia salva automaticamente (debounce 1.5s)
- **Email**: Queue processor com EmailService + templates

### Sprint 2 Completado (6/6 tarefas)
1. ✅ Campo Observações Consentimentos
2. ✅ Menu Contextual Marcas Íris (editar/cor/remover)
3. ✅ Auto-save Terapia verificado
4. ✅ Documentação REGRAS_CONSULTAS.md
5. ✅ Pop-up Templates Prescrições (SelecionarTemplatesWindow)
6. ✅ Persistência Estado Abas (ConfiguracaoClinicaViewModel)

### TODO's Eliminados
- **Início (03/10)**: 40 TODO's
- **Fim (12/10)**: 13 TODO's
- **Redução**: 67%

## 🔗 Dependency Injection (App.xaml.cs)

```csharp
// Services (Singleton)
services.AddSingleton<INavigationService, NavigationService>();
services.AddSingleton<IEmailService, EmailService>();
services.AddSingleton<ICameraService, RealCameraService>();
services.AddSingleton<IIridologyService, IridologyService>();
services.AddSingleton<IDragDebugService, DragDebugService>();

// Data (Scoped)
services.AddDbContext<BioDeskDbContext>(options =>
    options.UseSqlite($"Data Source={PathService.DatabasePath}"));
services.AddScoped<IUnitOfWork, UnitOfWork>();
services.AddScoped<IPacienteRepository, PacienteRepository>();

// ViewModels (Transient)
services.AddTransient<DashboardViewModel>();
services.AddTransient<FichaPacienteViewModel>();
services.AddTransient<ListaPacientesViewModel>();
services.AddTransient<ConfiguracoesViewModel>();
```

## 📖 Documentação Adicional

Para contexto mais profundo, consultar:
- **RELATORIO_SPRINT2_COMPLETO_12OUT2025.md**: Últimas implementações
- **CHECKLIST_ANTI_ERRO_UI.md**: Regras críticas XAML/binding
- **GUIA_TESTE_DEBUG_PATHSERVICE.md**: Debug PathService em desenvolvimento
- **REGRAS_CONSULTAS.md**: Por que consultas não podem ser editadas
- **SISTEMA_CONFIGURACOES.md**: Sistema ConfiguracaoClinicaViewModel
- **PLANO_DESENVOLVIMENTO_RESTANTE.md**: Roadmap funcionalidades futuras

---

**Princípio Fundamental**: "Se funciona e os testes passam, NÃO ALTERES!"
Estabilidade > Elegância | Funcionalidade > Refactoring desnecessário

