﻿# BioDeskPro2 - Guia rÃ¡pido para agentes de codificaÃ§Ã£o (IA)

Este cabeÃ§alho contÃ©m as instruÃ§Ãµes mÃ­nimas e accionÃ¡veis para um agente de codificaÃ§Ã£o ser produtivo rapidamente neste repositÃ³rio.

- SDK: .NET 8 LTS fixado em `global.json` (8.0.403). Sempre respeitar este SDK quando construir ou executar.
- Estrutura: soluÃ§Ã£o multi-projeto em `src/` (App, ViewModels, Domain, Data, Services, Tests). Ex.: `src/BioDesk.App` contÃ©m o WPF entrypoint e `App.xaml.cs` registra DI.

Regras essenciais (curtas):
- **ANTES DE QUALQUER ALTERAÃ‡ÃƒO**: explicar o plano ao utilizador, apontar ficheiros a tocar e aguardar confirmaÃ§Ã£o explÃ­cita antes de editar ou executar comandos que modifiquem o repositÃ³rio.
- Sempre usar `PathService` para obter paths (projeto depende fortemente disto; ver regras crÃ­ticas em `REGRAS_CRITICAS_BD.md`).
- ðŸ”´ **NUNCA ALTERAR sistema de EMAIL** sem ler `REGRAS_CRITICAS_EMAIL.md` primeiro (17h de debug, sistema 100% funcional).
- Antes de navegar para a ficha do paciente: chamar `SetPacienteAtivo(paciente)` e sÃ³ depois `NavigateTo("FichaPaciente")`.
- OperaÃ§Ãµes async em ViewModels devem usar `ExecuteWithErrorHandlingAsync(...)` (padrÃ£o obrigatÃ³rio).
- UI: quando mÃºltiplos UserControls no mesmo Grid, definir `Panel.ZIndex` e `Background="Transparent"` para evitar sobreposiÃ§Ã£o.

Ficheiros/locais chave a usar como referÃªncia:
- `src/BioDesk.App/App.xaml.cs` â€” bootstrap de DI e registo de serviÃ§os (ex.: AddSingleton/Scoped/AddTransient). **ðŸ”´ LINHAS 228-245 PROTEGIDAS** (ConfigureAppConfiguration).
- `src/BioDesk.Services/Email/EmailService.cs` â€” **ðŸ”´ LINHAS 17-55 E 80-150 PROTEGIDAS** (validaÃ§Ã£o credenciais + retry logic).
- `src/BioDesk.ViewModels/Abas/ComunicacaoViewModel.cs` â€” **ðŸ”´ LINHAS ~445-520 PROTEGIDAS** (early return anti-duplicaÃ§Ã£o).
- `src/**/PathService` (classe PathService) â€” GERENCIAMENTO de caminhos; NUNCA modificar sem backups.
- `src/BioDesk.Tests/Services/PacienteServiceTests.cs` â€” exemplos de contratos de comportamento que nÃ£o podem ser quebrados.
- `.vscode/settings.json` e `omnisharp.json` â€” mostram que o projeto usa OmniSharp/Roslyn analyzers e formataÃ§Ã£o automÃ¡tica.

Comandos essenciais (invocados por tarefas VS Code jÃ¡ existentes):
```powershell
dotnet restore
dotnet build
dotnet run --project src/BioDesk.App
dotnet test src/BioDesk.Tests
```

ExtensÃµes recomendadas (mÃ­nimo detectÃ¡vel):
- C# Dev Kit (recomendado no `README.md`) e a extensÃ£o C# (ms-dotnettools.csharp) â€” Omnisharp/formatador.
- PowerShell (para executar os scripts `.ps1` e tasks locais).

Notas de seguranÃ§a e estabilidade rÃ¡pidas:
- NUNCA alterar `PathService.cs`, `DatabasePath` ou a linha do DbContext em `App.xaml.cs` sem entender o impacto (hÃ¡ regras crÃ­ticas no repo).
- ðŸ”´ **NUNCA ALTERAR cÃ³digo marcado como PROTEGIDO** (ver `REGRAS_CRITICAS_EMAIL.md` e `REGRAS_CRITICAS_BD.md`).
- ðŸ”´ **Sistema de EMAIL estÃ¡ 100% funcional** (testado 22/10/2025) - NÃ£o "melhorar" ou "refatorar" sem pedido explÃ­cito.
- Antes de afirmar que um problema estÃ¡ resolvido, executar: `dotnet build` + `dotnet test`.

-- Fim da secÃ§Ã£o para agentes. O ficheiro continua com documentaÃ§Ã£o humana detalhada abaixo.
# BioDeskPro2 - Sistema de GestÃ£o MÃ©dica

Sistema WPF para gestÃ£o clÃ­nica com Naturopatia, Osteopatia e IrisdiagnÃ³stico, desenvolvido em C# .NET 8.

## ðŸ—ï¸ Arquitetura

### Estrutura de Projetos (6 camadas)
```
src/
â”œâ”€â”€ BioDesk.App/          # WPF Views + XAML + Dependency Injection bootstrap
â”œâ”€â”€ BioDesk.ViewModels/   # ViewModels MVVM (CommunityToolkit.Mvvm)
â”œâ”€â”€ BioDesk.Domain/       # Entidades (Paciente, Consulta, IrisAnalise)
â”œâ”€â”€ BioDesk.Data/         # EF Core DbContext + Repositories + SQLite
â”œâ”€â”€ BioDesk.Services/     # Business logic (Navigation, Email, PDF, Camera)
â””â”€â”€ BioDesk.Tests/        # xUnit tests (testes Ã¢ncora)
```

### Tecnologias-Chave
- **.NET 8 LTS** fixo via `global.json` (8.0.403)
- **WPF** com TargetFramework `net8.0-windows`, Nullable enabled
- **CommunityToolkit.Mvvm** para `[ObservableProperty]` e `[RelayCommand]`
- **Entity Framework Core** com SQLite (arquivo: `biodesk.db`)
- **FluentValidation** para regras de negÃ³cio
- **QuestPDF** para geraÃ§Ã£o de PDFs (prescriÃ§Ãµes/consentimentos)

## ðŸŽ¯ PadrÃµes MVVM ObrigatÃ³rios

### ViewModels Base Classes
```csharp
// Base para todos os ViewModels
public abstract partial class ViewModelBase : ObservableObject
{
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string _errorMessage = string.Empty;

    // SEMPRE usar este mÃ©todo para operaÃ§Ãµes async
    protected async Task ExecuteWithErrorHandlingAsync(Func<Task> operation,
        string errorContext = "", ILogger? logger = null) { }
}

// Para ViewModels que navegam entre views
public abstract class NavigationViewModelBase : ViewModelBase
{
    protected readonly INavigationService _navigationService;
}
```

### PadrÃ£o de Propriedades e Comandos
```csharp
// âœ… CORRETO - CommunityToolkit.Mvvm
[ObservableProperty]
private string _pesquisarTexto = string.Empty;

[RelayCommand]
private async Task PesquisarAsync() { }

// âŒ ERRADO - INotifyPropertyChanged manual
private string _texto;
public string Texto {
    get => _texto;
    set { _texto = value; OnPropertyChanged(); }
}
```

## ðŸ§­ Sistema de NavegaÃ§Ã£o

### NavegaÃ§Ã£o Consistente (Caminho de Ouro)
```csharp
// SEMPRE seguir esta sequÃªncia ao navegar para ficha de paciente:
_pacienteService.SetPacienteAtivo(paciente);  // 1Âº: Definir contexto
_navigationService.NavigateTo("FichaPaciente"); // 2Âº: Navegar

// Views registadas no INavigationService:
// - "Dashboard", "NovoPaciente", "FichaPaciente", "ListaPacientes", "Configuracoes"
```

### Fluxos de NavegaÃ§Ã£o PadrÃ£o
```
Dashboard â†’ Pesquisa (1 resultado) â†’ SetPacienteAtivo â†’ FichaPaciente
Dashboard â†’ Pesquisa (mÃºltiplos) â†’ ListaPacientes â†’ Selecionar â†’ SetPacienteAtivo â†’ FichaPaciente
Dashboard â†’ NovoPaciente â†’ ValidaÃ§Ã£o â†’ Gravar â†’ SetPacienteAtivo â†’ FichaPaciente
```

## ðŸ“‚ PathService - GestÃ£o de Ficheiros

**SEMPRE** usar `PathService` para caminhos de ficheiros. **NUNCA** hardcoded paths.

```csharp
// âœ… CORRETO
var dbPath = PathService.DatabasePath;
var templatesPath = PathService.TemplatesPath;
var consentimentoPath = PathService.GetConsentimentoPath(tipo, nome, data);

// âŒ ERRADO
var path = @"C:\Documentos\Templates";
var path = Path.Combine(Directory.GetCurrentDirectory(), "Templates");
```

**Modo Debug vs Release**:
- **Debug** (VS Code attached): Usa pasta do projeto (`BioDeskPro2/`)
- **Release** (instalado): Usa `C:\ProgramData\BioDeskPro2\`

Pastas geridas: `Documentos/`, `Templates/`, `Backups/`, `Logs/`, `Pacientes/`, `Prescricoes/`, `Consentimentos/`

## ðŸŽ¨ UI/XAML - Regras CrÃ­ticas

### SobreposiÃ§Ã£o UserControls (Bug Comum)
```xaml
<!-- âœ… CORRETO - Panel.ZIndex explÃ­cito + Background transparent -->
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

<!-- âŒ ERRADO - Sem Z-Index causa sobreposiÃ§Ã£o visual -->
<Grid>
    <local:UserControl1 Visibility="..."/>
    <local:UserControl2 Visibility="..."/>  <!-- Sempre fica por cima! -->
</Grid>
```

**Regra de Ouro**: Quando mÃºltiplos UserControls no mesmo Grid, **SEMPRE** definir `Panel.ZIndex` e `Background="Transparent"`.

### Design-Time DataContext
```xaml
<!-- SEMPRE adicionar d:DataContext para IntelliSense no XAML -->
<UserControl xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
             d:DataContext="{d:DesignInstance Type=vm:FichaPacienteViewModel}">
```

### Paleta de Cores (Terroso Pastel)
```xml
<Color x:Key="FundoPrincipal">0xFCFDFB</Color>      <!-- Gradiente â†’ 0xF2F5F0 -->
<Color x:Key="Cartao">0xF7F9F6</Color>
<Color x:Key="Borda">0xE3E9DE</Color>
<Color x:Key="TextoPrincipal">0x3F4A3D</Color>
<Color x:Key="TextoSecundario">0x5A6558</Color>
<Color x:Key="BotaoPrimario">0x9CAF97</Color>       <!-- Hover: 0x879B83 -->
```

## ðŸ› ï¸ Comandos de Desenvolvimento

### Build e ExecuÃ§Ã£o
```bash
# Restore + Build + Run (sequÃªncia completa)
dotnet clean && dotnet restore && dotnet build && dotnet run --project src/BioDesk.App

# Build incremental rÃ¡pido
dotnet build

# Executar testes
dotnet test src/BioDesk.Tests

# Build com anÃ¡lise completa (detectar CA warnings)
dotnet build --verbosity normal --no-incremental
```

### Tasks VS Code DisponÃ­veis
- **Build BioDeskPro2**: CompilaÃ§Ã£o rÃ¡pida
- **Run BioDeskPro2**: Executa aplicaÃ§Ã£o (dependsOn Build)
- **Test BioDeskPro2**: Executa testes xUnit
- **Analyze Code - Full Solution**: Build verboso com CA analyzers
- **Restore + Clean + Build**: SequÃªncia completa com logging

## ðŸ§ª Testes Ã‚ncora (Contratos)

Testes definem contratos crÃ­ticos - **NUNCA** alterar testes para esconder erros:

```csharp
// BioDesk.Tests/Services/PacienteServiceTests.cs
[Fact] public async Task SearchAsync_DevolveResultados() { }
[Fact] public async Task GravarPaciente_PermiteSetPacienteAtivo() { }
[Fact] public async Task GetRecentesAsync_DevolvePacientesOrdenadosPorDataAtualizacao() { }
[Fact] public void SetPacienteAtivo_DisparaEvento() { }
```

## ðŸ“‹ Error Handling Patterns

### ExecuteWithErrorHandlingAsync (ObrigatÃ³rio)
```csharp
// âœ… CORRETO - Em ViewModels
[RelayCommand]
private async Task PesquisarAsync()
{
    await ExecuteWithErrorHandlingAsync(async () =>
    {
        // 1. Validar inputs
        if (string.IsNullOrWhiteSpace(PesquisarTexto))
            return;

        // 2. OperaÃ§Ã£o business logic
        var resultados = await _pacienteService.SearchAsync(PesquisarTexto);

        // 3. Atualizar UI
        Resultados = resultados;
    },
    errorContext: "ao pesquisar pacientes",
    logger: _logger);
}

// âŒ ERRADO - Try-catch simples sem logging
try {
    var result = await _service.DoSomething();
}
catch { /* silÃªncio */ }
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

## ðŸš¨ Regras de VerificaÃ§Ã£o ObrigatÃ³rias

### NUNCA Fazer
1. **NUNCA** dizer "problema resolvido" sem executar `dotnet build` + `dotnet test`
2. **NUNCA** adaptar testes para esconder erros
3. **NUNCA** ignorar squiggles vermelhos no VS Code
4. **NUNCA** usar try-catch para silenciar problemas
5. **NUNCA** alterar cÃ³digo funcional sem razÃ£o explÃ­cita ("Se funciona, nÃ£o mexe")
6. **NUNCA** usar hardcoded paths - sempre `PathService`
7. **NUNCA** colocar mÃºltiplos UserControls sem `Panel.ZIndex`
8. **ðŸ”´ NUNCA NUNCA NUNCA ALTERAR PathService.cs** - Causa perda de dados (ver REGRAS_CRITICAS_BD.md)
9. **ðŸ”´ NUNCA ALTERAR DatabasePath** - BD fica inacessÃ­vel
10. **ðŸ”´ NUNCA ALTERAR App.xaml.cs linha DbContext** - Cria BD nova vazia

### SEMPRE Fazer
1. **SEMPRE** verificar build antes e depois: `dotnet clean && dotnet build`
2. **SEMPRE** usar `ExecuteWithErrorHandlingAsync` para operaÃ§Ãµes async
3. **SEMPRE** validar com FluentValidation antes de gravar
4. **SEMPRE** usar `SetPacienteAtivo` antes de `NavigateTo("FichaPaciente")`
5. **SEMPRE** implementar Dispose pattern completo (CA1063)
6. **SEMPRE** testar navegaÃ§Ã£o entre TODAS as abas apÃ³s mudanÃ§as XAML
7. **SEMPRE** usar `PathService` para caminhos de ficheiros
8. **SEMPRE** definir `d:DataContext` em UserControls para IntelliSense
9. **ðŸ”´ SEMPRE fazer backup manual antes de alteraÃ§Ãµes crÃ­ticas** (ver REGRAS_CRITICAS_BD.md)
10. **ðŸ”´ SEMPRE verificar tamanho da BD apÃ³s alteraÃ§Ãµes** (deve manter >700KB se tinha dados)

### Checklist PrÃ©-Commit
```bash
# 1. Build limpo
dotnet clean && dotnet restore && dotnet build
# Verificar: 0 Errors, warnings apenas AForge (compatibilidade)

# 2. Testes passam
dotnet test
# Verificar: Todos green

# 3. VS Code limpo
# Verificar: Sem squiggles vermelhos no Problems Panel

# 4. Executar aplicaÃ§Ã£o
dotnet run --project src/BioDesk.App
# Verificar: Dashboard abre, navegaÃ§Ã£o funciona
```

## ðŸ“Š ConfiguraÃ§Ã£o IntelliSense (NÃƒO ALTERAR)

Ficheiros jÃ¡ configurados e funcionais:
- **`.vscode/settings.json`**: Problems Panel em tree view, analyzers habilitados
- **`omnisharp.json`**: Roslyn analyzers, inlay hints, import completion
- **`.editorconfig`**: 88 regras CA configuradas

**âš ï¸ ATENÃ‡ÃƒO**: NÃ£o alterar estas configuraÃ§Ãµes sem motivo crÃ­tico - estÃ£o otimizadas.

## ðŸŽ¯ Status do Projeto (Atualizado: 12/10/2025)

### Build Status âœ…
- **0 Errors**, 24 Warnings (apenas AForge camera compatibility)
- AplicaÃ§Ã£o WPF executa perfeitamente
- Todos os testes (xUnit) compilam e passam

### Funcionalidades Implementadas âœ…
- **Dashboard**: Pesquisa global, pacientes recentes, cards navegaÃ§Ã£o
- **NavegaÃ§Ã£o**: Dashboard â†” NovoPaciente â†” FichaPaciente â†” ListaPacientes
- **Ficha Paciente**: 6 abas (Dados BiogrÃ¡ficos, DeclaraÃ§Ã£o SaÃºde, Consentimentos, Registo Consultas, IrisdiagnÃ³stico, ComunicaÃ§Ã£o)
- **PathService**: GestÃ£o Debug/Release de caminhos (`biodesk.db`, templates, PDFs)
- **IrisdiagnÃ³stico**: Canvas interativo com zoom, marcas em 2 zonas, menu contextual
- **Consentimentos**: Templates Naturopatia/Osteopatia com assinatura digital
- **PrescriÃ§Ãµes**: Templates globais com QuestPDF (pop-up de seleÃ§Ã£o)
- **Auto-save**: Terapia salva automaticamente (debounce 1.5s)
- **Email**: Queue processor com EmailService + templates

### Sprint 2 Completado (6/6 tarefas)
1. âœ… Campo ObservaÃ§Ãµes Consentimentos
2. âœ… Menu Contextual Marcas Ãris (editar/cor/remover)
3. âœ… Auto-save Terapia verificado
4. âœ… DocumentaÃ§Ã£o REGRAS_CONSULTAS.md
5. âœ… Pop-up Templates PrescriÃ§Ãµes (SelecionarTemplatesWindow)
6. âœ… PersistÃªncia Estado Abas (ConfiguracaoClinicaViewModel)

### TODO's Eliminados
- **InÃ­cio (03/10)**: 40 TODO's
- **Fim (12/10)**: 13 TODO's
- **ReduÃ§Ã£o**: 67%

## ðŸ”— Dependency Injection (App.xaml.cs)

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

## ðŸ“– DocumentaÃ§Ã£o Adicional

Para contexto mais profundo, consultar:
- **RELATORIO_SPRINT2_COMPLETO_12OUT2025.md**: Ãšltimas implementaÃ§Ãµes
- **CHECKLIST_ANTI_ERRO_UI.md**: Regras crÃ­ticas XAML/binding
- **GUIA_TESTE_DEBUG_PATHSERVICE.md**: Debug PathService em desenvolvimento
- **REGRAS_CONSULTAS.md**: Por que consultas nÃ£o podem ser editadas
- **SISTEMA_CONFIGURACOES.md**: Sistema ConfiguracaoClinicaViewModel
- **PLANO_DESENVOLVIMENTO_RESTANTE.md**: Roadmap funcionalidades futuras

---

**PrincÃ­pio Fundamental**: "Se funciona e os testes passam, NÃƒO ALTERES!"
Estabilidade > ElegÃ¢ncia | Funcionalidade > Refactoring desnecessÃ¡rio


