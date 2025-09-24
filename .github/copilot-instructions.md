<!-- BioDeskPro2 - Sistema de Gestão Médica -->

## Descrição do Projeto
BioDeskPro2 é um sistema de gestão médica desenvolvido em C# WPF com .NET 8, utilizando arquitetura MVVM e Entity Framework Core com SQLite.

## 10 Pilares para Desenvolvimento Consistente

### 1. SDK Fixo e Previsível
- .NET 8 LTS fixo via global.json
- TargetFramework: net8.0-windows
- UseWPF: true
- Nullable: enable

### 2. Estrutura de Projetos Estável
- BioDesk.App (WPF + Views)
- BioDesk.ViewModels
- BioDesk.Domain
- BioDesk.Data (EF Core)
- BioDesk.Services (Navegação/Pacientes/Hardware)

### 3. MVVM com CommunityToolkit.Mvvm
- ViewModelBase : ObservableObject
- NavigationViewModelBase para ViewModels com navegação
- [ObservableProperty] para propriedades
- [RelayCommand] para comandos
- FluentValidation para validação robusta

### 4. Navegação Única e Consistente
- INavigationService com Register("Dashboard"|"NovoPaciente"|"FichaPaciente"|"ListaPacientes")
- Sempre SetPacienteAtivo + NavigateTo("FichaPaciente")

### 5. XAML com Design-Time DataContext
- d:DataContext para intellisense
- Evitar erros de binding

### 6. Base de Dados Robusta + Seed
- SQLite com índices únicos
- Seed de 3 pacientes no arranque

### 7. Caminho de Ouro Comentado
- Fluxos documentados nos ViewModels
- Regras de negócio explícitas

### 8. Guardas Anti-Erro Padronizados
- IsDirty com diálogos
- Validação robusta com FluentValidation
- ExecuteWithErrorHandlingAsync obrigatório
- try/catch + ILogger em operações críticas

### 8.1. Padrões de Error Handling ⭐ NOVO
- **SEMPRE** usar `ExecuteWithErrorHandlingAsync` para operações assíncronas
- **NUNCA** fazer try/catch simples sem logging
- **SEMPRE** validar com FluentValidation antes de gravar
- **SEMPRE** mostrar feedback visual (IsLoading, ErrorMessage)

### 9. Testes Âncora
- Contratos definidos por testes
- SalvarPaciente_GravaENavegaParaFicha()
- SearchAsync_DevolveResultados()

### 10. Prompts Consistentes
- Nomes padronizados: PesquisarTexto, PesquisarCommand
- Comandos: SelecionarPacienteCommand, NavegarParaFichaCommand

## Paleta de Cores (Terroso Pastel)
- Fundo gradiente: #FCFDFB → #F2F5F0
- Cartão: #F7F9F6
- Borda: #E3E9DE
- Texto principal: #3F4A3D
- Texto secundário: #5A6558
- Botão principal: #9CAF97 (hover #879B83)

## Regras de Desenvolvimento
- SEMPRE verificar erros e debug
- SEMPRE consultar logs e diagnostics
- SEMPRE evitar duplicações (usar NavigationViewModelBase)
- SEMPRE apagar código obsoleto ao criar novos arquivos
- SEMPRE validar com FluentValidation antes de gravar
- SEMPRE usar SetPacienteAtivo antes de navegar para ficha
- SEMPRE usar ExecuteWithErrorHandlingAsync para operações async
- SEMPRE implementar loading states visuais (IsLoading binding)

## Regra Crítica Anti-Erro ✅ RESOLVIDA
- ✅ **Todos os erros de compilação e runtime foram corrigidos**
- ✅ **Problemas de WPF binding com Entity Framework resolvidos**
- ✅ **Sistema de navegação funcionando perfeitamente**
- ✅ **Build completamente limpo (0 erros, 0 warnings)**
- ✅ **Aplicação executando sem crashes**

## Status do Projeto - FUNCIONAL ✅
- **Build**: Completamente limpo
- **Execução**: Aplicação WPF inicia corretamente no Dashboard
- **Navegação**: Todas as views (Dashboard ↔ NovoPaciente ↔ FichaPaciente ↔ ListaPacientes) funcionais
- **Bindings**: WPF binding resolvido com PacienteViewModel wrapper
- **Base de Dados**: SQLite + EF Core operacional
- **Testes**: Todos os testes compilam e executam

## Arquitectura Implementada
- **Entidades**: Paciente simplificada (sem computed properties conflituosas)
- **ViewModels**: PacienteViewModel wrapper para WPF binding seguro
- **Serviços**: PacienteService e NavigationService completamente funcionais
- **Views**: Todas as views registadas e funcionais no DI container

---

## 🚨 REGRAS CRÍTICAS DE VERIFICAÇÃO - COPILOT

### ⚠️ VERIFICAÇÕES OBRIGATÓRIAS (NUNCA SALTAR)

#### 🔴 PROIBIÇÕES ABSOLUTAS
1. **NUNCA** dizer "problema resolvido" sem testar
2. **NUNCA** adaptar testes para esconder erros  
3. **NUNCA** ignorar erros do IntelliSense no VS Code
4. **NUNCA** usar try-catch para silenciar problemas

#### ✅ PROCESSO DE VERIFICAÇÃO OBRIGATÓRIO
```bash
# SEMPRE executar antes de confirmar sucesso:
dotnet clean
dotnet restore  
dotnet build --no-incremental
# Se build OK → dotnet test
```

#### 🔍 CHECKLIST INTELLISENSE VS CODE
- **Squiggles vermelhos**: Corrigir TODOS imediatamente
- **Squiggles amarelos**: Revisar warnings importantes
- **Using statements**: Verificar todos resolvidos
- **Project references**: Confirmar todos adicionados

#### 🐛 METODOLOGIA DE RESOLUÇÃO
1. **DETECTAR**: `dotnet build --verbosity detailed`
2. **ANALISAR**: Ler cada erro completamente
3. **CORRIGIR**: Um erro de cada vez
4. **VERIFICAR**: `dotnet build` até 0 erros
5. **TESTAR**: Só depois de build limpo

#### ❌ ANTI-PATTERNS PROIBIDOS
```csharp
// ERRADO: Esconder erros
try { /* código quebrado */ } catch { }

// ERRADO: Testes sem sentido
Assert.IsTrue(true);

// ERRADO: Comentar código quebrado
// var result = BrokenMethod();

// CERTO: Corrigir o erro real
if (service == null) 
    throw new ArgumentNullException(nameof(service));
```

#### 📋 CHECKLIST FINAL
Antes de afirmar qualquer correção:
- [ ] `dotnet build` = 0 Errors, 0 Warnings
- [ ] VS Code sem squiggles vermelhos
- [ ] Aplicação executa sem exceções
- [ ] Funcionalidades testadas manualmente

#### 🛑 QUANDO PARAR E PEDIR AJUDA
Após 3 tentativas falhadas do mesmo erro, admitir:
"Este problema requer investigação adicional. O erro sugere [problema específico]. Para corrigir adequadamente, precisamos [ação específica]."

**LEMBRETE FINAL**: Código funcional > Código "corrigido" que não funciona