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

## 🎯 NOVA ARQUITETURA APROVADA - Interface Clínica Otimizada

### Tab 2 — Gestão Clínica (Zero Redundâncias)

#### Sub-tab 2.1 — Avaliação Clínica (Questionário Estruturado)
**Interface**: Checklists/chips + sliders. **Zero texto obrigatório**.

1. **Motivos da consulta**
   - Motivos (multi-select chips): Dor lombar, Cervicalgia, Cefaleias, Ansiedade, Stress, Fadiga, Refluxo, Dispepsia, Obstipação, Diarreia, Intolerâncias, Alergias, Insónia, Dores articulares, Outro
   - Localização (selector corporal) + Lado (E/D/Bilateral)
   - Início (date picker), Duração (dropdown), Evolução (radio)
   - Intensidade (slider 0–10), Caráter (multi-chips)
   - Fatores agravantes/alívio (chips)

2. **História clínica passada**
   - Doenças crónicas (multi-select + "Nenhuma")
   - Cirurgias ([+] adicionar: Ano|Tipo|Observações)
   - Alergias (chips por tipo + "Sem alergias")
   - Medicação/Suplementação atual (listas + atalhos)

3. **Revisão de sistemas** (colapsável, tri-state)
   - Por sistema: Cardiovascular, Respiratório, Digestivo, etc.
   - Multi-select com observações opcionais

4. **Estilo de vida**
   - Alimentação, Hidratação, Exercício (chips/dropdowns)
   - Tabaco/Álcool/Cafeína (radio/dropdowns)
   - Stress (slider), Sono (chips)

5. **História familiar**
   - Antecedentes (multi-select) + Parentesco (chips)

**⚡ Frases Rápidas**: "Sem alergias", "Sem medicação crónica", etc.

#### Sub-tab 2.2 — Declaração & Consentimentos (Vista Legal)
- **Dataset**: Mesmo da 2.1, formatado como declaração
- **Consentimentos**: Accordion por tema (Naturopatia, Osteopatia, etc.)
- **Assinatura digital** + Data automática
- **RGPD**: Checkbox + assinatura
- **Ações**: Guardar | PDF | Email

**Princípio**: Edita na 2.1, assina na 2.2. **Zero duplicação**.

#### Sub-tab 2.3 — Registo Clínico
- **Consultas**: Tabela (Data|Tipo|Motivos|Observações)
- **Prescrições**: Templates → personalizar → PDF/Email
- **Timeline**: E-mails, PDFs, SMS, chamadas
- **Análises**: Títulos + relatórios

### Tab 3 — Medicina Complementar (🚧 EM DESENVOLVIMENTO)
#### 3.1 Naturopatia - Templates por objetivo
#### 3.2 Irisdiagnóstico - Galeria + overlays
#### 3.3 Terapia Bioenergética - Protocolos em cards

---

## 🛠️ CONFIGURAÇÃO E MANUTENÇÃO - DIRETRIZES AVANÇADAS

### 🔍 INTELLISENSE E ANÁLISE DE CÓDIGO - PROCEDIMENTOS PADRÃO

#### ✅ QUANDO CONFIGURAR INTELLISENSE
- **SEMPRE** que o utilizador mencionar "erros não aparecem"
- **SEMPRE** que pedir para "mostrar todos os erros"
- **SEMPRE** que mencionar "separadores" ou "organização" de erros
- **NUNCA** alterar configurações já funcionais sem razão explícita

#### 📂 HIERARQUIA DE CONFIGURAÇÃO (ordem de importância)
1. **`.vscode/settings.json`** → IntelliSense e Problems Panel
2. **`omnisharp.json`** → C# language server
3. **`.editorconfig`** → Regras de análise (CA rules)
4. **`global.json`** → SDK fixo (.NET 8)

#### 🎯 LOCALIZAÇÃO DE ERROS NO VS CODE
```json
// CONFIGURAÇÃO CRÍTICA para Problems Panel:
"problems.defaultViewMode": "tree",        // NÃO "list"
"problems.autoReveal": true,               // Auto-mostrar
"problems.sortOrder": "severity",          // Errors primeiro
"workbench.problems.visibility": "expanded" // Sempre visível
```

### ⚠️ WARNINGS E CODE ANALYSIS - RESOLUÇÃO SISTEMÁTICA

#### 🔴 PRIORIDADES DE CORREÇÃO
1. **Erros de compilação** (CS errors) → Build falha
2. **CA1063** → Dispose pattern incorreto
3. **CA1001** → Classe com fields disposable deve implementar IDisposable
4. **CS0105** → Using statements duplicados
5. **Outros CA rules** → Conforme configuração .editorconfig

#### 🛡️ PADRÃO DISPOSE OBRIGATÓRIO
```csharp
// NUNCA fazer isto (CA1063 violation):
public void Dispose() { /* clean up */ }

// SEMPRE fazer isto (CA1063 compliant):
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
    }
    _disposed = true;
}
```

### 📊 VERIFICAÇÃO E VALIDAÇÃO - CHECKLIST OBRIGATÓRIO

#### ✅ ANTES DE CONFIRMAR QUALQUER "CORREÇÃO"
```bash
# SEMPRE executar esta sequência:
dotnet clean
dotnet restore
dotnet build --verbosity normal
# Se build OK → confirmar 0 Warnings
```

#### 🔍 SINAIS DE CONFIGURAÇÃO CORRECTA
- **Problems Panel**: Visível com separadores por severity
- **Editor**: Squiggles vermelhos/amarelos a aparecer
- **Build output**: Verbosity detalhada com números exatos
- **IntelliSense**: Auto-completar a funcionar em C# files

#### ❌ SINAIS DE PROBLEMAS
- "Não vejo erros no Problems Panel"
- "IntelliSense não funciona"
- "Build passa mas tenho warnings"
- "Squiggles não aparecem no editor"

### 🎯 INSTRUÇÕES ESPECÍFICAS PARA COPILOT

#### 🚨 NUNCA FAZER
- Alterar settings.json que já funciona
- "Corrigir" código que compila e testa com sucesso
- Implementar Dispose simples sem padrão virtual
- Ignorar outputs de build detalhados

#### ✅ SEMPRE FAZER
- Verificar build antes e depois de mudanças
- Implementar Dispose pattern completo (CA1063)
- Ler mensagens de erro completamente
- Confirmar 0 Warnings no final

#### 📋 TEMPLATE DE VERIFICAÇÃO
```markdown
## Verificação Completa ✅

### Build Status
- [ ] `dotnet clean && dotnet build` → 0 Errors, 0 Warnings
- [ ] Problems Panel mostra erros organizados por severity
- [ ] IntelliSense funciona em ficheiros .cs
- [ ] Squiggles aparecem no editor

### Configuração VS Code
- [ ] `.vscode/settings.json` → tree view configurado
- [ ] `omnisharp.json` → analyzers habilitados
- [ ] `.editorconfig` → CA rules ativas

### Código
- [ ] Dispose patterns seguem CA1063
- [ ] Sem using statements duplicados
- [ ] Classes com disposable fields implementam IDisposable
```

---

## 🚨 REGRAS CRÍTICAS DE VERIFICAÇÃO - COPILOT

### ⚠️ VERIFICAÇÕES OBRIGATÓRIAS (NUNCA SALTAR)

#### 🔴 PROIBIÇÕES ABSOLUTAS
1. **NUNCA** dizer "problema resolvido" sem testar
2. **NUNCA** adaptar testes para esconder erros
3. **NUNCA** ignorar erros do IntelliSense no VS Code
4. **NUNCA** usar try-catch para silenciar problemas

#### 🛡️ REGRA DOURADA: PRESERVAR CÓDIGO FUNCIONAL
5. **NUNCA** alterar código que está funcionando sem razão explícita
6. **NUNCA** refatorar código estável apenas por "melhorar"
7. **NUNCA** tocar em funcionalidades que passam nos testes
8. **SEMPRE** perguntar antes de modificar código funcional
9. **SEMPRE** priorizar: "Se funciona, não mexe" > "código perfeito"

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

#### ⭐ PRINCÍPIO FUNDAMENTAL
**"Se está a funcionar e os testes passam, NÃO ALTERES!"**
- Código funcional é mais valioso que código "perfeito"
- Estabilidade > Elegância
- Funcionalidade > Refactoring desnecessário

#### 🔧 CONFIGURAÇÃO VS CODE INTELLISENSE OTIMIZADA ✅ COMPLETADA

### ✅ FILES CONFIGURADOS (NÃO ALTERAR - FUNCIONANDO PERFEITAMENTE)
- **`.vscode/settings.json`**: IntelliSense C# otimizado, Problems Panel em tree view, separadores organizados
- **`omnisharp.json`**: Roslyn analyzers, inlay hints, import completion habilitados
- **`.editorconfig`**: 88 regras CA configuradas para análise completa de código
- **`.vscode/extensions.json`**: Extensões recomendadas para C#/.NET development
- **`.vscode/tasks.json`**: Tasks de análise e build configuradas

### 🎯 ERROS NO INTELLISENSE - LOCALIZAÇÃO GARANTIDA
- **Problems Panel**: Separador "PROBLEMS" com view em árvore
- **Filtros**: Por severidade (Error → Warning → Information)
- **Auto-reveal**: Erros aparecem automaticamente ao abrir ficheiros
- **Editor decorations**: Squiggles vermelhos e amarelos visíveis
- **Background analysis**: Solução completa analisada continuamente

### 📋 PADRÕES DE DISPOSE IMPLEMENTADOS ✅ RESOLVIDOS
```csharp
// PADRÃO CA1063 CORRETO (implementado em 6 classes):
public class ExemploService : IDisposable
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
            _recursoManaged?.Dispose();
        }
        _disposed = true;
    }
}
```

### 🚀 BUILD STATUS: 100% LIMPO
- ✅ **0 Errors, 0 Warnings** (verificado 2025-09-28)
- ✅ **Todos os CA1063 warnings corrigidos**
- ✅ **Settings.json validation error resolvido**
- ✅ **CS0105 using duplicado removido**

**LEMBRETE FINAL**: Código funcional > Código "corrigido" que não funciona
