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
- [ObservableProperty] para propriedades
- [RelayCommand] para comandos

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
- Validação robusta
- try/catch + ILogger

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
- SEMPRE evitar duplicações
- SEMPRE apagar código obsoleto ao criar novos arquivos
- SEMPRE validar antes de gravar
- SEMPRE usar SetPacienteAtivo antes de navegar para ficha

## Regra Crítica Anti-Erro
- **NUNCA criar testes quando há erros de compilação ou runtime**
- **SEMPRE resolver erros existentes ANTES de criar novos testes**
- **PRIORIDADE MÁXIMA: Corrigir código que não compila ou executa**
- **SÓ DEPOIS de tudo funcional: então criar/manter testes**
- **Testes são para VALIDAR código funcional, não para contornar erros**

## Metodologia de Resolução de Erros
1. **DETECTAR**: Executar `dotnet build` para identificar erros
2. **ANALISAR**: Ler mensagens de erro completamente
3. **CORRIGIR**: Resolver um erro de cada vez
4. **VERIFICAR**: `dotnet build` novamente até não haver erros
5. **TESTAR**: Só então executar/criar testes se necessário
6. **NUNCA**: Criar código adicional enquanto há erros pendentes

## Prioridades de Ação (por ordem)
1. 🔥 **Erros de compilação** (CS0xxx)
2. 🔥 **Referências em falta** (using statements, project references)
3. 🔥 **Erros de runtime** (exceções não tratadas)
4. ⚠️ **Warnings** importantes
5. ✅ **Funcionalidade nova** (só depois de tudo limpo)
6. ✅ **Testes** (só no final, quando tudo funciona)