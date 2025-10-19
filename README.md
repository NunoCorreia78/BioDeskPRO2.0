# BioDeskPro2 - Sistema de Gestão Médica

BioDeskPro2 é um sistema de gestão médica desenvolvido em C# WPF com .NET 8, utilizando arquitetura MVVM e Entity Framework Core com SQLite.

## 🚀 Características Principais

- **Dashboard Clean**: Ecrã inicial otimizado para trabalho rápido
- **Gestão de Pacientes**: Criação, pesquisa e consulta de registos
- **Arquitetura MVVM**: Separação clara entre lógica e apresentação
- **Base de Dados SQLite**: Persistência local com Entity Framework Core
- **Paleta Terrosa Pastel**: Interface visualmente agradável
- **Testes Âncora**: Contratos definidos por testes automatizados

## 🏗️ Arquitetura

O projeto segue os **10 Pilares para Desenvolvimento Consistente**:

### Estrutura de Projetos
```
├── src/
│   ├── BioDesk.App/          # WPF Application + Views
│   ├── BioDesk.ViewModels/   # MVVM ViewModels
│   ├── BioDesk.Domain/       # Entidades e Lógica de Negócio
│   ├── BioDesk.Data/         # Entity Framework Core + SQLite
│   ├── BioDesk.Services/     # Serviços (Navegação/Pacientes/Hardware)
│   └── BioDesk.Tests/        # Testes Automatizados
├── global.json              # SDK .NET 8 LTS fixo
└── BioDeskPro2.sln          # Solution File
```

### Tecnologias Utilizadas
- **.NET 8 LTS** - Framework base
- **WPF** - Interface gráfica
- **CommunityToolkit.Mvvm** - MVVM implementation
- **Entity Framework Core** - ORM
- **SQLite** - Base de dados
- **xUnit** - Framework de testes

## 🎨 Dashboard

O dashboard implementa todas as especificações:

### Header com Status
- Indicadores de Online/Offline
- Estado do Iridoscópio e Osciloscópio  
- Relógio e data em tempo real

### Pesquisa Global
- Campo único para nome, nº utente, email
- Enter ou clique para pesquisar
- Navegação inteligente (1 resultado → ficha, múltiplos → lista)

### Cards de Navegação
- **Novo Paciente**: Criação rápida de fichas
- **Lista de Pacientes**: Consulta e pesquisa

### Pacientes Recentes
- 5 últimos pacientes atualizados
- Clique direto para abrir ficha

### Histórico de Envios
- Últimos emails/documentos enviados
- Links para histórico completo

## 🎨 Paleta de Cores (Terroso Pastel)

```css
Fundo gradiente: #FCFDFB → #F2F5F0
Cartão: #F7F9F6
Borda: #E3E9DE
Texto principal: #3F4A3D
Texto secundário: #5A6558
Botão principal: #9CAF97 (hover #879B83)
```

Estados dos dispositivos:
- Online: Verde #2E7D32
- Espera: Laranja #EF6C00  
- Offline: Vermelho #C62828
- Não detectado: Cinza #9E9E9E

## 🔄 Fluxos de Navegação (Caminho de Ouro)

### Criar Novo Paciente
```
Dashboard → Novo Paciente → Validação → Gravação → SetPacienteAtivo → Ficha do Paciente
```

### Pesquisar e Selecionar
```
Dashboard → Pesquisa → (1 resultado) → SetPacienteAtivo → Ficha do Paciente
Dashboard → Pesquisa → (múltiplos) → Lista → Selecionar → SetPacienteAtivo → Ficha do Paciente
```

### Pacientes Recentes
```
Dashboard → Selecionar Recente → SetPacienteAtivo → Ficha do Paciente
```

## 🛠️ Como Executar

### Pré-requisitos
- .NET 8 SDK
- Visual Studio Code (recomendado)
- Extensão C# Dev Kit

### Build e Execução
```bash
# Restaurar dependências
dotnet restore

# Compilar projeto
dotnet build

# Executar aplicação
dotnet run --project src/BioDesk.App

# Executar testes
dotnet test src/BioDesk.Tests
```

### Tasks do VS Code
- **Ctrl+Shift+P** → "Tasks: Run Task"
- **Build BioDeskPro2**: Compila todos os projetos
- **Run BioDeskPro2**: Executa a aplicação
- **Test BioDeskPro2**: Executa testes automatizados

## 🔧 Configuração Ambiente Desenvolvimento

### VS Code Shell Integration + GitHub Copilot

Para workflows automáticos com Copilot (ex: "run tests and fix errors"), é necessário ativar **VS Code Shell Integration**.

#### Setup Rápido (Windows PowerShell)

1. **Criar perfil PowerShell** (se não existir):
   ```powershell
   New-Item -ItemType File -Path $PROFILE -Force
   code $PROFILE
   ```

2. **Colar este código** no perfil (`Microsoft.VSCode_profile.ps1`):
   ```powershell
   # VS Code Shell Integration (obrigatório para Copilot ler terminal)
   if ($env:TERM_PROGRAM -eq "vscode") {
       $shellIntegrationPath = & code --locate-shell-integration-path pwsh
       if ($shellIntegrationPath -and (Test-Path $shellIntegrationPath)) {
           . $shellIntegrationPath
       }
   }
   
   # PSReadLine para melhor experiência terminal
   Import-Module PSReadLine -ErrorAction SilentlyContinue
   
   # Aliases úteis
   Set-Alias -Name build -Value dotnet
   Set-Alias -Name test -Value dotnet
   ```

3. **Configurar VS Code** (`.vscode/settings.json` já inclui):
   ```json
   {
     "terminal.integrated.shellIntegration.enabled": true,
     "github.copilot.chat.agent.runTasks": true,
     "chat.tools.terminal.autoApprove": {
       "git": true,
       "/^dotnet( |$)/": true
     }
   }
   ```

4. **Reiniciar terminal** (ou VS Code completo)

#### Verificar se Funciona
```powershell
# Deve mostrar variável __VSCodeState
Get-Variable __VSCodeState
```

✅ **Com Shell Integration ativa**, o Copilot consegue:
- Ler output de comandos automaticamente
- Executar `dotnet build` e analisar erros
- Correr testes e sugerir fixes
- Monitorizar git status

📖 **Documentação completa**: Ver `SOLUCAO_SHELL_INTEGRATION_19OUT2025.md` para troubleshooting detalhado.

## 🧪 Testes Âncora

Os testes definem contratos fundamentais:

- `SearchAsync_DevolveResultados()`: Pesquisa funcional
- `GravarPaciente_PermiteSetPacienteAtivo()`: Gravação + navegação
- `GetRecentesAsync_DevolvePacientesOrdenadosPorDataAtualizacao()`: Ordenação
- `SetPacienteAtivo_DisparaEvento()`: Eventos para UI

## 📊 Base de Dados

### Seed Inicial
A aplicação cria automaticamente 3 pacientes de exemplo:
- Ana Silva (📧 ana.silva@email.com)
- João Ferreira (📧 joao.ferreira@email.com)  
- Maria Costa (📧 maria.costa@email.com)

### Estrutura Paciente
```csharp
public class Paciente
{
    public int Id { get; set; }
    public string PrimeiroNome { get; set; }
    public string Apelido { get; set; }
    public DateTime DataNascimento { get; set; }
    public string? Email { get; set; }
    public string? Telefone { get; set; }
    public string? NumeroUtente { get; set; }
    public DateTime DataCriacao { get; set; }
    public DateTime DataUltimaAtualizacao { get; set; }
}
```

## 🔒 Guardas Anti-Erro

- **IsDirty**: Diálogos de confirmação
- **Validação robusta**: FluentValidation
- **Índices únicos**: Prevenção de duplicados
- **try/catch + ILogger**: Tratamento de exceções
- **Nullability enabled**: Prevenção de null reference

## 🔧 Desenvolvimento

### Regras Fundamentais
- ✅ **SEMPRE** verificar erros e debug
- ✅ **SEMPRE** consultar logs e diagnostics  
- ✅ **SEMPRE** evitar duplicações
- ✅ **SEMPRE** apagar código obsoleto
- ✅ **SEMPRE** validar antes de gravar
- ✅ **SEMPRE** usar SetPacienteAtivo antes de navegar

### Padrões MVVM
```csharp
// ViewModels herdam de ViewModelBase
public partial class DashboardViewModel : ViewModelBase
{
    [ObservableProperty]
    private string _pesquisarTexto = string.Empty;
    
    [RelayCommand]
    private async Task PesquisarAsync() { /* ... */ }
}
```

### Navegação Consistente
```csharp
// Sempre SetPacienteAtivo + NavigateTo
_pacienteService.SetPacienteAtivo(paciente);
_navigationService.NavigateTo("FichaPaciente");
```

## 📝 Próximos Passos

1. **Ficha do Paciente**: View detalhada com edição
2. **Lista de Pacientes**: View com pesquisa avançada  
3. **Novo Paciente**: Formulário de criação
4. **Hardware Integration**: Iridoscópio e Osciloscópio
5. **Relatórios**: Geração e envio por email
6. **Backup/Sync**: Sincronização de dados

## 🤝 Contribuição

Este projeto segue os 10 pilares para desenvolvimento consistente. Consulte `.github/copilot-instructions.md` para guidelines detalhadas.

## 📄 Licença

[Especificar licença do projeto]

---

**BioDeskPro2** - Desenvolvido com ❤️ usando .NET 8 + WPF + MVVM