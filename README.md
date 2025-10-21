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

## 📡 Modo Informacional (Radiônico)

O BioDeskPro2 suporta **Modo Informacional** para aplicação de terapias sem equipamento físico TiePie HS3.

### O que é?
- Terapia **radiônica/informacional** - emissão simbólica/energética sem sinais elétricos
- Timer, frequências e logs funcionam normalmente
- **Nenhuma comunicação** com hardware TiePie HS3
- Histórico completo mantido (com indicador de modo)

### Como Ativar
1. Abrir janela **"Terapia Local"**
2. Marcar checkbox **"Modo Informacional (sem equipamento físico)"**
3. Configurar voltagem, frequências e duração normalmente
4. Clicar **"Iniciar"** - sessão progride sem emissão física

### Quando Usar
- ✅ Aplicações radiônicas/informacionais
- ✅ Testar protocolos sem hardware conectado
- ✅ Desenvolver/validar novas sequências de frequências
- ✅ Trabalho em local sem acesso ao equipamento

### Indicadores Visuais
- **Banner amarelo** aparece quando modo ativo: `📡 Modo Informacional Ativo`
- Console logs distinguem modos: `📡 Modo Informacional` vs `⚡ Modo Físico`
- Histórico de sessões mostra tipo de aplicação (Físico ou Informacional)

### Diferenças Técnicas

| Aspeto | Modo Físico | Modo Informacional |
|--------|-------------|-------------------|
| Timer progressão | ✅ Sim (1s intervals) | ✅ Sim (1s intervals) |
| Emissão TiePie HS3 | ✅ Sim | ❌ Não |
| Logs de sessão | ✅ Sim | ✅ Sim |
| Histórico persistido | ✅ Sim (Fisico) | ✅ Sim (Informacional) |
| Interface UI | ✅ Idêntica | ✅ Idêntica |

### Implementação Técnica
```csharp
// Enum no SessionHistorico
public enum TipoModoAplicacao {
    Fisico = 0,          // Emissão elétrica real ao TiePie HS3
    Informacional = 1    // Radiônico (sem hardware)
}

// Propriedade no TerapiaLocalViewModel
[ObservableProperty]
private bool _modoInformacional = false;

// Lógica condicional durante sessão
if (ModoInformacional) {
    Console.WriteLine("📡 Modo Informacional: Mudando para {Hz} Hz");
    // Apenas logging, sem comunicação com hardware
} else {
    Console.WriteLine("⚡ Modo Físico: Mudando para {Hz} Hz");
    await _tiepieService.StartEmissionAsync(...);  // Emissão real
}

// Persistência no histórico
var session = new SessionHistorico {
    ModoAplicacao = ModoInformacional
        ? TipoModoAplicacao.Informacional
        : TipoModoAplicacao.Fisico,
    // ...outros campos
};
```

### Base de Dados
A coluna `ModoAplicacao` na tabela `SessionHistoricos` regista o tipo de aplicação:
- **0** = Fisico (emissão real ao equipamento)
- **1** = Informacional (radiônico, sem hardware)

**Migração automática**: A coluna é adicionada automaticamente no primeiro arranque após atualização.

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

## 🔌 Protocolo USB TiePie HS3

O BioDeskPro2 implementa **comunicação USB direta** com o osciloscópio TiePie Handyscope HS3 através de **DeviceIoControl** (Win32 API), **sem dependência** da biblioteca `hs3.dll`.

### 📡 Implementação Protocol Layer

**Namespace**: `BioDesk.Services.Hardware.TiePie.Protocol`

#### Arquitetura (3 camadas)

```
HS3Protocol.cs         → Constantes IOCTL + estruturas de dados
HS3DeviceDiscovery.cs  → Descoberta USB (SetupDi APIs)
HS3DeviceProtocol.cs   → Comunicação DeviceIoControl
```

#### IOCTL Codes Descobertos (via API Monitor)

| Código     | Nome            | Input  | Output | Descrição                    |
|------------|-----------------|--------|--------|------------------------------|
| 0x222000   | GET_DEVICE_INFO | 0 B    | 1024 B | VID/PID/Serial/Firmware      |
| 0x222059   | CONFIG_QUERY    | 10 B   | 8 B    | Configuração do dispositivo  |
| 0x222051   | READ_OPERATION  | 4 B    | 8 B    | Leitura de dados/status      |
| 0x22204E   | WRITE_OPERATION | 4 B    | 1-64 B | Escrita de comandos          |

#### Identificadores USB

```csharp
USB_VENDOR_ID  = 0x0E36  // TiePie Engineering
USB_PRODUCT_ID = 0x0008  // Handyscope HS3
DEVICE_INTERFACE_GUID = {f58af81e-4cdc-4d3f-b11e-0a89e4683972}
```

### ⚡ Padrões de Comunicação Críticos

#### READ→WRITE Pattern (Obrigatório)
```csharp
// ✅ CORRETO - Sempre alternar READ→WRITE
var readSuccess = protocol.ReadOperation(0x00000000, out var readResponse);
if (readSuccess) {
    var writeSuccess = protocol.WriteOperation(0x00000000, 64, out var writeResponse);
}

// ❌ ERRADO - Nunca WRITE sem READ anterior
protocol.WriteOperation(0x00000000, 64, out var response); // FALHA!
```

**Observação**: API Monitor capturou **33 ciclos** consecutivos de READ→WRITE no Inergetix CoRe.

#### Timing Crítico
- **Bulk Transfer 64 bytes**: 2.5ms (limite de pacote USB)
- **Single-threaded**: Todas as operações DeviceIoControl na mesma thread
- **Thread-safety**: `lock(_deviceLock)` em todas as operações

#### Sequência de Inicialização
```csharp
// 1. Descoberta automática
var devicePath = discovery.FindFirstHS3Device();

// 2. Abertura do dispositivo
var opened = protocol.OpenDevice(devicePath);

// 3. Obter capacidades (valida VID/PID)
var capsSuccess = protocol.GetDeviceCapabilities(out var capabilities);
Assert.Equal(0x0E36, capabilities.VendorId);
Assert.Equal(0x0008, capabilities.ProductId);

// 4. Configurar dispositivo
var configured = protocol.ConfigureDevice();

// 5. Pronto para READ→WRITE cycles
```

### 🧪 Testes de Integração (Hardware-Dependent)

**Ficheiro**: `src/BioDesk.Tests/Hardware/TiePie/Protocol/HS3ProtocolTests.cs`

Todos os testes usam `[Fact(Skip="Requires physical TiePie HS3 hardware connected via USB")]`:

1. **Test_DeviceDiscovery_FindsHS3**: Descoberta automática via SetupDi
2. **Test_OpenDevice_WithRealHardware**: Abertura SafeFileHandle
3. **Test_GetDeviceCapabilities_ReturnsCorrectVIDPID**: Validação IOCTL 0x222000
4. **Test_InitializationSequence_FollowsProtocol**: Sequência completa Open→GetCapabilities→Configure
5. **Test_SendCommand_ReadWritePattern**: 33 ciclos READ→WRITE
6. **Test_StressTest_1000Operations**: Thread-safety e estabilidade
7. **Test_TimingValidation_BulkTransfer64Bytes**: Validação timing 2.5ms

#### Ativar Testes com Hardware Físico
```csharp
// Remover Skip attribute para executar com hardware conectado:
[Fact] // (Skip="..." removido)
public async Task Test_OpenDevice_WithRealHardware() { /* ... */ }
```

### ⚠️ Limitações e Próximos Passos

#### Status Atual (20/10/2025)
- ✅ **Protocol layer completo**: Discovery + Communication + Tests
- ✅ **TiePieHS3Service integrado**: Usa USB protocol (não hs3.dll)
- ✅ **CA1063-compliant**: Dispose pattern em todas as classes
- ⚠️ **HS3Commands hipotéticos**: Códigos de comando inferidos de logs (precisam validação)
- ⚠️ **EmitFrequencyAsync pendente**: Retorna false até validação com hardware

#### Quando Hardware Chegar
1. Conectar HS3 via USB
2. Verificar Device Manager (VID_0E36&PID_0008 deve aparecer)
3. Executar `discovery.FindHS3Devices()` para obter device path
4. Remover `[Fact(Skip="...")]` dos testes em `HS3ProtocolTests.cs`
5. Executar testes: `dotnet test --filter FullyQualifiedName~HS3Protocol`
6. Validar códigos de comando com firmware (trial-and-error seguro)

#### Recursos para Validação
- **API Monitor logs**: Ver PR #14 para análise completa Inergetix CoRe
- **Firmware**: `hs3f12.hex` (reverse-engineering se necessário)
- **Guia completo**: `GUIA_HS3_USB_PROTOCOL.md` (troubleshooting + descoberta)

### 🔧 Troubleshooting Rápido

| Erro                         | Causa Provável                      | Solução                                |
|------------------------------|-------------------------------------|----------------------------------------|
| ERROR_FILE_NOT_FOUND         | Dispositivo não conectado           | Verificar Device Manager + USB         |
| ERROR_ACCESS_DENIED          | Permissões insuficientes            | Executar como Administrador            |
| ERROR_INVALID_PARAMETER      | IOCTL code errado                   | Validar contra documentação firmware   |
| Timeout em DeviceIoControl   | Cabo USB defeituoso/hub             | Conectar diretamente à porta USB       |
| VID/PID incorreto            | Dispositivo errado na porta         | Confirmar TiePie HS3 em Device Manager |

### 📚 Documentação Completa

- **`GUIA_HS3_USB_PROTOCOL.md`**: Validação hardware + troubleshooting + descoberta IOCTL
- **PR #14**: API Monitor analysis completo (7 ficheiros, 112 KB)
- **Source code**: `src/BioDesk.Services/Hardware/TiePie/Protocol/`

## 🎯📝 Próximos Passos

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
