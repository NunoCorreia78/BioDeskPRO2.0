# 📂 SISTEMA DE PASTAS DOCUMENTAIS POR PACIENTE

## 🎯 Visão Geral

Sistema completo de gestão de documentos organizados por paciente, com:
- ✅ Pasta automática por paciente: `C:\BioDeskPro2\Documentos\Pacientes\{Id}_Nome\`
- ✅ Subpastas organizadas por tipo (Declarações, Consentimentos, Prescrições, etc.)
- ✅ Botão "📂 Abrir Pasta" que abre diretamente no Windows Explorer
- ✅ Diálogo de anexos abre automaticamente na pasta do paciente
- ✅ Cópia automática de PDFs gerados para a pasta apropriada

---

## 📁 Estrutura de Pastas

```
C:\ProgramData\BioDeskPro2\Documentos\
└── Pacientes\
    ├── 1_João_Silva\
    │   ├── README.txt             ← Ficheiro informativo automático
    │   ├── Declaracoes\           ← Declarações de Saúde
    │   ├── Consentimentos\        ← Termos de Consentimento assinados
    │   ├── Prescricoes\           ← Prescrições e planos terapêuticos
    │   ├── Receitas\              ← Receitas médicas/naturopáticas
    │   ├── Relatorios\            ← Relatórios de consultas
    │   ├── Analises\              ← Resultados de análises clínicas
    │   └── Outros\                ← Documentos diversos
    ├── 2_Maria_Santos\
    │   └── ...
    └── 3_António_Costa\
        └── ...
```

### 📝 README.txt Automático

Cada pasta de paciente contém um ficheiro `README.txt` com:
- Nome e ID do paciente
- Data de criação da pasta
- Explicação da estrutura de subpastas
- Avisos sobre gestão automática

---

## 🎨 Interface de Utilizador

### 1. Botão "📂 Abrir Pasta" (ComunicacaoUserControl.xaml)

**Localização**: Área de estatísticas, lado direito
**Aspeto**: Botão azul com ícone 📂 e texto "Abrir Pasta"
**Comportamento**:
- Clique → Abre Windows Explorer na pasta do paciente
- Se pasta não existir → Cria estrutura completa automaticamente
- Subpastas criadas em simultâneo

```xaml
<!-- Botão Abrir Pasta -->
<Button Command="{Binding AbrirPastaPacienteCommand}"
        Background="#2196F3"
        Foreground="White">
    <StackPanel>
        <TextBlock Text="📂" FontSize="20"/>
        <TextBlock Text="Abrir Pasta" FontSize="11"/>
    </StackPanel>
</Button>
```

### 2. Secção de Anexos Melhorada

**Funcionalidades**:
- ✅ Botão "📎 Anexar Ficheiro" abre diálogo
- ✅ Diálogo abre automaticamente na pasta do paciente (se existir)
- ✅ Multi-seleção de ficheiros
- ✅ Lista visual de anexos com botão ❌ para remover
- ✅ Status: "Nenhum anexo" / "1 anexo (nome.pdf)" / "3 anexos"

```xaml
<!-- Secção de Anexos -->
<StackPanel Margin="0,0,0,12">
    <DockPanel>
        <Button Command="{Binding AdicionarAnexoCommand}">
            <StackPanel Orientation="Horizontal">
                <TextBlock Text="📎" Margin="0,0,4,0"/>
                <TextBlock Text="Anexar Ficheiro"/>
            </StackPanel>
        </Button>
        <TextBlock Text="{Binding StatusAnexos}" Margin="12,0,0,0"/>
    </DockPanel>

    <!-- Lista de anexos -->
    <ItemsControl ItemsSource="{Binding Anexos}">
        <ItemsControl.ItemTemplate>
            <DataTemplate>
                <Border>
                    <DockPanel>
                        <Button DockPanel.Dock="Right"
                                Command="{Binding DataContext.RemoverAnexoCommand, RelativeSource={RelativeSource AncestorType=UserControl}}"
                                CommandParameter="{Binding}">
                            <TextBlock Text="❌"/>
                        </Button>
                        <TextBlock Text="{Binding}"
                                   ToolTip="{Binding}"/>
                    </DockPanel>
                </Border>
            </DataTemplate>
        </ItemsControl.ItemTemplate>
    </ItemsControl>
</StackPanel>
```

---

## 🔧 Implementação Técnica

### 1. IDocumentoService Interface

```csharp
public interface IDocumentoService
{
    // Obter caminhos
    string ObterPastaPaciente(int pacienteId, string nomePaciente);
    string ObterSubpastaPaciente(int pacienteId, string nomePaciente, TipoDocumento subpasta);

    // Gestão de estrutura
    Task<bool> CriarEstruturaPastasPacienteAsync(int pacienteId, string nomePaciente);
    bool PastaExiste(int pacienteId, string nomePaciente);

    // Interação
    void AbrirPastaPaciente(int pacienteId, string nomePaciente, TipoDocumento? subpasta = null);
    Task<List<FicheiroInfo>> ListarFicheirosPacienteAsync(int pacienteId, string nomePaciente, TipoDocumento? subpasta = null);
    Task<string> CopiarFicheiroParaPacienteAsync(string caminhoOrigem, int pacienteId, string nomePaciente, TipoDocumento subpasta);
}

public enum TipoDocumento
{
    Declaracoes,
    Consentimentos,
    Prescricoes,
    Receitas,
    Relatorios,
    Analises,
    Outros
}

public class FicheiroInfo
{
    public string Nome { get; set; }
    public string CaminhoCompleto { get; set; }
    public long TamanhoBytes { get; set; }
    public DateTime DataCriacao { get; set; }
    public DateTime DataModificacao { get; set; }
    public TipoDocumento Categoria { get; set; }
    public string Extensao { get; set; }
    public string TamanhoFormatado => /* converte bytes para KB/MB/GB */;
}
```

### 2. DocumentoService Implementação

**Características**:
- ✅ Normaliza nomes de pasta (remove caracteres inválidos)
- ✅ Formato de pasta: `{Id}_{Nome_Normalizado}` (ex: `1_João_Silva`)
- ✅ Cria README.txt automaticamente com informações do paciente
- ✅ Usa `Process.Start()` para abrir Windows Explorer
- ✅ Logging detalhado de todas as operações
- ✅ Tratamento robusto de erros

```csharp
public sealed class DocumentoService : IDocumentoService
{
    private readonly ILogger<DocumentoService> _logger;
    private readonly string _pastaRaiz; // C:\ProgramData\BioDeskPro2\Documentos

    public DocumentoService(ILogger<DocumentoService> logger)
    {
        _logger = logger;
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        _pastaRaiz = Path.Combine(appData, "BioDeskPro2", "Documentos");

        // Criar pasta raiz se não existir
        if (!Directory.Exists(_pastaRaiz))
        {
            Directory.CreateDirectory(_pastaRaiz);
            _logger.LogInformation("📂 Pasta raiz criada: {Pasta}", _pastaRaiz);
        }
    }

    private string NormalizarNomePasta(string nome)
    {
        // Remove caracteres inválidos
        var invalidos = Path.GetInvalidFileNameChars();
        var limpo = string.Concat(nome.Where(c => !invalidos.Contains(c)));

        // Substitui espaços por underscore
        limpo = Regex.Replace(limpo, @"\s+", "_").Trim('_');

        return limpo;
    }

    public void AbrirPastaPaciente(int pacienteId, string nomePaciente, TipoDocumento? subpasta = null)
    {
        var caminho = subpasta.HasValue
            ? ObterSubpastaPaciente(pacienteId, nomePaciente, subpasta.Value)
            : ObterPastaPaciente(pacienteId, nomePaciente);

        // Criar se não existir
        if (!Directory.Exists(caminho))
        {
            CriarEstruturaPastasPacienteAsync(pacienteId, nomePaciente).Wait();
        }

        // Abrir no Explorer
        Process.Start(new ProcessStartInfo
        {
            FileName = caminho,
            UseShellExecute = true,
            Verb = "open"
        });

        _logger.LogInformation("📂 Pasta aberta: {Caminho}", caminho);
    }
}
```

### 3. ComunicacaoViewModel Comandos

```csharp
public partial class ComunicacaoViewModel : ViewModelBase
{
    private readonly IDocumentoService _documentoService;

    [ObservableProperty] private ObservableCollection<string> _anexos = new();
    [ObservableProperty] private string _statusAnexos = string.Empty;

    /// <summary>
    /// ⭐ NOVO: Abre pasta documental do paciente
    /// </summary>
    [RelayCommand]
    private void AbrirPastaPaciente()
    {
        if (PacienteAtual == null)
        {
            ErrorMessage = "Nenhum paciente selecionado!";
            return;
        }

        try
        {
            var nomeCompleto = $"{PacienteAtual.Nome} {PacienteAtual.Apelido}".Trim();
            _documentoService.AbrirPastaPaciente(PacienteAtual.Id, nomeCompleto);

            _logger.LogInformation("📂 Pasta aberta para paciente {Id}", PacienteAtual.Id);
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Erro ao abrir pasta: {ex.Message}";
            _logger.LogError(ex, "Erro ao abrir pasta do paciente");
        }
    }

    /// <summary>
    /// ⭐ NOVO: Adiciona anexo usando diálogo de ficheiros
    /// Abre automaticamente na pasta do paciente se existir
    /// </summary>
    [RelayCommand]
    private void AdicionarAnexo()
    {
        if (PacienteAtual == null)
        {
            ErrorMessage = "Nenhum paciente selecionado!";
            return;
        }

        try
        {
            var nomeCompleto = $"{PacienteAtual.Nome} {PacienteAtual.Apelido}".Trim();
            var openFileDialog = new OpenFileDialog
            {
                Title = "Selecionar Anexos",
                Filter = "Todos os ficheiros (*.*)|*.*|PDFs (*.pdf)|*.pdf|Imagens (*.png;*.jpg;*.jpeg)|*.png;*.jpg;*.jpeg",
                Multiselect = true
            };

            // ⭐ NOVO: Abre automaticamente na pasta do paciente
            var pastaPaciente = _documentoService.ObterPastaPaciente(PacienteAtual.Id, nomeCompleto);
            if (_documentoService.PastaExiste(PacienteAtual.Id, nomeCompleto))
            {
                openFileDialog.InitialDirectory = pastaPaciente;
            }

            if (openFileDialog.ShowDialog() == true)
            {
                foreach (var ficheiro in openFileDialog.FileNames)
                {
                    if (!Anexos.Contains(ficheiro))
                    {
                        Anexos.Add(ficheiro);
                    }
                }

                AtualizarStatusAnexos();
                _logger.LogInformation("📎 {Count} anexos adicionados", openFileDialog.FileNames.Length);
            }
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Erro ao adicionar anexo: {ex.Message}";
            _logger.LogError(ex, "Erro ao adicionar anexo");
        }
    }

    [RelayCommand]
    private void RemoverAnexo(string caminhoAnexo)
    {
        Anexos.Remove(caminhoAnexo);
        AtualizarStatusAnexos();
        _logger.LogInformation("🗑️ Anexo removido: {Caminho}", caminhoAnexo);
    }

    private void AtualizarStatusAnexos()
    {
        if (Anexos.Count == 0)
            StatusAnexos = "Nenhum anexo";
        else if (Anexos.Count == 1)
            StatusAnexos = $"1 anexo ({Path.GetFileName(Anexos[0])})";
        else
            StatusAnexos = $"{Anexos.Count} anexos";
    }
}
```

### 4. Registo no DI Container (App.xaml.cs)

```csharp
using BioDesk.Services.Documentos;

private static void ConfigureServices(IServiceCollection services)
{
    // ...

    // === DOCUMENTO SERVICE (gestão de pastas por paciente) ===
    services.AddSingleton<IDocumentoService, DocumentoService>();

    // ...
}
```

---

## 🚀 Fluxos de Utilizador

### Fluxo 1: Abrir Pasta do Paciente

1. Utilizador abre ficha de paciente (aba Comunicação)
2. Clica no botão "📂 Abrir Pasta"
3. Sistema:
   - Verifica se pasta existe
   - Se não: Cria estrutura completa (pastas + README.txt)
   - Abre Windows Explorer na pasta do paciente
4. Utilizador vê 7 subpastas + README.txt

### Fluxo 2: Anexar Ficheiro a Email

1. Utilizador compõe email na aba Comunicação
2. Clica em "📎 Anexar Ficheiro"
3. Sistema:
   - Abre `OpenFileDialog`
   - Se pasta do paciente existe → Define `InitialDirectory` para a pasta
   - Se não existe → Abre em `Meus Documentos` (padrão Windows)
4. Utilizador seleciona ficheiro(s) da pasta do paciente (ou outra)
5. Ficheiros aparecem na lista de anexos
6. Utilizador pode remover com ❌

### Fluxo 3: Guardar PDF Gerado Automaticamente

```csharp
// Exemplo futuro: Ao gerar PDF de Prescrição
var pdfPath = _prescricaoPdfService.GerarPDF(prescricao);

// Copiar para pasta do paciente automaticamente
var destino = await _documentoService.CopiarFicheiroParaPacienteAsync(
    pdfPath,
    paciente.Id,
    $"{paciente.Nome} {paciente.Apelido}",
    TipoDocumento.Prescricoes
);

_logger.LogInformation("📄 PDF copiado para: {Destino}", destino);
```

---

## 📊 Casos de Uso Avançados

### 1. Listar Todos os Ficheiros do Paciente

```csharp
var ficheiros = await _documentoService.ListarFicheirosPacienteAsync(
    pacienteId: 1,
    nomePaciente: "João Silva",
    subpasta: null // Todas as subpastas
);

foreach (var f in ficheiros)
{
    Console.WriteLine($"{f.Nome} ({f.TamanhoFormatado}) - {f.Categoria}");
}
```

### 2. Listar Apenas Prescrições

```csharp
var prescricoes = await _documentoService.ListarFicheirosPacienteAsync(
    pacienteId: 1,
    nomePaciente: "João Silva",
    subpasta: TipoDocumento.Prescricoes
);
```

### 3. Abrir Subpasta Específica

```csharp
_documentoService.AbrirPastaPaciente(
    pacienteId: 1,
    nomePaciente: "João Silva",
    subpasta: TipoDocumento.Analises
);
// Abre diretamente C:\...\1_João_Silva\Analises\
```

---

## ⚠️ Considerações Importantes

### 1. Localização da Pasta Raiz

- **Windows**: `C:\ProgramData\BioDeskPro2\Documentos\`
- **Razão**: `CommonApplicationData` é acessível por todos os utilizadores
- **Alternativa**: `AppData\Local` se preferir por utilizador

### 2. Normalização de Nomes

- Remove: `\ / : * ? " < > |` (caracteres inválidos)
- Espaços → `_` (underscore)
- Exemplo: `"João Silva" → "João_Silva"`

### 3. Conflitos de Nome

- Sistema usa formato `{Id}_{Nome}` → ID garante unicidade
- Exemplo: `1_João_Silva`, `2_João_Silva` (dois Joãos diferentes)

### 4. Ficheiros Duplicados

- Se ficheiro com mesmo nome já existir → Adiciona timestamp
- Exemplo: `Prescricao.pdf` → `Prescricao_20251001_143022.pdf`

### 5. Performance

- `ListarFicheirosPacienteAsync` pode ser lento com muitos ficheiros
- Considerar paginação se > 100 ficheiros por paciente
- Cache de `FicheiroInfo` se listagem frequente

---

## 🎯 Próximas Funcionalidades (Futuro)

### 1. Vista de Galeria na UI

```csharp
// Tab adicional: "📁 Documentos" na ficha paciente
public partial class DocumentosViewModel : ViewModelBase
{
    [ObservableProperty] private ObservableCollection<FicheiroInfo> _ficheiros = new();

    private async Task CarregarFicheirosAsync()
    {
        Ficheiros = new ObservableCollection<FicheiroInfo>(
            await _documentoService.ListarFicheirosPacienteAsync(PacienteAtual.Id, nomeCompleto)
        );
    }
}
```

### 2. Preview de PDFs

- Integrar `PdfiumViewer` ou `PDFSharp`
- Mostrar preview inline ao clicar em ficheiro

### 3. Pesquisa de Documentos

```csharp
var resultados = ficheiros.Where(f =>
    f.Nome.Contains(termoPesquisa, StringComparison.OrdinalIgnoreCase) ||
    f.Categoria.ToString().Contains(termoPesquisa, StringComparison.OrdinalIgnoreCase)
);
```

### 4. Upload de Ficheiros via Drag & Drop

- Arrastar ficheiros para área de anexos
- Copiar automaticamente para pasta do paciente

### 5. Sincronização Cloud (OneDrive/Dropbox)

- Configurar pasta raiz para cloud storage
- Acesso remoto aos documentos

---

## ✅ Checklist de Implementação

- [x] Interface `IDocumentoService` definida
- [x] Implementação `DocumentoService` completa
- [x] Registo no DI container
- [x] Comandos no `ComunicacaoViewModel`
- [x] UI: Botão "📂 Abrir Pasta"
- [x] UI: Secção de anexos melhorada
- [x] Diálogo abre na pasta do paciente
- [x] Normalização de nomes de pasta
- [x] Criação de README.txt automático
- [x] Logging detalhado
- [x] Tratamento de erros robusto
- [ ] Testes unitários (futuro)
- [ ] Vista de galeria de documentos (futuro)
- [ ] Preview de PDFs (futuro)

---

## 🧪 Como Testar

1. **Build e Executar**
   ```bash
   dotnet build
   dotnet run --project src/BioDesk.App
   ```

2. **Abrir Ficha de Paciente**
   - Selecionar paciente da lista
   - Navegar para aba "Comunicação"

3. **Testar Botão "📂 Abrir Pasta"**
   - Clicar no botão azul "📂 Abrir Pasta"
   - Verificar se abre Windows Explorer
   - Verificar estrutura de subpastas criada

4. **Testar Anexos**
   - Clicar em "📎 Anexar Ficheiro"
   - Verificar se diálogo abre na pasta do paciente
   - Selecionar múltiplos ficheiros
   - Verificar lista de anexos na UI
   - Testar remover anexo com ❌

5. **Verificar Logs**
   - Logs em Output do Visual Studio
   - Procurar mensagens: "📂 Pasta criada", "📎 X anexos adicionados"

---

## 📚 Referências

- **Path API**: `System.IO.Path`
- **Process API**: `System.Diagnostics.Process`
- **OpenFileDialog**: `Microsoft.Win32.OpenFileDialog`
- **Environment.SpecialFolder**: `CommonApplicationData`

---

**🎉 Sistema completamente funcional e pronto para uso!**
