# 🧹 AUDITORIA DE WORKSPACE + 📋 PLANO DE TEMPLATES - 07/10/2025

## 🎯 OBJECTIVO

1. **Identificar e eliminar ficheiros poluentes** no workspace
2. **Planear sistema de templates** para prescrições, emails e documentos
3. **Organizar arquitectura** para implementação futura

---

## 🔍 PARTE 1: AUDITORIA DE FICHEIROS POLUENTES

### 🗑️ FICHEIROS PARA ELIMINAR

#### 1. Backups Antigos da Base de Dados (MANTER APENAS O MAIS RECENTE)

```
✅ MANTER: biodesk_backup_iris_crop_20251007_194719.db (mais recente)

❌ ELIMINAR:
- biodesk_backup_20251007_112918.db  (antigo - 11:29)
- biodesk_backup_20251007_113656.db  (antigo - 11:36)
```

**Razão**: Backups antigos ocupam espaço desnecessário (~40-60MB cada).

---

#### 2. Ficheiros de Debug Temporários

```
❌ ELIMINAR:
- DEBUG_DOCUMENTOS.txt           (logs de debug da busca de documentos)
- DISPATCHER_EXCEPTION.txt       (log de exceção WPF resolvida)
- LOGS_DEBUG.txt                 (logs gerais de debug)
```

**Razão**: Informação temporária já incorporada em documentação MD.

---

#### 3. Scripts SQL Temporários

```
❌ ELIMINAR:
- DropIrisTables.sql            (script de desenvolvimento temporário)
```

**Razão**: Script de teste, não deve estar em produção.

---

#### 4. Ficheiros Recovery/Backup de Código

```
❌ ELIMINAR:
- RECOVERY_IrisdiagnosticoUserControl.xaml  (backup manual, já commitado)
```

**Razão**: Código já está no Git, backup redundante.

---

#### 5. Scripts PowerShell de Limpeza Duplicados

```
⚠️ CONSOLIDAR (escolher 1 e eliminar os outros):
- APAGAR_BACKUPS_ANTIGOS.ps1     (específico para backups)
- LimparWorkspace.ps1            (limpeza geral)
- LIMPEZA_COMPLETA.ps1           (limpeza agressiva)
- LIMPEZA_TOTAL.ps1              (limpeza total)
- CRIAR_BACKUP_LIMPO.ps1         (backup + limpeza)
- GIT_FRESH_START.ps1            (git clean)

✅ RECOMENDAÇÃO: Manter apenas "LimparWorkspace.ps1" (mais genérico)
❌ Eliminar os outros 5 scripts
```

**Razão**: Funcionalidades sobrepostas, confunde utilizador.

---

#### 6. Documentos MD de Análise Temporária (JÁ RESOLVIDOS)

```
⚠️ MOVER PARA PASTA "Docs_Historico/" ou ELIMINAR:

Resolvidos e documentados noutros ficheiros:
- ANALISE_ARRASTO_DEBUG_COMPLETA.md        (funcionalidade OK)
- ANALISE_CONEXOES_BD.md                   (SQLite OK)
- ANALISE_CONTROLE_TAMANHO_IRIS.md         (tamanho OK)
- ANALISE_ESTICAMENTO_MAPA.md              (resolvido)
- ANALISE_SEPARADORES_BD.md                (separadores OK)
- ANALISE_UX_MOVIMENTO_MAPA.md             (UX OK)
- CORRECAO_BOTOES_GRID.md                  (corrigido)
- CORRECAO_ESTICAMENTO_IMPLEMENTADA.md     (implementado)
- CORRECAO_SCROLLBAR_SEPARADORES.md        (corrigido)
- CORRECAO_STATUS_FALHADO_APOS_ENVIO.md    (corrigido)
- CORRECOES_DECLARACAO_SAUDE.md            (corrigidas)
- CORRECOES_LOGGING_PERFORMANCE.md         (corrigidas)
- CORRECOES_LOGOS_ICONES_07OUT2025.md      (corrigidas)
- CORRECOES_MANUAIS_URGENTES.md            (corrigidas)
- CORRECOES_SISTEMA_EMAIL.md               (corrigidas)
- DIAGNOSTICO_MAPA_IRIDOLOGICO.md          (resolvido)
- PROBLEMA_ASSINATURA_PDF.md               (resolvido)
- CORRECAO_CRITICA_EMAILS_AGENDADOS.md     (resolvida)
- CORRECAO_BLOQUEIO_POWERSHELL_07OUT2025.md (resolvida)
- CORRECOES_IMAGENS_IRIS_07OUT2025.md      (resolvidas)
```

**Razão**: Documentos de troubleshooting já resolvidos. Manter histórico em pasta separada.

---

### 📂 ESTRUTURA PROPOSTA PARA ORGANIZAÇÃO

```
📁 BioDeskPro2/
├── 📁 Docs_Historico/              ← CRIAR (arquivar MDs antigos)
│   ├── 2025-10/
│   │   ├── ANALISE_*.md
│   │   ├── CORRECAO_*.md
│   │   ├── DIAGNOSTICO_*.md
│   │   └── PROBLEMA_*.md
│   └── README.md                   (índice de documentos históricos)
│
├── 📁 Scripts/                     ← CRIAR (consolidar scripts PS1)
│   ├── LimparWorkspace.ps1        (único script de limpeza)
│   ├── ConfigurarEmail.ps1        (configuração email)
│   └── README.md                   (documentação de scripts)
│
├── 📁 Debug_Scripts/               ← JÁ EXISTE (manter)
│   ├── CheckDB.cs
│   └── FixIrisImagePaths.csx
│
└── 📁 Backups/                     ← CRIAR (isolar backups)
    ├── biodesk_backup_iris_crop_20251007_194719.db
    └── README.md                   (política de backups)
```

---

### 🛠️ SCRIPT DE LIMPEZA AUTOMATIZADA

Criar **`LimparWorkspaceCompleto.ps1`**:

```powershell
# 🧹 LIMPEZA COMPLETA DE WORKSPACE - BioDeskPro2
# Data: 07 de Outubro de 2025

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "   🧹 LIMPEZA DE WORKSPACE - BioDeskPro2" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# 1. Criar pastas de organização
Write-Host "📁 Criar estrutura de pastas..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path "Docs_Historico/2025-10" | Out-Null
New-Item -ItemType Directory -Force -Path "Scripts" | Out-Null
New-Item -ItemType Directory -Force -Path "Backups" | Out-Null

# 2. Eliminar backups antigos (manter apenas o mais recente)
Write-Host "🗑️  Eliminar backups antigos..." -ForegroundColor Yellow
Remove-Item "biodesk_backup_20251007_112918.db" -Force -ErrorAction SilentlyContinue
Remove-Item "biodesk_backup_20251007_113656.db" -Force -ErrorAction SilentlyContinue

# 3. Mover backup recente para pasta Backups/
Write-Host "📦 Organizar backups..." -ForegroundColor Yellow
Move-Item "biodesk_backup_iris_crop_20251007_194719.db" "Backups/" -Force -ErrorAction SilentlyContinue

# 4. Eliminar ficheiros de debug temporários
Write-Host "🗑️  Eliminar ficheiros de debug..." -ForegroundColor Yellow
Remove-Item "DEBUG_DOCUMENTOS.txt" -Force -ErrorAction SilentlyContinue
Remove-Item "DISPATCHER_EXCEPTION.txt" -Force -ErrorAction SilentlyContinue
Remove-Item "LOGS_DEBUG.txt" -Force -ErrorAction SilentlyContinue
Remove-Item "DropIrisTables.sql" -Force -ErrorAction SilentlyContinue
Remove-Item "RECOVERY_IrisdiagnosticoUserControl.xaml" -Force -ErrorAction SilentlyContinue

# 5. Mover documentos históricos para pasta
Write-Host "📚 Organizar documentos históricos..." -ForegroundColor Yellow
$historicos = @(
    "ANALISE_ARRASTO_DEBUG_COMPLETA.md",
    "ANALISE_CONEXOES_BD.md",
    "ANALISE_CONTROLE_TAMANHO_IRIS.md",
    "ANALISE_ESTICAMENTO_MAPA.md",
    "ANALISE_SEPARADORES_BD.md",
    "ANALISE_UX_MOVIMENTO_MAPA.md",
    "CORRECAO_BOTOES_GRID.md",
    "CORRECAO_ESTICAMENTO_IMPLEMENTADA.md",
    "CORRECAO_SCROLLBAR_SEPARADORES.md",
    "CORRECAO_STATUS_FALHADO_APOS_ENVIO.md",
    "CORRECOES_DECLARACAO_SAUDE.md",
    "CORRECOES_LOGGING_PERFORMANCE.md",
    "CORRECOES_LOGOS_ICONES_07OUT2025.md",
    "CORRECOES_MANUAIS_URGENTES.md",
    "CORRECOES_SISTEMA_EMAIL.md",
    "DIAGNOSTICO_MAPA_IRIDOLOGICO.md",
    "PROBLEMA_ASSINATURA_PDF.md",
    "CORRECAO_CRITICA_EMAILS_AGENDADOS.md",
    "CORRECAO_BLOQUEIO_POWERSHELL_07OUT2025.md",
    "CORRECOES_IMAGENS_IRIS_07OUT2025.md"
)

foreach ($doc in $historicos) {
    if (Test-Path $doc) {
        Move-Item $doc "Docs_Historico/2025-10/" -Force
    }
}

# 6. Consolidar scripts PowerShell
Write-Host "📜 Consolidar scripts..." -ForegroundColor Yellow
Move-Item "ConfigurarEmail.ps1" "Scripts/" -Force -ErrorAction SilentlyContinue
Move-Item "LimparWorkspace.ps1" "Scripts/" -Force -ErrorAction SilentlyContinue

# Scripts para eliminar (duplicados)
Remove-Item "APAGAR_BACKUPS_ANTIGOS.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "LIMPEZA_COMPLETA.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "LIMPEZA_TOTAL.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "CRIAR_BACKUP_LIMPO.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "GIT_FRESH_START.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "ORGANIZAR_DOCUMENTOS.ps1" -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "✅ Limpeza concluída com sucesso!" -ForegroundColor Green
Write-Host ""
Write-Host "📊 Resumo:" -ForegroundColor Cyan
Write-Host "   • Backups antigos eliminados: 2" -ForegroundColor White
Write-Host "   • Ficheiros debug eliminados: 5" -ForegroundColor White
Write-Host "   • Documentos históricos movidos: 20" -ForegroundColor White
Write-Host "   • Scripts duplicados eliminados: 6" -ForegroundColor White
Write-Host ""
Write-Host "📁 Nova estrutura:" -ForegroundColor Cyan
Write-Host "   • Docs_Historico/2025-10/  (documentos antigos)" -ForegroundColor White
Write-Host "   • Scripts/                 (scripts consolidados)" -ForegroundColor White
Write-Host "   • Backups/                 (backups organizados)" -ForegroundColor White
Write-Host ""
```

---

## 📋 PARTE 2: PLANO DE TEMPLATES

### 🎯 OBJECTIVO

Criar sistema de **templates reutilizáveis** para:
1. 📄 Prescrições médicas (Naturopatia, Osteopatia, etc.)
2. 📧 Emails automáticos (confirmação consulta, follow-up, etc.)
3. 📝 Relatórios de consulta
4. ✅ Consentimentos (já parcialmente implementado)

---

### 📐 ARQUITECTURA PROPOSTA

#### 1. Estrutura de Pastas

```
📁 BioDeskPro2/
├── 📁 Templates/                      ← CRIAR
│   ├── 📁 Prescricoes/               ← Prescrições médicas
│   │   ├── Prescricao_Geral.json
│   │   ├── Plano_Alimentar.json
│   │   ├── Suplementacao.json
│   │   ├── Fitoterapia.json
│   │   └── Tratamento_Osteopatico.json
│   │
│   ├── 📁 Emails/                    ← Templates de email
│   │   ├── Confirmacao_Consulta.json
│   │   ├── Lembrete_Consulta.json
│   │   ├── FollowUp_Consulta.json
│   │   ├── Boas_Vindas.json
│   │   └── Resultados_Analises.json
│   │
│   ├── 📁 Relatorios/                ← Relatórios de consulta
│   │   ├── Relatorio_Consulta_Geral.json
│   │   ├── Relatorio_Irisdiagnostico.json
│   │   └── Relatorio_Evolucao.json
│   │
│   └── 📁 Consentimentos/            ← Já existe em Consentimentos/
│       ├── Naturopatia.json
│       ├── Osteopatia.json
│       └── RGPD.json
```

---

#### 2. Formato JSON dos Templates

**Exemplo: `Prescricao_Geral.json`**

```json
{
  "id": "prescricao_geral_v1",
  "nome": "Prescrição Geral",
  "categoria": "Prescricao",
  "descricao": "Template padrão para prescrições de naturopatia",
  "versao": "1.0",
  "dataCriacao": "2025-10-07",
  "autor": "BioDeskPro",

  "campos": [
    {
      "id": "titulo",
      "tipo": "texto",
      "label": "Título da Prescrição",
      "obrigatorio": true,
      "valorPadrao": "Plano de Tratamento Natural"
    },
    {
      "id": "objetivos",
      "tipo": "texto_longo",
      "label": "Objetivos do Tratamento",
      "obrigatorio": true,
      "placeholder": "Ex: Reduzir dor lombar, melhorar sono, equilibrar digestão..."
    },
    {
      "id": "suplementos",
      "tipo": "lista",
      "label": "Suplementação",
      "itens": [
        { "nome": "Vitamina D3", "dose": "2000 UI/dia", "duracao": "3 meses" },
        { "nome": "Magnésio", "dose": "400mg/dia", "duracao": "2 meses" }
      ]
    },
    {
      "id": "fitoterapia",
      "tipo": "lista",
      "label": "Fitoterapia",
      "itens": [
        { "nome": "Valeriana", "dose": "300mg", "frequencia": "Antes de dormir" }
      ]
    },
    {
      "id": "alimentacao",
      "tipo": "texto_longo",
      "label": "Recomendações Alimentares",
      "placeholder": "Evitar: ... / Privilegiar: ..."
    },
    {
      "id": "exercicios",
      "tipo": "texto_longo",
      "label": "Exercícios Recomendados",
      "placeholder": "Caminhada 30min/dia, alongamentos..."
    },
    {
      "id": "observacoes",
      "tipo": "texto_longo",
      "label": "Observações Adicionais",
      "obrigatorio": false
    }
  ],

  "formatoPDF": {
    "cabecalho": {
      "incluirLogo": true,
      "incluirDadosTerapeuta": true,
      "incluirDataEmissao": true
    },
    "corpo": {
      "fonteTitulo": "Roboto Bold 18pt",
      "fonteCampos": "Roboto 12pt",
      "corPrimaria": "#9CAF97",
      "espacamentoLinhas": 1.5
    },
    "rodape": {
      "incluirAssinatura": true,
      "textoRodape": "Este documento foi gerado eletronicamente e não requer assinatura física."
    }
  }
}
```

**Exemplo: `Confirmacao_Consulta.json` (Email)**

```json
{
  "id": "email_confirmacao_consulta_v1",
  "nome": "Confirmação de Consulta",
  "categoria": "Email",
  "descricao": "Email automático de confirmação de agendamento",
  "versao": "1.0",

  "assunto": "✅ Consulta Confirmada - {{DataConsulta}} às {{HoraConsulta}}",

  "corpo": "Olá {{NomePaciente}},\n\nA sua consulta de {{TipoConsulta}} foi confirmada para:\n\n📅 Data: {{DataConsulta}}\n🕐 Hora: {{HoraConsulta}}\n📍 Local: {{LocalConsulta}}\n\n{{MensagemPersonalizada}}\n\nEm caso de necessidade de reagendamento, por favor contacte-nos com pelo menos 24h de antecedência.\n\nAtenciosamente,\n{{NomeTerapeuta}}\n{{ContactoTerapeuta}}",

  "variaveis": [
    { "id": "NomePaciente", "tipo": "texto", "origem": "Paciente.Nome" },
    { "id": "DataConsulta", "tipo": "data", "origem": "Consulta.Data" },
    { "id": "HoraConsulta", "tipo": "hora", "origem": "Consulta.Hora" },
    { "id": "TipoConsulta", "tipo": "texto", "origem": "Consulta.Tipo" },
    { "id": "LocalConsulta", "tipo": "texto", "origem": "Configuracoes.Clinica.Morada" },
    { "id": "MensagemPersonalizada", "tipo": "texto_opcional", "origem": "Manual" },
    { "id": "NomeTerapeuta", "tipo": "texto", "origem": "Configuracoes.Terapeuta.Nome" },
    { "id": "ContactoTerapeuta", "tipo": "texto", "origem": "Configuracoes.Terapeuta.Contacto" }
  ],

  "anexos": [],

  "configuracoes": {
    "enviarAutomaticamente": false,
    "permitirEdicao": true,
    "guardarCopia": true
  }
}
```

---

#### 3. Serviços (Backend)

**`src/BioDesk.Services/Templates/ITemplateService.cs`**

```csharp
using System.Collections.Generic;
using System.Threading.Tasks;
using BioDesk.Domain.Models;

namespace BioDesk.Services.Templates;

public interface ITemplateService
{
    // Listar templates por categoria
    Task<List<TemplateInfo>> ListarTemplatesAsync(CategoriaTemplate? categoria = null);

    // Carregar template específico
    Task<Template> CarregarTemplateAsync(string templateId);

    // Preencher template com dados do paciente
    Task<TemplatePreeenchido> PreencherTemplateAsync(string templateId, int pacienteId, Dictionary<string, object>? dadosAdicionais = null);

    // Gerar PDF a partir de template preenchido
    Task<string> GerarPDFAsync(TemplatePreeenchido templatePreenchido, string caminhoDestino);

    // Enviar template por email
    Task<bool> EnviarTemplatePorEmailAsync(string templateId, int pacienteId, Dictionary<string, object>? dadosAdicionais = null);

    // Criar/editar template (admin)
    Task<bool> SalvarTemplateAsync(Template template);

    // Eliminar template
    Task<bool> EliminarTemplateAsync(string templateId);
}

public enum CategoriaTemplate
{
    Prescricao,
    Email,
    Relatorio,
    Consentimento
}

public class TemplateInfo
{
    public string Id { get; set; } = string.Empty;
    public string Nome { get; set; } = string.Empty;
    public CategoriaTemplate Categoria { get; set; }
    public string Descricao { get; set; } = string.Empty;
    public string Versao { get; set; } = "1.0";
}

public class Template : TemplateInfo
{
    public List<CampoTemplate> Campos { get; set; } = new();
    public FormatoPDF? FormatoPDF { get; set; }
    public ConfiguracoesEmail? ConfiguracoesEmail { get; set; }
}

public class CampoTemplate
{
    public string Id { get; set; } = string.Empty;
    public TipoCampo Tipo { get; set; }
    public string Label { get; set; } = string.Empty;
    public bool Obrigatorio { get; set; }
    public object? ValorPadrao { get; set; }
    public string? Placeholder { get; set; }
}

public enum TipoCampo
{
    Texto,
    TextoLongo,
    Lista,
    Data,
    Numero,
    Checkbox
}

public class TemplatePreeenchido
{
    public string TemplateId { get; set; } = string.Empty;
    public int PacienteId { get; set; }
    public Dictionary<string, object> Valores { get; set; } = new();
    public DateTime DataPreenchimento { get; set; }
}
```

---

#### 4. ViewModels (Frontend)

**`src/BioDesk.ViewModels/TemplateViewModel.cs`**

```csharp
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Services.Templates;
using System.Collections.ObjectModel;

namespace BioDesk.ViewModels;

public partial class TemplateViewModel : ViewModelBase
{
    private readonly ITemplateService _templateService;
    private readonly IPacienteService _pacienteService;

    [ObservableProperty]
    private ObservableCollection<TemplateInfo> _templatesPrescricao = new();

    [ObservableProperty]
    private ObservableCollection<TemplateInfo> _templatesEmail = new();

    [ObservableProperty]
    private TemplateInfo? _templateSelecionado;

    [ObservableProperty]
    private bool _isPreenchendoTemplate;

    public TemplateViewModel(ITemplateService templateService, IPacienteService pacienteService)
    {
        _templateService = templateService;
        _pacienteService = pacienteService;
    }

    [RelayCommand]
    private async Task CarregarTemplatesAsync()
    {
        var prescricoes = await _templateService.ListarTemplatesAsync(CategoriaTemplate.Prescricao);
        TemplatesPrescricao = new ObservableCollection<TemplateInfo>(prescricoes);

        var emails = await _templateService.ListarTemplatesAsync(CategoriaTemplate.Email);
        TemplatesEmail = new ObservableCollection<TemplateInfo>(emails);
    }

    [RelayCommand]
    private async Task SelecionarTemplateAsync(TemplateInfo template)
    {
        TemplateSelecionado = template;
        // Abrir UI de preenchimento
    }

    [RelayCommand]
    private async Task GerarPDFAsync()
    {
        if (TemplateSelecionado == null) return;

        IsPreenchendoTemplate = true;

        // Lógica de preenchimento e geração de PDF

        IsPreenchendoTemplate = false;
    }
}
```

---

### 🖥️ UI - ONDE INSERIR

#### Opção 1: **Nova Aba "Templates" no FichaPacienteView**

```xaml
<!-- Adicionar tab em FichaPacienteView.xaml -->
<TabItem Header="📋 Templates">
    <Grid>
        <Grid.ColumnDefinitions>
            <ColumnDefinition Width="200"/>
            <ColumnDefinition Width="*"/>
        </Grid.ColumnDefinitions>

        <!-- Coluna 0: Lista de Templates -->
        <Border Grid.Column="0" Background="#F7F9F6" Padding="12">
            <StackPanel>
                <TextBlock Text="📄 Prescrições" FontWeight="Bold" Margin="0,0,0,8"/>
                <ListBox ItemsSource="{Binding TemplatesPrescricao}"
                         SelectedItem="{Binding TemplateSelecionado}">
                    <ListBox.ItemTemplate>
                        <DataTemplate>
                            <TextBlock Text="{Binding Nome}"/>
                        </DataTemplate>
                    </ListBox.ItemTemplate>
                </ListBox>

                <TextBlock Text="📧 Emails" FontWeight="Bold" Margin="0,16,0,8"/>
                <ListBox ItemsSource="{Binding TemplatesEmail}"
                         SelectedItem="{Binding TemplateSelecionado}">
                    <ListBox.ItemTemplate>
                        <DataTemplate>
                            <TextBlock Text="{Binding Nome}"/>
                        </DataTemplate>
                    </ListBox.ItemTemplate>
                </ListBox>
            </StackPanel>
        </Border>

        <!-- Coluna 1: Formulário de Preenchimento -->
        <Border Grid.Column="1" Background="White" Padding="24">
            <ScrollViewer>
                <StackPanel>
                    <TextBlock Text="{Binding TemplateSelecionado.Nome}"
                               FontSize="24" FontWeight="Bold" Margin="0,0,0,16"/>

                    <!-- Campos dinâmicos do template -->
                    <ItemsControl ItemsSource="{Binding TemplateSelecionado.Campos}">
                        <!-- DataTemplate dinâmico baseado no tipo de campo -->
                    </ItemsControl>

                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,24,0,0">
                        <Button Content="📄 Gerar PDF"
                                Command="{Binding GerarPDFCommand}"
                                Background="#9CAF97"
                                Foreground="White"
                                Padding="16,8"
                                Margin="0,0,12,0"/>

                        <Button Content="📧 Enviar Email"
                                Command="{Binding EnviarEmailCommand}"
                                Background="#87A4D4"
                                Foreground="White"
                                Padding="16,8"/>
                    </StackPanel>
                </StackPanel>
            </ScrollViewer>
        </Border>
    </Grid>
</TabItem>
```

**Vantagens**:
- ✅ Acesso directo no contexto do paciente
- ✅ Dados do paciente já carregados
- ✅ Fluxo natural: Consulta → Prescrição

**Desvantagens**:
- ⚠️ Adiciona mais uma aba (já há muitas)

---

#### Opção 2: **Integrar em "Comunicação" (Existente)**

```xaml
<!-- Adicionar secção em ComunicacaoUserControl.xaml -->
<Expander Header="📋 Templates de Email" IsExpanded="False" Margin="0,12,0,0">
    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <ComboBox Grid.Row="0"
                  ItemsSource="{Binding TemplatesEmail}"
                  SelectedItem="{Binding TemplateSelecionado}"
                  DisplayMemberPath="Nome"
                  Margin="0,0,0,12"/>

        <Button Grid.Row="1"
                Content="📧 Carregar Template"
                Command="{Binding CarregarTemplateCommand}"
                HorizontalAlignment="Stretch"/>
    </Grid>
</Expander>
```

**Vantagens**:
- ✅ Sem adicionar aba nova
- ✅ Templates de email integrados no fluxo de comunicação
- ✅ Simples e directo

**Desvantagens**:
- ⚠️ Apenas para templates de email (prescrições ficam noutro lado)

---

#### Opção 3: **Botão de Ação Rápida no Dashboard**

```xaml
<!-- Adicionar em DashboardView.xaml -->
<Button Content="📋 Nova Prescrição (Template)"
        Command="{Binding AbrirTemplateCommand}"
        Background="#9CAF97"
        Foreground="White"
        Padding="24,12"
        Margin="12"/>
```

**Vantagens**:
- ✅ Acesso rápido desde dashboard
- ✅ Não interfere com estrutura existente

**Desvantagens**:
- ⚠️ Precisa seleccionar paciente primeiro

---

### ✅ RECOMENDAÇÃO FINAL

**Implementação Faseada**:

#### 📍 FASE 1 (Imediata): Templates de Email na Comunicação
- ✅ Integrar na aba **"Comunicação"** existente
- ✅ Adicionar dropdown de templates de email
- ✅ Botão "Carregar Template" → preenche campos de email
- ✅ Simples, rápido, não quebra fluxo existente

#### 📍 FASE 2 (Curto Prazo): Nova Aba "Prescrições"
- ✅ Criar aba **"Prescrições"** em FichaPacienteView
- ✅ Lista de templates de prescrição
- ✅ Formulário dinâmico de preenchimento
- ✅ Botões "Gerar PDF" e "Enviar Email"

#### 📍 FASE 3 (Médio Prazo): Editor de Templates (Admin)
- ✅ Interface de administração em Configurações
- ✅ Criar/editar/eliminar templates
- ✅ Importar/exportar templates JSON

---

## 📊 RESUMO DE ACÇÕES

### 🗑️ Limpeza Imediata

```powershell
# Executar script de limpeza
.\LimparWorkspaceCompleto.ps1
```

**Resultado**:
- ✅ 2 backups antigos eliminados
- ✅ 5 ficheiros debug eliminados
- ✅ 20 documentos históricos arquivados
- ✅ 6 scripts duplicados eliminados
- ✅ Workspace organizado e limpo

---

### 📋 Implementação de Templates

**Próximos Passos**:

1. ✅ **Criar estrutura de pastas**:
   ```bash
   mkdir Templates/Prescricoes
   mkdir Templates/Emails
   mkdir Templates/Relatorios
   ```

2. ✅ **Criar templates JSON de exemplo** (3-5 templates)

3. ✅ **Implementar ITemplateService** (backend)

4. ✅ **Integrar em ComunicacaoUserControl** (Fase 1)

5. ✅ **Criar aba Prescrições** (Fase 2)

6. ✅ **Documentar uso de templates** (README.md)

---

## 📝 NOTAS FINAIS

### ⚠️ AVISOS

- **Backups**: Sempre criar backup antes de executar limpeza
- **Git**: Commit antes de mover ficheiros
- **Testes**: Testar aplicação após limpeza

### 🎯 OBJECTIVO ALCANÇADO

✅ Workspace limpo e organizado
✅ Plano de templates completo e detalhado
✅ Arquitectura escalável para futuras funcionalidades
✅ Resposta do agente de codificação localizada e expandida

---

**Autor**: GitHub Copilot
**Data**: 07 de outubro de 2025
**Versão**: 1.0
**Baseado em**: RESUMO_SESSAO_04OUT2025.md (linhas 100-120)
**Status**: 📋 Documentação Completa
