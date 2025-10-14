# 📋 Resumo da Sessão - 09 Outubro 2025

## ✅ SISTEMA DE TEMPLATES E DOCUMENTOS EXTERNOS - CAMADAS COMPLETAS

### 🎯 Objetivo
Implementar sistema completo de gestão de templates globais da clínica e documentos externos dos pacientes (análises, exames, receitas de outros médicos).

---

## ✅ TRABALHO COMPLETADO

### 1️⃣ **CAMADA DE DATABASE** (Completada)
**Entities criadas:**
- `TemplateGlobal.cs` - Templates da clínica e documentos externos importados
  - Propriedades: Id, Nome, Tipo (TemplateApp|DocumentoExterno), CaminhoArquivo, Categoria, DisponivelEmail, DataAdicao, DataAtualizacao, IsDeleted
  - Tipo distingue entre templates da aplicação vs. documentos externos importados
  - DisponivelEmail permite marcar quais devem aparecer como opção de anexo em emails

- `DocumentoExternoPaciente.cs` - Documentos externos específicos de cada paciente
  - Propriedades: Id, PacienteId, NomeArquivo, CaminhoArquivo, Categoria, DataDocumento, DataUpload, TamanhoBytes, TipoMime, IsDeleted
  - Navigation property: Paciente (virtual)
  - Categorias: Análises, Imagiologia, Receitas, Relatórios, Outros

**Repositories criados:**
- `ITemplateGlobalRepository` + `TemplateGlobalRepository`
  - Métodos: GetAllActiveAsync, GetTemplatesDisponiveisEmailAsync, GetByTipoAsync, GetByCategoriaAsync
- `IDocumentoExternoPacienteRepository` + `DocumentoExternoPacienteRepository`
  - Métodos: GetAllActiveAsync, GetByPacienteIdAsync, GetByCategoriaAsync

**DbContext atualizado:**
- `BioDeskDbContext.cs` - Adicionados DbSets e configurações de índices:
  ```csharp
  public DbSet<TemplateGlobal> TemplatesGlobais { get; set; }
  public DbSet<DocumentoExternoPaciente> DocumentosExternosPacientes { get; set; }

  // Índices para performance:
  IX_TemplatesGlobais_Tipo
  IX_TemplatesGlobais_DisponivelEmail
  IX_DocumentosExternos_PacienteId
  IX_DocumentosExternos_Categoria
  IX_DocumentosExternos_DataDocumento
  ```

**Unit of Work atualizado:**
- `IUnitOfWork` + `UnitOfWork` - Adicionadas propriedades:
  ```csharp
  ITemplateGlobalRepository TemplatesGlobais { get; }
  IDocumentoExternoPacienteRepository DocumentosExternos { get; }
  ```

**Migration aplicada:**
- `20251009112209_AddTemplatesAndExternalDocuments.cs`
- Criadas tabelas com índices
- Aplicada com sucesso à base de dados

---

### 2️⃣ **CAMADA DE SERVICES** (Completada)
**Services criados:**

**ITemplateGlobalService + TemplateGlobalService:**
- `GetAllTemplatesAsync()` - Todos os templates ativos
- `GetTemplatesDisponiveisEmailAsync()` - Templates marcados para email
- `GetTemplatesPorCategoriaAsync(categoria)` - Filtra por categoria
- `GetTemplateByIdAsync(id)` - Busca por ID
- `AdicionarTemplateAsync(...)` - Adiciona template/documento
- `AtualizarTemplateAsync(template)` - Atualiza metadados
- `RemoverTemplateAsync(id)` - Soft delete
- `AlterarDisponibilidadeEmailAsync(id, disponivel)` - Toggle disponibilidade
- `ImportarDocumentoExternoAsync(...)` - **Copia ficheiro para Templates_Globais/** e regista na BD
  - Gera nome único com timestamp
  - Cria caminho relativo para portabilidade
  - Marca como tipo "DocumentoExterno"

**IDocumentoExternoPacienteService + DocumentoExternoPacienteService:**
- `GetDocumentosPorPacienteAsync(pacienteId)` - Todos os documentos do paciente
- `GetDocumentosPorCategoriaAsync(pacienteId, categoria)` - Filtra por categoria
- `GetDocumentoByIdAsync(id)` - Busca por ID
- `AdicionarDocumentoAsync(...)` - **Copia ficheiro para Pacientes/{NomeCompleto}/Documentos_Externos/** e regista
  - Cria pasta se não existir
  - Determina MIME type automaticamente
  - Calcula tamanho do ficheiro
  - Gera nome único com timestamp
- `AtualizarDocumentoAsync(documento)` - Atualiza metadados
- `RemoverDocumentoAsync(id)` - Soft delete + **apaga ficheiro físico**
- `GetCaminhoCompletoDocumento(documento)` - Retorna caminho absoluto
- `DocumentoExiste(documento)` - Verifica se ficheiro existe fisicamente

**Correções aplicadas durante desenvolvimento:**
- Missing using statements (System, System.IO, System.Linq, etc.)
- Namespace correto: `BioDesk.Data.Repositories` (não `BioDesk.Data`)
- PathService é static class (sem injeção de dependência)
- Property names: `DocumentosExternos` (não `DocumentosExternosPacientes` no IUnitOfWork)
- Entity properties: `Paciente.NomeCompleto` (não `Nome`)
- Total: 8 correções de property names, 2 correções de namespaces, adição de using statements

**Registados no DI container (App.xaml.cs):**
```csharp
services.AddScoped<ITemplateGlobalService, TemplateGlobalService>();
services.AddScoped<IDocumentoExternoPacienteService, DocumentoExternoPacienteService>();
```

---

### 3️⃣ **CAMADA DE VIEWMODELS** (Completada)
**ViewModels criados:**

**TemplatesGlobalViewModel:**
- **Propriedades:**
  - `Templates` (ObservableCollection) - Todos os templates carregados
  - `TemplateSelecionado` - Template atualmente selecionado
  - `FiltroNome`, `FiltroTipo`, `FiltroCategoria` - Filtros de pesquisa
  - `IsLoading`, `ErrorMessage` - Estados UI

- **Comandos:**
  - `InicializarAsync()` - Carrega todos os templates ao iniciar
  - `AplicarFiltros()` - Filtragem reativa ao mudar propriedades
  - `ImportarDocumentoExternoCommand` - Importa ficheiro externo
  - `AlterarDisponibilidadeEmailCommand` - Toggle checkbox disponibilidade
  - `RemoverTemplateCommand` - Soft delete template
  - `VisualizarTemplateCommand` - Abre ficheiro no viewer padrão do sistema

- **Error Handling:**
  - `ExecuteWithErrorHandlingAsync()` - Padrão obrigatório conforme copilot-instructions.md
  - Try/catch + logging em todas as operações
  - ErrorMessage binding para feedback visual

**DocumentosExternosViewModel:**
- **Propriedades:**
  - `PacienteId` - ID do paciente atual
  - `Documentos` (ObservableCollection) - Documentos do paciente
  - `DocumentoSelecionado` - Documento atualmente selecionado
  - `FiltroCategoria` - Filtro por categoria
  - `IsLoading`, `ErrorMessage` - Estados UI

- **Comandos:**
  - `InicializarParaPacienteAsync(pacienteId)` - Inicializa para paciente específico
  - `CarregarDocumentosAsync()` - Recarrega documentos (com filtros)
  - `AdicionarDocumentoCommand` - Upload novo documento
  - `AtualizarDocumentoCommand` - Atualiza metadados
  - `RemoverDocumentoCommand` - Remove documento (DB + ficheiro)
  - `VisualizarDocumentoCommand` - Abre documento no viewer

- **Helper Methods:**
  - `FormatarTamanho(bytes)` - Formata tamanho do ficheiro (B/KB/MB)

**Registados no DI container (App.xaml.cs):**
```csharp
services.AddTransient<TemplatesGlobalViewModel>();
services.AddTransient<DocumentosExternosViewModel>();
```

**Correções aplicadas:**
- Método `AtualizarTemplateAsync` (não `UpdateTemplateAsync`)
- Método `RemoverTemplateAsync` (não `RemoveTemplateAsync`)
- PathService.TemplatesPath (não `TemplatesGlobaisPath`)
- Parâmetro `caminhoOrigem` (não `caminhoArquivo`) no AdicionarDocumentoAsync

---

## ✅ BUILD STATUS: 100% LIMPO
```
0 Errors, 36 Warnings (apenas AForge compatibility - não-críticos)
Todas as camadas compilam sem erros
DI container configurado corretamente
```

---

## 🔄 PRÓXIMOS PASSOS (Views XAML)

### 4️⃣ **Atualizar ConfiguraçõesView** (ViewModel já existe - ConfiguracaoClinicaViewModel)
Adicionar novo TabItem "Templates & Documentos":
- **DataGrid** para listar templates:
  - Colunas: Nome, Tipo, Categoria, DisponivelEmail (checkbox), Ações (Ver/Apagar)
- **Botões**:
  - "Importar Documento Externo" → OpenFileDialog
  - "Apagar" → RemoverTemplateCommand com confirmação
  - "Ver" → VisualizarTemplateCommand
- **Filtros**: TextBox (Nome), ComboBox (Tipo), ComboBox (Categoria)
- **Binding**: `DataContext="{Binding TemplatesGlobalViewModel}"` (adicionar ao ConfiguracaoClinicaViewModel)

### 5️⃣ **Atualizar FichaPacienteView**
Adicionar novo TabItem "Documentos Externos" ao TabControl existente:
- **DataGrid** para listar documentos do paciente:
  - Colunas: NomeArquivo, Categoria, DataDocumento, TamanhoBytes (formatado), Ações (Ver/Apagar)
- **Botões**:
  - "Upload Documento" → OpenFileDialog + Dialog de metadados (categoria, data)
  - "Ver" → VisualizarDocumentoCommand
  - "Apagar" → RemoverDocumentoCommand com confirmação
- **Filtros**: ComboBox (Categoria)
- **Binding**: `DataContext="{Binding DocumentosExternosViewModel}"` (adicionar ao FichaPacienteViewModel)
- **Inicialização**: `await DocumentosExternosViewModel.InicializarParaPacienteAsync(PacienteAtivo.Id)`

### 6️⃣ **Atualizar EmailView** (integração de templates como anexos)
Adicionar secção "Templates Disponíveis" após área de anexos atual:
- **Expander** com título "Templates da Clínica"
- **ItemsControl** com CheckBox para cada template disponível:
  ```xaml
  <ItemsControl ItemsSource="{Binding TemplatesDisponiveis}">
      <ItemsControl.ItemTemplate>
          <DataTemplate>
              <CheckBox Content="{Binding Nome}"
                        IsChecked="{Binding Selecionado}"
                        Margin="0,2"/>
          </DataTemplate>
      </ItemsControl.ItemTemplate>
  </ItemsControl>
  ```
- **EmailViewModel**:
  - Adicionar propriedade `TemplatesDisponiveis` (ObservableCollection)
  - Carregar em `InicializarAsync()`: `await _templateService.GetTemplatesDisponiveisEmailAsync()`
  - Anexar ficheiros selecionados ao enviar email

### 7️⃣ **Implementar cabeçalhos profissionais em PDFs**
Atualizar serviços PDF para incluir logo da clínica e informações:
- **PrescricaoPdfService.cs**
- **ConsentimentoPdfService.cs**
- **DeclaracaoSaudePdfService.cs**

Criar método partilhado:
```csharp
private void RenderProfessionalHeader(IContainer container, ConfiguracaoClinica config)
{
    container.Row(row =>
    {
        row.Spacing(10);

        // Logo circular (se existir)
        if (File.Exists(config.CaminhoLogo))
        {
            row.ConstantItem(80).Image(config.CaminhoLogo)
                .FitArea();
        }

        // Informações da clínica
        row.RelativeItem().Column(column =>
        {
            column.Item().Text(config.NomeClinica)
                .FontSize(16).Bold();
            column.Item().Text($"NIF: {config.Nif}");
            column.Item().Text($"Tel: {config.Telefone} | Email: {config.Email}");
            column.Item().Text($"Morada: {config.Morada}, {config.CodigoPostal} {config.Cidade}");
        });
    });
}
```

---

## 📦 ARQUIVOS CRIADOS NESTA SESSÃO

### Domain Layer
- `src/BioDesk.Domain/Entities/TemplateGlobal.cs`
- `src/BioDesk.Domain/Entities/DocumentoExternoPaciente.cs`

### Data Layer
- `src/BioDesk.Data/Repositories/ITemplateGlobalRepository.cs`
- `src/BioDesk.Data/Repositories/TemplateGlobalRepository.cs`
- `src/BioDesk.Data/Repositories/IDocumentoExternoPacienteRepository.cs`
- `src/BioDesk.Data/Repositories/DocumentoExternoPacienteRepository.cs`
- `src/BioDesk.Data/Migrations/20251009112209_AddTemplatesAndExternalDocuments.cs`

### Service Layer
- `src/BioDesk.Services/Templates/ITemplateGlobalService.cs`
- `src/BioDesk.Services/Templates/TemplateGlobalService.cs`
- `src/BioDesk.Services/Documentos/IDocumentoExternoPacienteService.cs`
- `src/BioDesk.Services/Documentos/DocumentoExternoPacienteService.cs`

### ViewModel Layer
- `src/BioDesk.ViewModels/Templates/TemplatesGlobalViewModel.cs`
- `src/BioDesk.ViewModels/Documentos/DocumentosExternosViewModel.cs`

### Configuration
- `src/BioDesk.App/App.xaml.cs` (atualizado - DI registrations)
- `src/BioDesk.Data/BioDeskDbContext.cs` (atualizado - DbSets + índices)
- `src/BioDesk.Data/Repositories/IUnitOfWork.cs` (atualizado - propriedades)
- `src/BioDesk.Data/Repositories/UnitOfWork.cs` (atualizado - lazy initialization)

---

## 🎓 LIÇÕES APRENDIDAS

### 1. **Verificação de Nomes de Métodos/Propriedades**
Sempre verificar interfaces antes de implementar ViewModels:
- ✅ `AtualizarTemplateAsync` (não `UpdateTemplateAsync`)
- ✅ `RemoverTemplateAsync` (não `RemoveTemplateAsync`)
- ✅ `DocumentosExternos` (não `DocumentosExternosPacientes`)

### 2. **PathService é Static Class**
Não injetar como dependência, usar diretamente:
```csharp
// ERRADO:
public TemplateGlobalService(IPathService pathService) { }

// CORRETO:
PathService.TemplatesPath
PathService.AppDataPath
```

### 3. **Padrão Dispose CA1063**
Warnings de dispose resolvidos previamente (CameraService, RealCameraService) - não interferem neste sistema.

### 4. **EF Core Migration Errors**
`HostAbortedException` durante `dotnet ef database update` é artefacto não-crítico do EF Tools bootstrap - ignorar se migration aplicada com sucesso.

### 5. **Error Handling Obrigatório**
Sempre implementar `ExecuteWithErrorHandlingAsync()` em ViewModels:
- Try/catch com logging
- ErrorMessage binding para UI
- IsLoading states para feedback visual

---

## 📊 PROGRESSO GERAL DO PROJETO

### ✅ TAREFAS COMPLETADAS (5 pedidos originais)
1. ✅ **Live search** - Lista de pacientes com filtragem em tempo real
2. ⏳ **Botões Cancelar/Abortar** - Auditoria pendente
3. 🔄 **Sistema de Templates** - 75% completo (falta Views XAML)
4. ✅ **Ajustes prescrição** - Ícone 24px, texto legal alterado
5. ✅ **Campos de consulta** - Grid 3 colunas, campos renomeados

### 🔄 EM PROGRESSO
- Sistema de Templates & Documentos Externos (camadas Database/Services/ViewModels ✅, Views XAML ⏳)

### ⏳ PRÓXIMA SESSÃO
- Criar/atualizar Views XAML (ConfiguraçõesView, FichaPacienteView, EmailView)
- Implementar cabeçalhos PDF profissionais com logo
- Auditoria de botões Cancelar/Abortar em todas as janelas

---

## 🔧 COMANDOS ÚTEIS

### Build & Test
```powershell
dotnet clean
dotnet restore
dotnet build --no-incremental
dotnet test
```

### Run Application
```powershell
dotnet run --project src/BioDesk.App
```

### Database Migrations
```powershell
# Ver migrations aplicadas
dotnet ef migrations list --project src/BioDesk.Data

# Aplicar migrations
dotnet ef database update --project src/BioDesk.Data --startup-project src/BioDesk.App
```

---

**📅 Data:** 09 Outubro 2025
**⏱️ Duração:** ~2h
**✅ Status:** Camadas Database/Services/ViewModels completadas com sucesso. Views XAML pendentes para próxima sessão.
