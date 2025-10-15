# ✅ Checklist de Integração - ItemBancoCoreSeeder.cs

**Data**: 15 de Outubro de 2025
**Objetivo**: Garantir integração correta do seed data gerado por Codex/ChatGPT

---

## 📥 FASE 1: Receber o Código

### Localização do Ficheiro:
```
src/BioDesk.Data/SeedData/ItemBancoCoreSeeder.cs
```

### Verificação Visual:
- [ ] Ficheiro tem extensão `.cs`
- [ ] Namespace correto: `BioDesk.Data.SeedData`
- [ ] Classe é `public static`
- [ ] Tem método `GetAll()` que retorna `List<ItemBancoCore>`
- [ ] Tem método `ValidateAll()` no final

---

## 🔍 FASE 2: Validação de Conteúdo

### Estrutura Obrigatória:
```csharp
using System;
using System.Collections.Generic;
using System.Text.Json;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Data.SeedData;

public static class ItemBancoCoreSeeder
{
    public static List<ItemBancoCore> GetAll()
    {
        var items = new List<ItemBancoCore>();
        items.AddRange(GetFloraisBach());      // Mínimo 38
        items.AddRange(GetChakras());          // Mínimo 28
        items.AddRange(GetMeridianos());       // Mínimo 20
        // ... outras categorias
        return items;
    }

    private static List<ItemBancoCore> GetFloraisBach() { ... }
    private static List<ItemBancoCore> GetChakras() { ... }
    // ... outros métodos

    public static void ValidateAll() { ... }
}
```

### Checklist de Conteúdo:
- [ ] **Mínimo 86 itens** (38 Bach + 28 Chakras + 20 Meridianos)
- [ ] Todos os itens têm `ExternalId` (GUID)
- [ ] Todos os itens têm `Nome` não-vazio
- [ ] Todos os itens têm `Categoria` (enum válido)
- [ ] Todos os itens têm `JsonMetadata` não-null
- [ ] Todos os itens têm `FonteOrigem` preenchida
- [ ] Todos os itens têm `GeneroAplicavel` ("Masculino"/"Feminino"/"Ambos")
- [ ] Florais Bach: TODOS têm `GeneroAplicavel = "Ambos"`
- [ ] Chakras: TODOS têm `GeneroAplicavel = "Ambos"`
- [ ] Emoções: TODAS têm `GeneroAplicavel = "Ambos"`

### Verificação de Género (CRÍTICO):
- [ ] Se existir "Próstata" → `GeneroAplicavel = "Masculino"`
- [ ] Se existir "Testículos" → `GeneroAplicavel = "Masculino"`
- [ ] Se existir "Ovários" → `GeneroAplicavel = "Feminino"`
- [ ] Se existir "Útero" → `GeneroAplicavel = "Feminino"`
- [ ] Se existir "Mama" → `GeneroAplicavel = "Feminino"`

---

## 🏗️ FASE 3: Compilação

### Comandos PowerShell:
```powershell
# 1. Restaurar dependências (caso necessário)
dotnet restore

# 2. Build limpo
dotnet clean
dotnet build

# 3. Verificar erros
# Deve mostrar: "Build succeeded. 0 Error(s)"
```

### Checklist de Build:
- [ ] Build **SEM ERROS**
- [ ] Warnings aceitáveis (apenas AForge camera se existirem)
- [ ] Namespace `BioDesk.Domain.Enums` reconhecido
- [ ] `CategoriaCore` enum acessível
- [ ] `ItemBancoCore` entity acessível

### Erros Comuns e Soluções:

| Erro | Solução |
|------|---------|
| `CategoriaCore não encontrado` | Adicionar `using BioDesk.Domain.Enums;` |
| `ItemBancoCore não encontrado` | Adicionar `using BioDesk.Domain.Entities;` |
| `JsonSerializer não encontrado` | Adicionar `using System.Text.Json;` |
| `Guid.Parse() inválido` | Verificar formato GUID (36 caracteres) |
| `DateTime.UtcNow inacessível` | Adicionar `using System;` |

---

## ✅ FASE 4: Validação de Dados

### Criar Ficheiro de Teste:
```
src/BioDesk.Tests/SeedData/ItemBancoCoreSeederTests.cs
```

### Código de Teste Básico:
```csharp
using Xunit;
using BioDesk.Data.SeedData;
using BioDesk.Domain.Enums;

namespace BioDesk.Tests.SeedData;

public class ItemBancoCoreSeederTests
{
    [Fact]
    public void GetAll_DeveRetornarItens()
    {
        // Act
        var items = ItemBancoCoreSeeder.GetAll();

        // Assert
        Assert.NotNull(items);
        Assert.NotEmpty(items);
        Assert.True(items.Count >= 86, $"Esperados min 86 itens, encontrados {items.Count}");
    }

    [Fact]
    public void GetAll_DeveTer38FloraisBach()
    {
        // Act
        var items = ItemBancoCoreSeeder.GetAll();
        var bachCount = items.Count(x => x.Categoria == CategoriaCore.FloraisBach);

        // Assert
        Assert.Equal(38, bachCount);
    }

    [Fact]
    public void GetAll_DeveTer28Chakras()
    {
        // Act
        var items = ItemBancoCoreSeeder.GetAll();
        var chakraCount = items.Count(x => x.Categoria == CategoriaCore.Chakra);

        // Assert
        Assert.Equal(28, chakraCount);
    }

    [Fact]
    public void GetAll_ZeroGuidsDuplicados()
    {
        // Act
        var items = ItemBancoCoreSeeder.GetAll();
        var duplicates = items.GroupBy(x => x.ExternalId)
                              .Where(g => g.Count() > 1)
                              .ToList();

        // Assert
        Assert.Empty(duplicates);
    }

    [Fact]
    public void GetAll_TodosComJsonMetadata()
    {
        // Act
        var items = ItemBancoCoreSeeder.GetAll();
        var semMetadata = items.Where(x => string.IsNullOrEmpty(x.JsonMetadata)).ToList();

        // Assert
        Assert.Empty(semMetadata);
    }

    [Fact]
    public void ValidateAll_NaoDeveLancarException()
    {
        // Act & Assert
        var exception = Record.Exception(() => ItemBancoCoreSeeder.ValidateAll());
        Assert.Null(exception);
    }
}
```

### Executar Testes:
```powershell
dotnet test src/BioDesk.Tests --filter "ItemBancoCoreSeederTests"
```

### Checklist de Testes:
- [ ] `GetAll_DeveRetornarItens` → PASS
- [ ] `GetAll_DeveTer38FloraisBach` → PASS
- [ ] `GetAll_DeveTer28Chakras` → PASS
- [ ] `GetAll_ZeroGuidsDuplicados` → PASS
- [ ] `GetAll_TodosComJsonMetadata` → PASS
- [ ] `ValidateAll_NaoDeveLancarException` → PASS

---

## 🗄️ FASE 5: Migration da Base de Dados

### Criar Migration:
```powershell
# No terminal do VS Code:
cd src/BioDesk.Data
dotnet ef migrations add AddItemBancoCore -s ../BioDesk.App
```

### Checklist de Migration:
- [ ] Ficheiro `*_AddItemBancoCore.cs` criado em `Migrations/`
- [ ] Método `Up()` contém `migrationBuilder.CreateTable("ItensBancoCore", ...)`
- [ ] Método `Down()` contém `migrationBuilder.DropTable("ItensBancoCore")`
- [ ] Todos os 7 índices criados:
  - IX_ItensBancoCore_ExternalId (UNIQUE)
  - IX_ItensBancoCore_Categoria
  - IX_ItensBancoCore_Nome
  - IX_ItensBancoCore_Subcategoria
  - IX_ItensBancoCore_GeneroAplicavel
  - IX_ItensBancoCore_IsActive
  - IX_ItensBancoCore_Categoria_Active_Genero (composto)

### Aplicar Migration:
```powershell
dotnet ef database update -s ../BioDesk.App
```

### Verificar Tabela Criada:
```powershell
# Abrir SQLite database browser
# Ou via terminal:
sqlite3 biodesk.db ".tables"
# Deve listar: ItensBancoCore
```

---

## 📊 FASE 6: Seed da Base de Dados

### Opção 1: Via DbContext.OnModelCreating (Recomendado)
```csharp
// Em BioDeskDbContext.cs, método SeedData():
private static void SeedData(ModelBuilder modelBuilder)
{
    // ... seeds existentes ...

    // SEED: Itens Core Informacional
    var itensCore = ItemBancoCoreSeeder.GetAll();
    modelBuilder.Entity<ItemBancoCore>().HasData(itensCore);
}
```

⚠️ **ATENÇÃO**: Seeds grandes podem aumentar tempo de migration!

### Opção 2: Via Código (Mais Flexível)
```csharp
// Criar serviço de inicialização
public class DatabaseInitializer
{
    private readonly BioDeskDbContext _context;

    public DatabaseInitializer(BioDeskDbContext context)
    {
        _context = context;
    }

    public async Task SeedItemsBancoCoreAsync()
    {
        // Verificar se já existem itens
        if (await _context.ItensBancoCore.AnyAsync())
        {
            Console.WriteLine("Itens Core já existem. Skip seed.");
            return;
        }

        var items = ItemBancoCoreSeeder.GetAll();
        await _context.ItensBancoCore.AddRangeAsync(items);
        await _context.SaveChangesAsync();

        Console.WriteLine($"✅ {items.Count} itens Core inseridos com sucesso!");
    }
}
```

### Executar Seed (App.xaml.cs):
```csharp
// Em App.xaml.cs, método OnStartup():
protected override async void OnStartup(StartupEventArgs e)
{
    base.OnStartup(e);

    var scope = _serviceProvider.CreateScope();
    var context = scope.ServiceProvider.GetRequiredService<BioDeskDbContext>();

    var initializer = new DatabaseInitializer(context);
    await initializer.SeedItemsBancoCoreAsync();

    // ... resto do código de inicialização
}
```

---

## 🧪 FASE 7: Testes de Query

### Testar Queries Básicas:
```csharp
[Fact]
public async Task Query_FloraisBachAtivos()
{
    // Arrange
    var context = CreateTestContext();
    await SeedTestData(context);

    // Act
    var florais = await context.ItensBancoCore
        .Where(x => x.Categoria == CategoriaCore.FloraisBach)
        .Where(x => x.IsActive)
        .ToListAsync();

    // Assert
    Assert.Equal(38, florais.Count);
}

[Fact]
public async Task Query_OrgaosMasculinos()
{
    // Arrange
    var context = CreateTestContext();
    await SeedTestData(context);

    // Act
    var orgaosMasc = await context.ItensBancoCore
        .Where(x => x.Categoria == CategoriaCore.Orgao)
        .Where(x => x.GeneroAplicavel == "Masculino")
        .ToListAsync();

    // Assert
    Assert.NotEmpty(orgaosMasc);
    Assert.All(orgaosMasc, x =>
        Assert.Contains(x.Nome.ToLower(), new[] { "próstata", "testículo", "pénis" })
    );
}
```

---

## 📝 FASE 8: Documentação Final

### Criar Relatório de Implementação:
```
RESUMO_IMPLEMENTACAO_CORE.md
```

### Conteúdo do Relatório:
```markdown
# Resumo Implementação - Sistema Core Informacional

## ✅ Implementado

- [x] Entidade ItemBancoCore (12 propriedades)
- [x] Enum CategoriaCore (14 categorias)
- [x] DbContext configurado (7 índices)
- [x] ItemBancoCoreSeeder.cs (X itens)
  - [x] 38 Florais de Bach
  - [x] 28 Chakras
  - [x] 20 Meridianos
  - [x] X Homeopatia
  - [x] X Emoções
  - [x] X Órgãos
- [x] Método ValidateAll()
- [x] Migration aplicada
- [x] Seed data inserido (X registos)
- [x] Testes unitários (6 testes ✅)

## 📊 Estatísticas

| Categoria | Itens | Género "Ambos" | Género Específico |
|-----------|-------|----------------|-------------------|
| FloraisBach | 38 | 38 | 0 |
| Chakra | 28 | 28 | 0 |
| Meridiano | 20 | 20 | 0 |
| Orgao | X | Y | Z |
| **TOTAL** | **X** | **Y** | **Z** |

## 🎯 Próximos Passos

1. [ ] Expandir categorias restantes (Vitaminas, Minerais, etc.)
2. [ ] Integrar com CoreAnaliseService
3. [ ] UI de pesquisa e listagem
4. [ ] Sistema de transmissão informacional

## 🔗 Ficheiros Criados

- `src/BioDesk.Domain/Entities/ItemBancoCore.cs`
- `src/BioDesk.Domain/Enums/CategoriaCore.cs`
- `src/BioDesk.Data/SeedData/ItemBancoCoreSeeder.cs`
- `src/BioDesk.Data/Migrations/*_AddItemBancoCore.cs`
- `src/BioDesk.Tests/SeedData/ItemBancoCoreSeederTests.cs`
- `SEED_DATA_CORE_INFORMACIONAL.md`
```

---

## ✅ CHECKLIST FINAL

### Código:
- [ ] `ItemBancoCoreSeeder.cs` existe em `src/BioDesk.Data/SeedData/`
- [ ] Build passa sem erros
- [ ] Todos os testes passam (6/6 ✅)
- [ ] ValidateAll() executa sem exception

### Base de Dados:
- [ ] Migration criada
- [ ] Migration aplicada
- [ ] Tabela `ItensBancoCore` existe
- [ ] 7 índices criados
- [ ] Dados inseridos (min 86 registos)

### Validação:
- [ ] Zero GUIDs duplicados
- [ ] Género correto em órgãos reprodutores
- [ ] Todos os itens têm JsonMetadata
- [ ] Todos os itens têm FonteOrigem
- [ ] Totais corretos por categoria

### Documentação:
- [ ] `SEED_DATA_CORE_INFORMACIONAL.md` criado
- [ ] `RESUMO_IMPLEMENTACAO_CORE.md` criado
- [ ] Comentários inline no código

---

**Status Final**: ✅ Tudo pronto para produção | 🚀 Sistema Core Informacional operacional
