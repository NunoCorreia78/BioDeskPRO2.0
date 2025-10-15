# 🎯 Próximos Passos - Banco Core (156 Itens)

**Data**: 15 de Outubro 2025
**Status Atual**: ✅ Seed completo, 156 itens na BD confirmados via logs

---

## ✅ **O QUE JÁ ESTÁ FEITO**

1. ✅ Entidade `ItemBancoCore` criada (`src/BioDesk.Domain/Entities/`)
2. ✅ Enum `CategoriaCore` (BachFlorais, Chakras, Meridianos, Orgaos)
3. ✅ Seeder com 156 itens (`ItemBancoCoreSeeder.cs`)
4. ✅ Migration da tabela `ItensBancoCore` executada
5. ✅ Método `EnsureItensBancoCoreSeeded()` no `BioDeskDbContext`
6. ✅ Seed automático no startup (`App.xaml.cs:254`)
7. ✅ Logging em ficheiro diário funcionando
8. ✅ Validação via logs: `EXISTS = TRUE` (dados presentes)

---

## 🎯 **PASSO 2: Repository Layer** (Data Access)

### **Objetivo**
Criar camada de acesso estruturado aos 156 itens, em vez de usar `DbContext` diretamente nas ViewModels.

### **Ficheiros a Criar**

#### **A) Interface**
```
📁 src/BioDesk.Data/Repositories/IItemBancoCoreRepository.cs
```

```csharp
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Data.Repositories;

public interface IItemBancoCoreRepository
{
    /// <summary>
    /// Retorna todos os 156 itens ativos do Banco Core
    /// </summary>
    Task<List<ItemBancoCore>> GetAllAsync();

    /// <summary>
    /// Retorna itens filtrados por categoria (ex: só Bach Florais)
    /// </summary>
    Task<List<ItemBancoCore>> GetByCategoriaAsync(CategoriaCore categoria);

    /// <summary>
    /// Busca item específico por ExternalId (Guid único)
    /// </summary>
    Task<ItemBancoCore?> GetByExternalIdAsync(Guid externalId);

    /// <summary>
    /// Pesquisa por nome (ex: "chakra" retorna todos os chakras)
    /// </summary>
    Task<List<ItemBancoCore>> SearchAsync(string termo);

    /// <summary>
    /// Conta total de itens por categoria (validação)
    /// </summary>
    Task<Dictionary<CategoriaCore, int>> GetCountPorCategoriaAsync();
}
```

#### **B) Implementação**
```
📁 src/BioDesk.Data/Repositories/ItemBancoCoreRepository.cs
```

```csharp
using Microsoft.EntityFrameworkCore;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Data.Repositories;

public class ItemBancoCoreRepository : IItemBancoCoreRepository
{
    private readonly BioDeskDbContext _context;

    public ItemBancoCoreRepository(BioDeskDbContext context)
    {
        _context = context;
    }

    public async Task<List<ItemBancoCore>> GetAllAsync()
    {
        return await _context.ItensBancoCore
            .Where(i => i.Ativo)
            .OrderBy(i => i.Categoria)
            .ThenBy(i => i.Nome)
            .ToListAsync();
    }

    public async Task<List<ItemBancoCore>> GetByCategoriaAsync(CategoriaCore categoria)
    {
        return await _context.ItensBancoCore
            .Where(i => i.Ativo && i.Categoria == categoria)
            .OrderBy(i => i.Nome)
            .ToListAsync();
    }

    public async Task<ItemBancoCore?> GetByExternalIdAsync(Guid externalId)
    {
        return await _context.ItensBancoCore
            .FirstOrDefaultAsync(i => i.ExternalId == externalId);
    }

    public async Task<List<ItemBancoCore>> SearchAsync(string termo)
    {
        if (string.IsNullOrWhiteSpace(termo))
            return await GetAllAsync();

        var termoLower = termo.ToLower();
        return await _context.ItensBancoCore
            .Where(i => i.Ativo &&
                   (i.Nome.ToLower().Contains(termoLower) ||
                    (i.Notas != null && i.Notas.ToLower().Contains(termoLower))))
            .OrderBy(i => i.Categoria)
            .ThenBy(i => i.Nome)
            .ToListAsync();
    }

    public async Task<Dictionary<CategoriaCore, int>> GetCountPorCategoriaAsync()
    {
        return await _context.ItensBancoCore
            .Where(i => i.Ativo)
            .GroupBy(i => i.Categoria)
            .Select(g => new { Categoria = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Categoria, x => x.Count);
    }
}
```

#### **C) Registar no Dependency Injection**
```
📁 src/BioDesk.App/App.xaml.cs (ConfigureServices)
```

Adicionar após linha ~143:
```csharp
services.AddScoped<IItemBancoCoreRepository, ItemBancoCoreRepository>();
```

---

## 🎯 **PASSO 3: Service Layer** (Business Logic)

### **Objetivo**
Adicionar lógica de negócio, validações e cache. ViewModels chamam Services (não Repositories diretamente).

### **Ficheiros a Criar**

#### **A) Interface**
```
📁 src/BioDesk.Services/Core/IItemBancoCoreService.cs
```

```csharp
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;

namespace BioDesk.Services.Core;

public interface IItemBancoCoreService
{
    /// <summary>
    /// Retorna todos os itens disponíveis (com cache de 5 min)
    /// </summary>
    Task<List<ItemBancoCore>> GetItensDisponiveisAsync();

    /// <summary>
    /// Retorna itens de uma categoria específica
    /// </summary>
    Task<List<ItemBancoCore>> GetItensPorCategoriaAsync(CategoriaCore categoria);

    /// <summary>
    /// Busca item por ExternalId
    /// </summary>
    Task<ItemBancoCore?> GetItemAsync(Guid externalId);

    /// <summary>
    /// Pesquisa com termo (nome, notas)
    /// </summary>
    Task<List<ItemBancoCore>> PesquisarAsync(string termo);

    /// <summary>
    /// Valida integridade do seed (156 itens, 38+28+20+70)
    /// </summary>
    Task<ValidationResult> ValidarIntegridadeAsync();

    /// <summary>
    /// Invalida cache (forçar reload)
    /// </summary>
    void InvalidarCache();
}

public class ValidationResult
{
    public bool IsValido { get; set; }
    public int TotalItens { get; set; }
    public Dictionary<CategoriaCore, int> CountPorCategoria { get; set; } = new();
    public List<string> Erros { get; set; } = new();
}
```

#### **B) Implementação**
```
📁 src/BioDesk.Services/Core/ItemBancoCoreService.cs
```

```csharp
using BioDesk.Data.Repositories;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;
using BioDesk.Services.Cache;
using Microsoft.Extensions.Logging;

namespace BioDesk.Services.Core;

public class ItemBancoCoreService : IItemBancoCoreService
{
    private readonly IItemBancoCoreRepository _repository;
    private readonly ICacheService _cacheService;
    private readonly ILogger<ItemBancoCoreService> _logger;

    private const string CACHE_KEY_ALL = "ItemBancoCore:All";
    private const int CACHE_MINUTES = 5;

    public ItemBancoCoreService(
        IItemBancoCoreRepository repository,
        ICacheService cacheService,
        ILogger<ItemBancoCoreService> logger)
    {
        _repository = repository;
        _cacheService = cacheService;
        _logger = logger;
    }

    public async Task<List<ItemBancoCore>> GetItensDisponiveisAsync()
    {
        var cached = _cacheService.Get<List<ItemBancoCore>>(CACHE_KEY_ALL);
        if (cached != null)
        {
            _logger.LogDebug("Itens Banco Core retornados do cache");
            return cached;
        }

        var itens = await _repository.GetAllAsync();
        _cacheService.Set(CACHE_KEY_ALL, itens, TimeSpan.FromMinutes(CACHE_MINUTES));

        _logger.LogInformation($"Carregados {itens.Count} itens do Banco Core");
        return itens;
    }

    public async Task<List<ItemBancoCore>> GetItensPorCategoriaAsync(CategoriaCore categoria)
    {
        return await _repository.GetByCategoriaAsync(categoria);
    }

    public async Task<ItemBancoCore?> GetItemAsync(Guid externalId)
    {
        return await _repository.GetByExternalIdAsync(externalId);
    }

    public async Task<List<ItemBancoCore>> PesquisarAsync(string termo)
    {
        return await _repository.SearchAsync(termo);
    }

    public async Task<ValidationResult> ValidarIntegridadeAsync()
    {
        var result = new ValidationResult();

        var countPorCategoria = await _repository.GetCountPorCategoriaAsync();
        result.CountPorCategoria = countPorCategoria;
        result.TotalItens = countPorCategoria.Values.Sum();

        // Validar contagens esperadas
        var esperados = new Dictionary<CategoriaCore, int>
        {
            { CategoriaCore.BachFlorais, 38 },
            { CategoriaCore.Chakras, 28 },
            { CategoriaCore.Meridianos, 20 },
            { CategoriaCore.Orgaos, 70 }
        };

        foreach (var (categoria, esperado) in esperados)
        {
            if (!countPorCategoria.TryGetValue(categoria, out var atual) || atual != esperado)
            {
                result.Erros.Add($"{categoria}: esperado {esperado}, encontrado {atual}");
            }
        }

        if (result.TotalItens != 156)
        {
            result.Erros.Add($"Total: esperado 156, encontrado {result.TotalItens}");
        }

        result.IsValido = result.Erros.Count == 0;

        _logger.LogInformation($"Validação Banco Core: {(result.IsValido ? "OK" : "FALHOU")}");
        return result;
    }

    public void InvalidarCache()
    {
        _cacheService.Remove(CACHE_KEY_ALL);
        _logger.LogDebug("Cache do Banco Core invalidado");
    }
}
```

#### **C) Registar no DI**
```
📁 src/BioDesk.App/App.xaml.cs (ConfigureServices)
```

Adicionar:
```csharp
services.AddScoped<IItemBancoCoreService, ItemBancoCoreService>();
```

---

## 🎯 **PASSO 4: UI - Tab Terapias Bioenergéticas**

### **Objetivo**
Interface para o utilizador ver, pesquisar e selecionar os 156 itens para usar em sessões de biofeedback.

### **Ficheiros a Editar/Criar**

#### **A) ViewModel**
```
📁 src/BioDesk.ViewModels/FichaPaciente/TerapiasBioenergeticasViewModel.cs
```

```csharp
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using BioDesk.Domain.Entities;
using BioDesk.Domain.Enums;
using BioDesk.Services.Core;
using System.Collections.ObjectModel;

namespace BioDesk.ViewModels.FichaPaciente;

public partial class TerapiasBioenergeticasViewModel : ViewModelBase
{
    private readonly IItemBancoCoreService _itemBancoCoreService;

    [ObservableProperty]
    private ObservableCollection<ItemBancoCore> _itensDisponiveis = new();

    [ObservableProperty]
    private ObservableCollection<ItemBancoCore> _itensSelecionados = new();

    [ObservableProperty]
    private string _pesquisarTexto = string.Empty;

    [ObservableProperty]
    private CategoriaCore? _categoriaFiltro = null;

    [ObservableProperty]
    private ItemBancoCore? _itemSelecionado;

    public TerapiasBioenergeticasViewModel(IItemBancoCoreService itemBancoCoreService)
    {
        _itemBancoCoreService = itemBancoCoreService;
    }

    [RelayCommand]
    private async Task CarregarItensAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            IsLoading = true;

            var itens = await _itemBancoCoreService.GetItensDisponiveisAsync();
            ItensDisponiveis = new ObservableCollection<ItemBancoCore>(itens);

        }, "ao carregar itens do Banco Core");
    }

    [RelayCommand]
    private async Task PesquisarAsync()
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            if (string.IsNullOrWhiteSpace(PesquisarTexto))
            {
                await CarregarItensAsync();
                return;
            }

            var resultados = await _itemBancoCoreService.PesquisarAsync(PesquisarTexto);
            ItensDisponiveis = new ObservableCollection<ItemBancoCore>(resultados);

        }, "ao pesquisar itens");
    }

    [RelayCommand]
    private async Task FiltrarPorCategoriaAsync(CategoriaCore? categoria)
    {
        await ExecuteWithErrorHandlingAsync(async () =>
        {
            CategoriaFiltro = categoria;

            if (categoria == null)
            {
                await CarregarItensAsync();
                return;
            }

            var itens = await _itemBancoCoreService.GetItensPorCategoriaAsync(categoria.Value);
            ItensDisponiveis = new ObservableCollection<ItemBancoCore>(itens);

        }, "ao filtrar por categoria");
    }

    [RelayCommand]
    private void AdicionarItem(ItemBancoCore? item)
    {
        if (item == null || ItensSelecionados.Contains(item))
            return;

        ItensSelecionados.Add(item);
    }

    [RelayCommand]
    private void RemoverItem(ItemBancoCore? item)
    {
        if (item != null)
        {
            ItensSelecionados.Remove(item);
        }
    }

    [RelayCommand]
    private void LimparSelecao()
    {
        ItensSelecionados.Clear();
    }
}
```

#### **B) View (XAML)**
```
📁 src/BioDesk.App/Views/FichaPaciente/Abas/TerapiasBioenergeticasUserControl.xaml
```

Estrutura básica:
```xml
<UserControl x:Class="BioDesk.App.Views.FichaPaciente.Abas.TerapiasBioenergeticasUserControl"
             xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
             xmlns:d="http://schemas.microsoft.com/expression/blend/2008"
             xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
             xmlns:vm="clr-namespace:BioDesk.ViewModels.FichaPaciente;assembly=BioDesk.ViewModels"
             d:DataContext="{d:DesignInstance Type=vm:TerapiasBioenergeticasViewModel}"
             mc:Ignorable="d">

    <Grid>
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/> <!-- Pesquisa/Filtros -->
            <RowDefinition Height="*"/>    <!-- Lista itens -->
            <RowDefinition Height="Auto"/> <!-- Selecionados -->
        </Grid.RowDefinitions>

        <!-- HEADER: Pesquisa e Filtros -->
        <StackPanel Grid.Row="0" Margin="10">
            <TextBox Text="{Binding PesquisarTexto, UpdateSourceTrigger=PropertyChanged}"
                     Margin="0,0,0,10"/>

            <WrapPanel>
                <Button Content="Todos" Command="{Binding FiltrarPorCategoriaCommand}"
                        CommandParameter="{x:Null}"/>
                <Button Content="Bach Florais" Command="{Binding FiltrarPorCategoriaCommand}"
                        CommandParameter="0"/>
                <Button Content="Chakras" Command="{Binding FiltrarPorCategoriaCommand}"
                        CommandParameter="1"/>
                <Button Content="Meridianos" Command="{Binding FiltrarPorCategoriaCommand}"
                        CommandParameter="2"/>
                <Button Content="Órgãos" Command="{Binding FiltrarPorCategoriaCommand}"
                        CommandParameter="3"/>
            </WrapPanel>
        </StackPanel>

        <!-- LISTA DE ITENS DISPONÍVEIS -->
        <ListBox Grid.Row="1"
                 ItemsSource="{Binding ItensDisponiveis}"
                 SelectedItem="{Binding ItemSelecionado}"
                 Margin="10">
            <ListBox.ItemTemplate>
                <DataTemplate>
                    <StackPanel Orientation="Horizontal">
                        <TextBlock Text="{Binding Nome}" FontWeight="Bold"/>
                        <TextBlock Text="{Binding Categoria}" Margin="10,0,0,0"
                                   Foreground="Gray"/>
                        <Button Content="+" Command="{Binding DataContext.AdicionarItemCommand,
                                RelativeSource={RelativeSource AncestorType=UserControl}}"
                                CommandParameter="{Binding}"
                                Margin="10,0,0,0"/>
                    </StackPanel>
                </DataTemplate>
            </ListBox.ItemTemplate>
        </ListBox>

        <!-- ITENS SELECIONADOS -->
        <Border Grid.Row="2" BorderBrush="Gray" BorderThickness="1" Margin="10">
            <StackPanel>
                <TextBlock Text="Selecionados para Sessão" FontWeight="Bold" Margin="5"/>
                <ItemsControl ItemsSource="{Binding ItensSelecionados}" Margin="5">
                    <ItemsControl.ItemTemplate>
                        <DataTemplate>
                            <StackPanel Orientation="Horizontal">
                                <Button Content="X"
                                        Command="{Binding DataContext.RemoverItemCommand,
                                        RelativeSource={RelativeSource AncestorType=UserControl}}"
                                        CommandParameter="{Binding}"/>
                                <TextBlock Text="{Binding Nome}" Margin="5,0"/>
                            </StackPanel>
                        </DataTemplate>
                    </ItemsControl.ItemTemplate>
                </ItemsControl>
                <Button Content="Limpar Tudo" Command="{Binding LimparSelecaoCommand}"
                        HorizontalAlignment="Right" Margin="5"/>
            </StackPanel>
        </Border>
    </Grid>
</UserControl>
```

#### **C) Registar ViewModel no DI**
```
📁 src/BioDesk.App/App.xaml.cs
```

Adicionar:
```csharp
services.AddTransient<TerapiasBioenergeticasViewModel>();
```

#### **D) Carregar ViewModel na FichaPacienteViewModel**
```
📁 src/BioDesk.ViewModels/FichaPacienteViewModel.cs
```

Adicionar propriedade:
```csharp
public TerapiasBioenergeticasViewModel TerapiasBioenergeticasViewModel { get; }
```

Injetar no construtor:
```csharp
public FichaPacienteViewModel(
    // ... outros parâmetros
    TerapiasBioenergeticasViewModel terapiasBioenergeticasViewModel)
{
    // ... inicializações
    TerapiasBioenergeticasViewModel = terapiasBioenergeticasViewModel;
}
```

---

## ⏱️ **ESTIMATIVA DE TEMPO**

| Passo | Tempo Estimado |
|-------|----------------|
| **Passo 2**: Repository | 15-20 min |
| **Passo 3**: Service | 20-25 min |
| **Passo 4**: UI básica | 30-40 min |
| **Testes manuais** | 10-15 min |
| **TOTAL** | **~90 minutos** |

---

## 🎯 **CRITÉRIOS DE SUCESSO**

Ao completar os 3 passos, deves conseguir:

1. ✅ Abrir Tab 7 (Terapias Bioenergéticas) na Ficha do Paciente
2. ✅ Ver lista dos 156 itens agrupados/filtráveis
3. ✅ Pesquisar por nome (ex: "rescue" encontra "Rescue Remedy")
4. ✅ Filtrar por categoria (só Bach Florais, só Chakras, etc.)
5. ✅ Adicionar itens à seleção da sessão
6. ✅ Remover itens da seleção
7. ✅ Ver contadores (ex: "38 Bach Florais disponíveis")

---

## 📝 **NOTAS TÉCNICAS**

- **Cache**: Service usa ICacheService (5 min) para evitar queries repetidas
- **Lazy Loading**: Itens só carregam quando Tab 7 é aberta
- **Thread-safe**: ObservableCollection atualizada no Dispatcher
- **Logging**: Todas as operações registadas em `Logs/biodesk-YYYYMMDD.log`

---

## 🚀 **COMANDO PARA COMEÇAR**

```bash
# Criar pastas
mkdir -p src/BioDesk.Services/Core

# Criar ficheiros
touch src/BioDesk.Data/Repositories/IItemBancoCoreRepository.cs
touch src/BioDesk.Data/Repositories/ItemBancoCoreRepository.cs
touch src/BioDesk.Services/Core/IItemBancoCoreService.cs
touch src/BioDesk.Services/Core/ItemBancoCoreService.cs
```

---

**Pronto para implementar? Responde "SIM" e implemento tudo automaticamente!** 🚀
