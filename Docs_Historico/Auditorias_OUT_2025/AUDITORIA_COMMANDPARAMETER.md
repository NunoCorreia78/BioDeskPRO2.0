# 🔍 AUDITORIA PREVENTIVA - CommandParameter Type Safety

**Data**: 02/10/2025  
**Contexto**: Correção de `ArgumentException` em `SelecionarTodosDocumentosCommand` devido a incompatibilidade de tipos entre XAML CommandParameter e assinatura do comando.

---

## 🚨 PROBLEMA ORIGINAL

### Erro Runtime
```
ArgumentException: Parameter 'parameter' (object) cannot be of type System.String, 
as the command type requires an argument of type System.Boolean
```

### Causa Raiz
WPF passa `CommandParameter="True"` como **System.String**, mas `RelayCommand<bool>` espera **System.Boolean**.

### Solução Implementada
Mudei a assinatura do comando para aceitar `object?` e fazer conversão segura:

```csharp
[RelayCommand]
private void SelecionarTodosDocumentos(object? parameter)
{
    bool selecionar = parameter switch
    {
        bool b => b,
        string s when bool.TryParse(s, out var result) => result,
        _ => false
    };

    foreach (var doc in DocumentosPaciente)
    {
        doc.Selecionado = selecionar;
    }
}
```

**XAML simplificado**:
```xaml
<Button CommandParameter="True" .../>
<Button CommandParameter="False" .../>
```

---

## ✅ AUDITORIA COMPLETA - RESULTADOS

### 1. CommandParameter com Strings Literais

#### ✅ **FichaPacienteView.xaml** - SEGURO
```xaml
CommandParameter="1"
CommandParameter="2"
...
CommandParameter="6"
```

**ViewModel**: `void NavegarParaAba(object parameter)` ✅  
**Status**: ✅ Aceita `object`, faz parse interno

---

### 2. CommandParameter com {Binding}

#### ✅ **RegistoConsultasUserControl.xaml** - SEGURO
```xaml
CommandParameter="{Binding}"  <!-- Binding retorna Sessao -->
```

**ViewModel**: `void AbrirDetalhesConsulta(Sessao sessao)` ✅  
**Status**: ✅ Tipo correto, binding retorna objeto `Sessao`

#### ✅ **DeclaracaoSaudeUserControl.xaml** - SEGURO
```xaml
CommandParameter="{Binding}"  <!-- Binding retorna Cirurgia, Medicacao, etc -->
```

**ViewModels**:
- `void RemoverCirurgia(Cirurgia? cirurgia)` ✅
- `void RemoverMedicacao(Medicacao? medicacao)` ✅
- `void RemoverAlergia(Alergia? alergia)` ✅
- `void RemoverAntecedenteFamiliar(AntecedenteFamiliar? antecedente)` ✅

**Status**: ✅ Todos os tipos correspondem aos objetos retornados pelo binding

#### ✅ **ComunicacaoUserControl.xaml** - SEGURO
```xaml
CommandParameter="{Binding}"  <!-- Binding retorna string (caminho ficheiro) -->
```

**ViewModel**: `void RemoverAnexo(string caminhoFicheiro)` ✅  
**Status**: ✅ Tipo correto, ItemsSource é `ObservableCollection<string>`

---

## 📋 CHECKLIST PREVENTIVO

Para EVITAR erros semelhantes no futuro:

### ✅ Ao criar comandos com parâmetros:

1. **SEMPRE** usar `object?` se houver dúvida sobre o tipo do CommandParameter
2. **SEMPRE** fazer conversão segura com pattern matching ou `TryParse`
3. **SEMPRE** logar tipo recebido em caso de erro
4. **NUNCA** assumir tipo automático do XAML

### ✅ Ao usar CommandParameter no XAML:

1. **STRINGS LITERAIS** → Comando deve aceitar `object` ou `string`
2. **BINDINGS** → Verificar tipo do objeto retornado pelo DataContext
3. **NÚMEROS** → Passar como string e fazer parse no comando
4. **BOOLEANS** → Passar como string ("True"/"False") e fazer parse

### ⚠️ SINAIS DE ALERTA:

- `RelayCommand<int>` com `CommandParameter="1"` → ❌ Vai falhar
- `RelayCommand<bool>` com `CommandParameter="True"` → ❌ Vai falhar
- `RelayCommand<MyClass>` com `CommandParameter="{Binding}"` → ⚠️ Verificar tipo do binding

### ✅ PADRÕES SEGUROS:

```csharp
// PADRÃO RECOMENDADO - Aceitar object e converter
[RelayCommand]
private void MeuComando(object? parameter)
{
    if (parameter is int numero)
    {
        // Usar numero
    }
    else if (int.TryParse(parameter?.ToString(), out var numeroParseado))
    {
        // Usar numeroParseado
    }
}
```

```csharp
// ALTERNATIVA - Tipos complexos com binding correto
[RelayCommand]
private void RemoverItem(MinhaEntidade? entidade)
{
    if (entidade is null) return;
    // Usar entidade
}
```

```xaml
<!-- XAML correspondente -->
<Button Command="{Binding RemoverItemCommand}" 
        CommandParameter="{Binding}"/>  <!-- DataContext é MinhaEntidade -->
```

---

## 🎯 CONCLUSÃO

✅ **Todos os CommandParameter na aplicação estão seguros**  
✅ **Comando problemático corrigido com conversão robusta**  
✅ **Zero vulnerabilidades de tipo detectadas**

### Próximas Ações:
- [ ] Documentar padrões em guidelines de desenvolvimento
- [ ] Criar analyzers customizados para detectar `RelayCommand<T>` com tipos primitivos
- [ ] Adicionar testes unitários para comandos parametrizados

---

**Autor**: GitHub Copilot  
**Revisão**: Manual + Automated Grep Search
