# 🔴 DIAGNÓSTICO: Botão Mapa Iridológico

**Data**: 04 de Outubro de 2025  
**Status**: ✅ **CORRIGIDO** (aguarda teste em runtime)

---

## 🐛 PROBLEMA REPORTADO

**Sintoma**: "O Botão mapa iridológico não faz nada."

---

## 🔍 INVESTIGAÇÃO

### 1. Verificação do Binding (XAML)
✅ **OK** - Binding está correto:
```xaml
<!-- IrisdiagnosticoUserControl.xaml linha 433-434 -->
<ToggleButton Content="🗺️ Mapa Iridológico"
              IsChecked="{Binding MostrarMapaIridologico}"
              Command="{Binding AlternarMapaIridologicoCommand}"/>
```

### 2. Verificação do ViewModel
✅ **OK** - Comando existe e está implementado:
```csharp
// IrisdiagnosticoViewModel.cs linha 706
[RelayCommand]
private async Task AlternarMapaIridologicoAsync()
{
    MostrarMapaIridologico = !MostrarMapaIridologico;
    _logger.LogInformation("🗺️ Mapa iridológico: {Estado}", MostrarMapaIridologico ? "VISÍVEL" : "OCULTO");

    if (MostrarMapaIridologico && IrisImagemSelecionada != null)
    {
        await CarregarMapaIridologicoAsync();
    }
}
```

### 3. Verificação do Serviço
✅ **OK** - `IIridologyService` está registado no DI:
```csharp
// App.xaml.cs linha 259
services.AddSingleton<IIridologyService, IridologyService>();
```

### 4. ❌ PROBLEMA ENCONTRADO: Caminho JSON Errado

**Código Original** (IridologyService.cs linha 27-33):
```csharp
_caminhoJsonBase = Path.Combine(
    AppDomain.CurrentDomain.BaseDirectory,
    "..", "..", "..", "..", ".."  // ← 5 níveis acima!
);
```

**Problema**:
- `AppDomain.CurrentDomain.BaseDirectory` = `bin/Debug/net8.0-windows/`
- 5 níveis acima = muito longe!
- Ficheiros JSON estão em: `src/BioDesk.App/Resources/IridologyMaps/`

**Resultado**:
- `CarregarMapaAsync()` retorna `null`
- Log mostraria: "❌ Arquivo JSON não encontrado"
- Polígonos nunca são renderizados

---

## ✅ CORREÇÃO APLICADA

**Novo Código** (IridologyService.cs):
```csharp
// Caminho correto: BioDesk.App/Resources/IridologyMaps/
// AppDomain.CurrentDomain.BaseDirectory = bin/Debug/net8.0-windows/
// Subir 3 níveis até src/BioDesk.App/
_caminhoJsonBase = Path.Combine(
    AppDomain.CurrentDomain.BaseDirectory,
    "..", "..", "..", // bin/Debug/net8.0-windows → src/BioDesk.App
    "Resources",
    "IridologyMaps"
);

var caminhoResolvido = Path.GetFullPath(_caminhoJsonBase);
_logger.LogInformation("📂 IridologyService inicializado. Caminho JSON: {Caminho}", caminhoResolvido);

// Verificar se pasta existe
if (!Directory.Exists(caminhoResolvido))
{
    _logger.LogError("❌ PASTA NÃO EXISTE: {Caminho}", caminhoResolvido);
}
```

**Melhorias**:
1. ✅ Caminho correto: `bin/Debug/net8.0-windows → src/BioDesk.App/Resources/IridologyMaps/`
2. ✅ Log mostra caminho resolvido completo
3. ✅ Validação de existência da pasta
4. ✅ Mensagem de erro clara se pasta não existir

---

## 📋 BUILD STATUS

```
Build succeeded.
    32 Warning(s) ← AForge + CA1063 (Dispose pattern)
    0 Error(s)   ← ✅ CÓDIGO COMPILANDO
```

**Warnings Importantes**:
- CA1063: `RealCameraService.Dispose()` não segue padrão correto
- CS0618: QuestPDF Image method obsoleto (não crítico)

---

## 🧪 TESTES NECESSÁRIOS (RUNTIME)

### Teste 1: Verificar Caminho JSON
**Como testar**:
1. Executar aplicação: `dotnet run --project src/BioDesk.App`
2. Ir para aba **Irisdiagnóstico**
3. Verificar logs no arranque:
   - Deve aparecer: `"📂 IridologyService inicializado. Caminho JSON: C:\...\src\BioDesk.App\Resources\IridologyMaps"`
   - **NÃO** deve aparecer: `"❌ PASTA NÃO EXISTE"`

### Teste 2: Botão Mapa Iridológico
**Pré-requisitos**:
- Paciente com fotos de íris (Esquerdo e/ou Direito)

**Passos**:
1. Selecionar paciente na lista
2. Ir para aba **Irisdiagnóstico**
3. Selecionar foto de íris (Esquerdo ou Direito)
4. Clicar no botão **"🗺️ Mapa Iridológico"**

**Resultado Esperado**:
- ✅ Botão fica "pressionado" (IsChecked=True)
- ✅ Log mostra: `"🗺️ Mapa iridológico: VISÍVEL"`
- ✅ Log mostra: `"✅ Mapa iridológico carregado: 72 zonas, Tipo: esq"` (ou "drt")
- ✅ Polígonos coloridos aparecem sobrepostos na imagem da íris
- ✅ Canvas `ZonasOverlayCanvas` fica visível

**Resultado se Ainda Falhar**:
- ❌ Botão muda estado mas nada aparece
- ❌ Log mostra: `"❌ Arquivo JSON não encontrado"`
- ❌ Canvas permanece vazio

### Teste 3: Hit-Testing de Zonas
**Pré-requisito**: Mapa iridológico visível

**Passos**:
1. Clicar numa das zonas coloridas sobre a íris

**Resultado Esperado**:
- ✅ Propriedade `ZonaDetectada` atualiza com nome da zona
- ✅ Painel de info mostra: "Zona: [Nome da Zona]"

---

## 🎯 PRÓXIMOS PASSOS

### Imediato (HOJE)
1. ✅ **Executar aplicação**
2. ✅ **Verificar logs do IridologyService** (caminho JSON)
3. ✅ **Testar botão Mapa Iridológico** com paciente real

### Se Falhar Novamente
**Possíveis Causas**:
1. ❌ Ficheiros JSON não existem em `src/BioDesk.App/Resources/IridologyMaps/`
2. ❌ IrisImagemSelecionada é null (nenhuma imagem selecionada)
3. ❌ Caminho ainda errado (verificar output do log)
4. ❌ JSON malformado (erro de deserialização)

**Debug**:
```bash
# Verificar se ficheiros existem
ls "src/BioDesk.App/Resources/IridologyMaps/"
# Deve mostrar: iris_esq.json, iris_drt.json

# Verificar tamanho (devem ser ~750KB cada)
ls -lh "src/BioDesk.App/Resources/IridologyMaps/"
```

### Depois de Confirmar Funcionamento
4. ✅ Marcar TODO #6 como **tested**
5. ✅ Atualizar documentação

---

## 📊 RESUMO DE CORREÇÕES

| Item | Antes | Depois | Status |
|------|-------|--------|--------|
| **Caminho JSON** | `../.../..` (5×) | `../../Resources/IridologyMaps` | ✅ Corrigido |
| **Validação Pasta** | ❌ Não tinha | ✅ Verifica se existe | ✅ Adicionado |
| **Log Detalhado** | ⚠️ Caminho relativo | ✅ Caminho absoluto | ✅ Melhorado |
| **Build** | ✅ OK | ✅ OK | ✅ Sem regressão |

---

## 🔗 FICHEIROS ALTERADOS

1. ✅ `src/BioDesk.Services/IridologyService.cs` (linhas 27-42)
   - Caminho JSON corrigido
   - Validação de pasta adicionada
   - Logging melhorado

2. ✅ TODO list atualizada (#6 completed, #10 added)

---

**FIM DO DIAGNÓSTICO**

**Status Final**: ✅ **CORREÇÃO APLICADA - AGUARDA TESTE EM RUNTIME**
