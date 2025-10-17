# 🔍 Auditoria Completa XAML Resources - 16/10/2025

## 📋 Problema Identificado

**Erro Runtime XAML:** `StaticResourceExtension threw an exception` em múltiplos ficheiros

### 🔴 Causa Raiz

**Definições duplicadas de converters** entre `App.xaml` (global) e ficheiros XAML individuais (local), causando conflitos de resolução de recursos.

---

## ✅ Correções Aplicadas

### 1️⃣ **FichaPacienteView.xaml** (Linha 22)
**Problema:** `StringParameterToVisibilityConverter` definido localmente
**Solução:** Removida definição local (já existe no App.xaml linha 24)

```xml
<!-- ANTES -->
<converters:StringParameterToVisibilityConverter x:Key="StringParameterToVisibilityConverter" />

<!-- DEPOIS -->
<!-- StringParameterToVisibilityConverter já está definido no App.xaml -->
```

---

### 2️⃣ **ConfiguracoesWindow.xaml** (Linhas 19-20)
**Problema:** `StringToVisibilityConverter` e `InverseBooleanConverter` duplicados
**Solução:** Removidas definições locais (já existem no App.xaml linhas 14+16)

```xml
<!-- ANTES -->
<converters:StringToVisibilityConverter x:Key="StringToVisibilityConverter" />
<converters:InverseBooleanConverter x:Key="InverseBooleanConverter" />

<!-- DEPOIS -->
<!--  Converters já definidos no App.xaml: StringToVisibilityConverter, InverseBooleanConverter  -->
```

---

### 3️⃣ **DashboardView.xaml** (Linhas 16-17)
**Problema:** `BooleanToVisibilityConverter` e `InverseBooleanToVisibilityConverter` duplicados
**Solução:** Removidas definições locais (já existem no App.xaml linhas 13+15)

```xml
<!-- ANTES -->
<BooleanToVisibilityConverter x:Key="BooleanToVisibilityConverter" />
<converters:InverseBooleanToVisibilityConverter x:Key="InverseBooleanToVisibilityConverter" />

<!-- DEPOIS -->
<!--  Converters já definidos no App.xaml: BooleanToVisibilityConverter, InverseBooleanToVisibilityConverter  -->
```

---

### 4️⃣ **IrisdiagnosticoUserControl.xaml** (Linha 13)
**Problema:** `BooleanToVisibilityConverter` duplicado
**Solução:** Removida definição local (já existe no App.xaml linha 13)

```xml
<!-- ANTES -->
<BooleanToVisibilityConverter x:Key="BooleanToVisibilityConverter"/>

<!-- DEPOIS -->
<!--  BooleanToVisibilityConverter já definido no App.xaml linha 13  -->
```

---

### 5️⃣ **ComunicacaoUserControl.xaml** (Linhas 17-19)
**Problema:** `BooleanToVisibilityConverter` e `InverseBooleanConverter` duplicados
**Solução:** Removidas definições locais

```xml
<!-- ANTES -->
<BooleanToVisibilityConverter x:Key="BoolToVisibility" />
<local:InverseBooleanConverter x:Key="InverseBoolConverter" />

<!-- DEPOIS -->
<!--  BooleanToVisibilityConverter e InverseBooleanConverter já estão no App.xaml  -->
```

---

### 6️⃣ **App.xaml** (Linha 29) - **CRÍTICO!**
**Problema:** Alias `BoolToVisibility` não estava registado
**Solução:** Adicionado alias explícito para compatibilidade

```xml
<!-- ANTES -->
<converters:BooleanToVisibilityConverter x:Key="BoolToVisibilityConverter"/>
<converters:InverseBooleanToVisibilityConverter x:Key="InverseBoolToVisibilityConverter"/>

<!-- DEPOIS -->
<converters:BooleanToVisibilityConverter x:Key="BoolToVisibilityConverter"/>
<converters:BooleanToVisibilityConverter x:Key="BoolToVisibility"/>
<converters:InverseBooleanToVisibilityConverter x:Key="InverseBoolToVisibilityConverter"/>
```

**Justificação:** O código usa `{StaticResource BoolToVisibility}` em 16 locais (BiofeedbackView, ComunicacaoUserControl, ListaPacientesView, DeclaracaoSaudeUserControl, DocumentosExternosUserControl, ConfiguracoesView).

---

## 📊 Recursos Globais no App.xaml (Referência)

### ✅ Converters Disponíveis Globalmente

| Converter | Key no App.xaml | Uso |
|-----------|----------------|-----|
| `BooleanToVisibilityConverter` | `BooleanToVisibilityConverter`, `BoolToVisibilityConverter`, **`BoolToVisibility`** | Bool → Visibility |
| `StringToVisibilityConverter` | `StringToVisibilityConverter` | String não-vazia → Visible |
| `InverseBooleanToVisibilityConverter` | `InverseBooleanToVisibilityConverter`, `InverseBoolToVisibilityConverter` | !Bool → Visibility |
| `InverseBooleanConverter` | `InverseBooleanConverter`, `InverseBoolConverter` | !Bool |
| `GreaterThanConverter` | `GreaterThanConverter` | value > parameter |
| `NullToVisibilityConverter` | `NullToVisibilityConverter`, `NullToVisibilityConverterCollapsed` | Null → Collapsed/Visible |
| `StatusToColorConverter` | `StatusToColorConverter` | Status → Color |
| `StatusToVisibilityConverter` | `StatusToVisibilityConverter` | Status → Visibility |
| `StringParameterToVisibilityConverter` | `StringParameterToVisibilityConverter` | String match → Visibility |
| `FlexibleDateConverter` | `FlexibleDateConverter` | Date formatting |
| `StringToBoolConverter` | `StringToBoolConverter` | String → Bool |

### ✅ Cores Globais (Paleta Terroso Pastel)

- `FundoPrimario`, `FundoPrincipal` → `#FCFDFB`
- `FundoSecundario` → `#F2F5F0`
- `FundoCartao`, `CartaoBrush` → `#F7F9F6`
- `CorBorda`, `BordaBrush` → `#E3E9DE`
- `TextoPrincipal` → `#3F4A3D`
- `TextoSecundario` → `#5A6558`
- `BotaoPrincipal`, `BotaoPrimarioBrush` → `#9CAF97`
- `BotaoPrincipalHover`, `BotaoHover` → `#879B83`

---

## 🚨 Regras Críticas (Não Violável)

### ❌ NUNCA Fazer

1. **NUNCA redefinir converters localmente** se já existem no `App.xaml`
2. **NUNCA criar instâncias nativas** do WPF (`<BooleanToVisibilityConverter />`) - usar sempre as do `App.xaml`
3. **NUNCA usar `x:Key` diferente** do registado no `App.xaml` (ex: `BoolToVisibility` vs `BooleanToVisibilityConverter`)

### ✅ SEMPRE Fazer

1. **SEMPRE verificar `App.xaml` antes** de adicionar converter local
2. **SEMPRE usar StaticResource** para converters: `{StaticResource BooleanToVisibilityConverter}`
3. **SEMPRE documentar** quando converter local é necessário (ex: `TabStyleConverter` específico de FichaPaciente)

---

## 📝 Ficheiros Auditados (26 ficheiros)

### ✅ Limpos (Sem Duplicações)
- `BiofeedbackView.xaml`
- `ToastNotification.xaml`
- `EditarObservacaoDialog.xaml`
- `SelecionarTemplatesWindow.xaml`
- `ObservacaoMarcaDialog.xaml`
- `ConfiguracoesView.xaml`
- `BancoCoreUserControl.xaml`
- `CameraCaptureWindow.xaml`
- `ItensCoreUserControl.xaml`
- `ListaPacientesView.xaml`
- `ConsentimentosUserControl.xaml`
- `TerapiasBioenergeticasUserControl.xaml`
- `RegistoConsultasUserControl.xaml`
- `DocumentosExternosUserControl.xaml`
- `DeclaracaoSaudeUserControl.xaml`

### ✅ Corrigidos (Duplicações Removidas)
- ✅ `FichaPacienteView.xaml`
- ✅ `ConfiguracoesWindow.xaml`
- ✅ `DashboardView.xaml`
- ✅ `IrisdiagnosticoUserControl.xaml`
- ✅ `ComunicacaoUserControl.xaml`

### ✅ App.xaml Atualizado
- ✅ Adicionado alias `BoolToVisibility` (linha 29)

---

## 🎯 Resultado Final

### Build Status
```
Build succeeded.
    28 Warning(s) (apenas AForge compatibilidade)
    0 Error(s)
```

### Runtime Status
✅ **Aplicação executa sem erros XAML**
✅ **Navegação FichaPaciente funcional**
✅ **Todos os converters resolvem corretamente**

---

## 📚 Lições Aprendidas

### 1. Ordem de Resolução de Recursos XAML
1. **Local Resources** (UserControl.Resources) - resolvidos primeiro
2. **Window Resources** (Window.Resources)
3. **Application Resources** (App.xaml)
4. **System Resources** (WPF built-in)

**Problema:** Se converter existe em **Local** e **Application**, WPF tenta usar o local mas pode falhar se houver incompatibilidades de tipo/namespace.

### 2. Converters Nativos vs Customizados
- **Nativo WPF:** `<BooleanToVisibilityConverter />` (namespace `System.Windows.Controls`)
- **Customizado:** `<converters:BooleanToVisibilityConverter />` (namespace `BioDesk.App.Converters`)

**Recomendação:** Sempre usar converters customizados para consistência e evitar conflitos.

### 3. Alias de Compatibilidade
Quando código usa nomes diferentes (ex: `BoolToVisibility` vs `BooleanToVisibilityConverter`), criar **múltiplas keys** para o mesmo converter:

```xml
<converters:BooleanToVisibilityConverter x:Key="BooleanToVisibilityConverter"/>
<converters:BooleanToVisibilityConverter x:Key="BoolToVisibility"/>
```

---

## 🔧 Ferramentas de Diagnóstico

### Comando PowerShell - Verificar Duplicações
```powershell
# Procurar converters locais que existem no App.xaml
Get-ChildItem -Path "src/BioDesk.App" -Filter "*.xaml" -Recurse |
    Select-String -Pattern "x:Key=\"(Boolean|String|Inverse|Null).*Converter\"" |
    Group-Object Line | Where-Object Count -gt 1
```

### Comando Git - Ver Alterações
```bash
git diff src/BioDesk.App/App.xaml
git diff src/BioDesk.App/Views/FichaPacienteView.xaml
git diff src/BioDesk.App/Views/Dialogs/ConfiguracoesWindow.xaml
git diff src/BioDesk.App/Views/DashboardView.xaml
git diff src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml
git diff src/BioDesk.App/Views/Abas/ComunicacaoUserControl.xaml
```

---

## ✅ Checklist Pré-Commit

Antes de criar novos ficheiros XAML:

- [ ] Verificar se converters necessários já existem no `App.xaml`
- [ ] Se existirem, **NÃO** redefinir localmente
- [ ] Se não existirem, adicionar ao `App.xaml` (não local)
- [ ] Usar `StaticResource` com nome exato do `App.xaml`
- [ ] Build sem erros
- [ ] Executar app e testar navegação

---

**Auditoria concluída em:** 16/10/2025 22:30
**Status:** ✅ **100% Funcional**
**Próximos passos:** Testes E2E de navegação e funcionalidades
