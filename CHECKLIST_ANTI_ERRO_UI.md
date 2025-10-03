# ⚠️ CHECKLIST ANTI-ERRO UI/BINDING - OBRIGATÓRIO

## 🚨 REGRAS CRÍTICAS - NUNCA IGNORAR

### 1. **SOBREPOSIÇÃO DE USERCONTROLS**

❌ **NUNCA** colocar UserControls no mesmo Grid sem Z-Index
✅ **SEMPRE** usar `Panel.ZIndex` quando UserControls partilham espaço
✅ **SEMPRE** usar bordas coloridas DEBUG durante desenvolvimento

```xaml
<!-- CORRETO -->
<Grid>
    <UserControl1 Panel.ZIndex="100" BorderBrush="Red" BorderThickness="2"/>
    <UserControl2 Panel.ZIndex="50" BorderBrush="Blue" BorderThickness="2"/>
</Grid>
```

### 2. **VISIBILITY BINDING**

❌ **NUNCA** confiar apenas em `Visibility=Collapsed`
✅ **SEMPRE** verificar com bordas DEBUG se está realmente oculto
✅ **SEMPRE** testar cada estado de navegação

### 3. **BACKGROUND TRANSPARENTE**

❌ **NUNCA** deixar UserControls com Background sólido por defeito
✅ **SEMPRE** usar `Background="Transparent"` em UserControls sobrepostos

### 4. **ORDEM DE RENDERIZAÇÃO**

❌ **NUNCA** assumir que ordem no XAML = ordem visual
✅ **SEMPRE** definir explicitamente com Panel.ZIndex
✅ **SEMPRE** comentar a intenção da ordem

### 5. **TESTE VISUAL OBRIGATÓRIO**

✅ **SEMPRE** testar navegação entre TODAS as abas
✅ **SEMPRE** verificar se conteúdo corresponde ao tab ativo
✅ **SEMPRE** usar bordas DEBUG até confirmar funcionamento

## 🔍 PROCEDIMENTO DEBUG

### 1. **Identificar Sobreposição**

```xaml
<!-- Adicionar temporariamente -->
BorderBrush="Red" BorderThickness="3"    <!-- UserControl 1 -->
BorderBrush="Blue" BorderThickness="3"   <!-- UserControl 2 -->
```

### 2. **Verificar Z-Index**

```xaml
Panel.ZIndex="100"  <!-- Deve ficar por cima -->
Panel.ZIndex="50"   <!-- Deve ficar por baixo -->
```

### 3. **Confirmar Visibility**

- Clicar em cada tab
- Verificar se aparece apenas a borda correta
- Confirmar que conteúdo corresponde ao tab

### 4. **Remover DEBUG**

- Só remover bordas depois de 100% confirmado
- Manter comentários explicativos

## 📋 CHECKLIST PRÉ-COMMIT

□ Todos os UserControls têm Panel.ZIndex definido
□ Background="Transparent" em UserControls sobrepostos
□ Testei navegação entre TODAS as abas
□ Conteúdo corresponde ao tab ativo em todos os casos
□ Removido borders DEBUG após confirmação
□ Comentários explicam ordem/prioridade dos controles

## 🚫 ANTI-PATTERNS PROIBIDOS

```xaml
<!-- ERRADO - Vai causar sobreposição -->
<Grid>
    <UserControl1/>
    <UserControl2/>  <!-- Fica por cima sempre -->
</Grid>

<!-- ERRADO - Background sólido interfere -->
<UserControl Background="White">

<!-- ERRADO - Sem Z-Index definido -->
<UserControl Visibility="{Binding ...}"/>
```

## ✅ PATTERNS OBRIGATÓRIOS

```xaml
<!-- CORRETO - Z-Index explícito + Background transparente -->
<Grid>
    <UserControl1
        Panel.ZIndex="100"
        Background="Transparent"
        BorderBrush="Red" BorderThickness="2"
        Visibility="{Binding ...}"/>
    <UserControl2
        Panel.ZIndex="50"
        Background="Transparent"
        BorderBrush="Blue" BorderThickness="2"
        Visibility="{Binding ...}"/>
</Grid>
```

---

**LEMBRETE**: Este documento foi criado após o bug de sobreposição UserControls.
**NUNCA MAIS** deplorar sem seguir este checklist!
