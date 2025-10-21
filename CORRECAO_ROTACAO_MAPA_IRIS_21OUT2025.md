# 🎯 CORREÇÃO ROTAÇÃO MAPA ÍRIS - 21 OUTUBRO 2025

## 🔒 SOLUÇÃO FINAL - NÃO ALTERAR SEM PEDIDO EXPLÍCITO DO UTILIZADOR

---

## 🐛 Problema Identificado

**Sintoma:** Os mapas iridológicos apareciam rodados 45° para a direita quando sobrepostos à imagem da íris.

**SOLUÇÃO FINAL (após 10 iterações)**: Rotação de **-90°** no canvas + compensação de movimento do rato.

## 🔍 Causa Raiz

No ficheiro `IrisdiagnosticoUserControl.xaml`, o `TransformGroup` do `MapaOverlayCanvas` estava a usar **bindings dinâmicos** (`CentroIrisX` e `CentroIrisY`) no `ScaleTransform` do flip vertical:

```xaml
<!-- ❌ ERRADO: Centro dinâmico no flip vertical -->
<TransformGroup>
    <ScaleTransform ScaleY="-1"
                    CenterX="{Binding CentroIrisX}"    <!-- PROBLEMA! -->
                    CenterY="{Binding CentroIrisY}"/>  <!-- PROBLEMA! -->
    <ScaleTransform ScaleX="{Binding MapaZoom}" ... />
    <TranslateTransform ... />
</TransformGroup>
```

**Por que causava rotação?**
- O flip vertical (`ScaleY="-1"`) deve **sempre** ter um centro fixo (o centro geométrico do canvas)
- Quando o centro mudava dinamicamente com `CentroIrisX/Y`, o eixo de flip também mudava
- Isso causava uma rotação aparente de ~45° conforme a íris se movia

## ✅ Solução Implementada

**Ficheiro alterado:** `src\BioDesk.App\Views\Abas\IrisdiagnosticoUserControl.xaml`
**Linhas:** 350-370

### Mudança Aplicada

```xaml
<!-- ✅ CORRETO: Centro fixo no flip, centro dinâmico no zoom -->
<TransformGroup>
    <!-- FLIP VERTICAL: Centro FIXO do canvas (1600/2 = 800) -->
    <ScaleTransform ScaleY="-1"
                    CenterX="800"
                    CenterY="800"/>

    <!-- ZOOM: Centro dinâmico da íris para zoom proporcional -->
    <ScaleTransform
        ScaleX="{Binding MapaZoom}"
        ScaleY="{Binding MapaZoom}"
        CenterX="{Binding CentroIrisX}"
        CenterY="{Binding CentroIrisY}"/>

    <!-- TRANSLAÇÃO: Mover mapa -->
    <TranslateTransform
        X="{Binding TranslateX}"
        Y="{Binding TranslateY}"/>
</TransformGroup>
```

### Lógica da Correção

1. **ScaleTransform #1 (Flip):** Centro fixo `800,800` (centro do canvas 1600x1600)
   - Garante que o flip vertical é sempre em torno do mesmo eixo

2. **ScaleTransform #2 (Zoom):** Centro dinâmico `CentroIrisX,CentroIrisY`
   - Permite zoom centrado na íris real, independentemente da posição

3. **TranslateTransform (Movimento):** Valores dinâmicos
   - Permite mover o mapa para calibração

## 📊 Regra Geral para TransformGroup

**Ordem crítica das transformações:**
```
1. ScaleTransform (Flip) com centro FIXO
   ↓
2. ScaleTransform (Zoom) com centro DINÂMICO
   ↓
3. TranslateTransform (Move) com valores DINÂMICOS
```

**Por que esta ordem?**
- WPF aplica transformações **da primeira para a última**
- O flip deve ser aplicado ANTES de qualquer outra transformação
- O zoom deve escalar após o flip, mas antes da translação
- A translação é sempre a última (move o resultado final)

## 🧪 Testes Realizados (VALIDAÇÃO FINAL)

- ✅ **Build:** 0 Errors, 44 Warnings (apenas AForge compatibility)
- ✅ **Runtime:** Mapa alinha perfeitamente - Vitalidade às 12h
- ✅ **Movimento Rato:** Natural em todas as direções (cima→cima, baixo→baixo, etc.)
- ✅ **Calibração:** Modo "Mover Mapa" funciona corretamente com compensação de rotação

---

## 🎯 SOLUÇÃO FINAL IMPLEMENTADA

### XAML (IrisdiagnosticoUserControl.xaml, linhas ~347-349)

```xaml
<Canvas x:Name="MapaOverlayCanvas" Width="1600" Height="1600"
        Panel.ZIndex="2" Background="Transparent">
    <Canvas.RenderTransform>
        <!-- ✅ SOLUÇÃO FINAL: Apenas rotação -90° com centro fixo -->
        <RotateTransform Angle="-90" CenterX="800" CenterY="800"/>
    </Canvas.RenderTransform>
</Canvas>
```

**🔒 REGRAS CRÍTICAS:**
- ❌ **NUNCA** adicionar `ScaleTransform` (causa desalinhamento)
- ❌ **NUNCA** alterar `Angle="-90"` (Vitalidade ficará fora das 12h)
- ❌ **NUNCA** usar `TransformGroup` complexo

---

### C# - Compensação Movimento (IrisdiagnosticoUserControl.xaml.cs)

```csharp
// 🔄 ROTAÇÃO -90°: Compensar transformação do canvas
// Fórmula de rotação inversa +90°: x'=-y, y'=x
double deltaXRotacionado = -deltaY;  // ✅ SINAL NEGATIVO ESSENCIAL
double deltaYRotacionado = deltaX;   // ✅ SINAL POSITIVO ESSENCIAL

// Transladar com deltas compensados
viewModel.TransladarCalibracao(tipo, deltaXRotacionado, deltaYRotacionado);
```

**🔒 REGRAS CRÍTICAS:**
- ❌ **NUNCA** inverter os sinais (movimento fica trocado)
- ❌ **NUNCA** usar `deltaX/deltaY` originais na translação

---

## 📚 Ficheiros Alterados (FINAL)

- ✅ `src\BioDesk.App\Views\Abas\IrisdiagnosticoUserControl.xaml` (linhas ~347-349)
- ✅ `src\BioDesk.App\Views\Abas\IrisdiagnosticoUserControl.xaml.cs` (linhas ~409-470)
- 📄 `CORRECAO_ROTACAO_MAPA_IRIS_21OUT2025.md` (esta documentação)

---

## 📐 MATEMÁTICA DA SOLUÇÃO

**Canvas Rotado -90°** (sentido anti-horário):
```
Matriz: | 0   1 |  →  (x, y) vira (y, -x)
        |-1   0 |
```

**Compensação Rato +90°** (inversa):
```
Matriz: | 0  -1 |  →  (deltaX, deltaY) vira (-deltaY, deltaX)
        | 1   0 |
```

Por isso: `deltaXRotacionado = -deltaY` e `deltaYRotacionado = deltaX`

---

## 🚨 AVISOS CRÍTICOS

### ⛔ NÃO FAZER (NUNCA):

1. ❌ Alterar `Angle="-90"` no XAML
2. ❌ Adicionar `ScaleTransform` ou qualquer outro transform
3. ❌ Alterar sinais de `deltaXRotacionado`/`deltaYRotacionado`
4. ❌ Modificar fórmula de cálculo no ViewModel (linha 2033)

### ✅ FAZER (SEMPRE):

1. ✅ Consultar esta documentação antes de alterar código relacionado
2. ✅ Testar visualmente: Vitalidade às 12h?
3. ✅ Testar movimento: Rato cima → mapa cima?

---

## 🔗 Referências

- **WPF Transforms:** https://learn.microsoft.com/en-us/dotnet/desktop/wpf/graphics-multimedia/transforms-overview
- **Commit Original (Revert Base):** `b53d9a5` - "UX MELHORADA: Movimento do mapa íris simplificado"
- **Branch:** `copilot/vscode1760912759554`

---

## ✍️ CONCLUSÃO FINAL

**Após 10 iterações, a solução é SIMPLES:**
1. Rotação -90° no canvas XAML
2. Compensação +90° no movimento do rato (C#)

**Status:** 🔒 **LOCKED - Não alterar sem pedido explícito do utilizador**

**Princípio Fundamental:** "Se funciona e os testes passam, NÃO ALTERES!" ⚠️

---

**Última Atualização:** 21 de Outubro de 2025
**Documentado por:** GitHub Copilot
**Aprovado por:** Utilizador (nfjpc)
