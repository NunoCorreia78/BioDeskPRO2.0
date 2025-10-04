# 🤖 BRIEFING TÉCNICO PARA AGENTE DE CODIFICAÇÃO

## 📋 CONTEXTO DO PROBLEMA

### Sistema: BioDeskPro2 - Módulo de Iridologia
- **Linguagem**: C# WPF (.NET 8)
- **Arquitetura**: MVVM com CommunityToolkit.Mvvm
- **Objetivo**: Calibração interativa de mapa iridológico usando handlers arrastáveis

---

## ✅ O QUE JÁ FUNCIONA

### 1. Mouse Events (100% Funcional)
```csharp
// IrisdiagnosticoUserControl.xaml.cs - Linhas 150-235
private void Handler_MouseDown(object sender, MouseButtonEventArgs e)
private void Handler_MouseMove(object sender, MouseEventArgs e)
private void Handler_MouseUp(object sender, MouseButtonEventArgs e)
```

**Status**: ✅ Handlers capturam eventos, movem-se visualmente, posições X/Y atualizam corretamente

### 2. Estrutura de Dados
```csharp
// IrisdiagnosticoViewModel.cs
public ObservableCollection<CalibrationHandler> HandlersPupila { get; set; }
public ObservableCollection<CalibrationHandler> HandlersIris { get; set; }

public class CalibrationHandler
{
    public double X { get; set; }      // Posição visual no canvas
    public double Y { get; set; }
    public string Tipo { get; set; }   // "Pupila" ou "Íris"
    public double Angulo { get; set; } // Ângulo nominal (0°, 45°, 90°, etc.)
}
```

**Status**: ✅ 8 handlers por círculo (16 total), propriedades bindadas corretamente

### 3. Renderização Base
```csharp
// IrisdiagnosticoViewModel.cs - Linha 992
public void RecalcularPoligonosComDeformacao()
{
    if (ModoCalibracaoAtivo && (HandlersPupila.Count > 0 || HandlersIris.Count > 0))
        RenderizarPoligonosComDeformacao(); // ← Chama interpolação
    else
        RenderizarPoligonos(); // ← Círculos perfeitos
}
```

**Status**: ✅ Mapa renderiza, polígonos aparecem, não desaparecem

---

## ❌ O QUE NÃO FUNCIONA (PROBLEMA CRÍTICO)

### Comportamento Atual (ERRADO)
```
Ação: Arrasto handler à DIREITA (aumentar raio)
Esperado: Zona à DIREITA estica
Real: Zonas à ESQUERDA + CIMA + BAIXO deformam, zona DIREITA fica ESTÁTICA
```

**Sintoma**: **Deformação 100% INVERTIDA** - zonas distantes do handler deformam, zona do handler fica parada

---

## 🔍 CÓDIGO PROBLEMÁTICO

### Arquivo: `IrisdiagnosticoViewModel.cs`
### Método: `InterpolateRadiusFromHandlers()` (Linhas ~1100-1155)

```csharp
private double InterpolateRadiusFromHandlers(
    double angulo,              // Ângulo do ponto a deformar (radianos)
    double raioOriginal,        // Raio do ponto no círculo perfeito
    ObservableCollection<CalibrationHandler> handlers,
    double centroX,             // Centro do círculo (300 ou CentroIrisX)
    double centroY)
{
    // 1. Calcula ângulo de cada handler
    var handlersComAngulo = handlers.Select(h => {
        var dx = h.X + 8 - centroX; // +8 para compensar offset do Ellipse
        var dy = h.Y + 8 - centroY;
        var anguloHandler = Math.Atan2(dy, dx); // ← SUSPEITO #1
        var raioHandler = Math.Sqrt(dx * dx + dy * dy);
        return new { Handler = h, Angulo = anguloHandler, Raio = raioHandler };
    }).OrderBy(h => h.Angulo).ToList();

    // 2. Encontra handlers adjacentes (antes/depois do ângulo)
    var handlerAnterior = handlersComAngulo.LastOrDefault(h => h.Angulo <= angulo) 
                          ?? handlersComAngulo[^1]; // Wrap-around
    var handlerPosterior = handlersComAngulo.FirstOrDefault(h => h.Angulo > angulo) 
                           ?? handlersComAngulo[0];

    // 3. Calcula fatores de deformação
    var raioNominal = GetRaioNominal(handlerAnterior.Handler.Tipo);
    var fatorAnterior = handlerAnterior.Raio / raioNominal;
    var fatorPosterior = handlerPosterior.Raio / raioNominal;

    // 4. Interpolação linear
    var anguloAnterior = handlerAnterior.Angulo;
    var anguloPosterior = handlerPosterior.Angulo;
    
    // Wrap-around 0°/360°
    if (anguloPosterior < anguloAnterior) anguloPosterior += 2 * Math.PI;
    if (angulo < anguloAnterior) angulo += 2 * Math.PI;
    
    var rangeAngulo = anguloPosterior - anguloAnterior;
    var t = rangeAngulo > 0.0001 ? (angulo - anguloAnterior) / rangeAngulo : 0.5;
    t = Math.Clamp(t, 0, 1);

    // 5. Aplica deformação
    var fatorDeformacao = fatorAnterior * (1 - t) + fatorPosterior * t;
    return raioOriginal * fatorDeformacao; // ← RESULTADO INVERTIDO
}
```

---

## 🐛 SUSPEITAS DE ROOT CAUSE

### Hipótese A: Referencial de Ângulos Invertido
- **WPF Canvas**: Origem (0,0) no canto SUPERIOR ESQUERDO
- **Math.Atan2**: Assume origem matemática (0,0) no centro com Y crescendo para CIMA
- **Possível solução**: Inverter Y: `Math.Atan2(-dy, dx)` ou `Math.Atan2(dy, -dx)`

### Hipótese B: Centro Dinâmico Desatualizado
```csharp
// InterpolateZoneWithHandlers() - Linha ~1063
var zonaCentroX = raioMedioZona < 80 ? CentroPupilaX : CentroIrisX;
var zonaCentroY = raioMedioZona < 80 ? CentroPupilaY : CentroIrisY;
```
- **Problema**: `CentroIrisX/Y` pode não estar atualizado no momento da deformação
- **Possível solução**: Recalcular centro baseado na média das posições dos handlers

### Hipótese C: Coordenadas Polares Inconsistentes
```csharp
// Conversão polar → cartesiano no RenderizarPoligonosComDeformacao()
double angulo = coordenada.Angulo * Math.PI / 180.0; // Graus → Radianos
double raioDeformado = InterpolateRadiusFromHandlers(angulo, raioOriginal, ...);
double x = zonaCentroX + raioDeformado * Math.Cos(angulo);
double y = zonaCentroY + raioDeformado * Math.Sin(angulo);
```
- **Problema**: `coordenada.Angulo` vem do JSON (0-360°), mas handlers usam `Atan2` (-π a π)
- **Possível solução**: Normalizar todos os ângulos para mesmo referencial

### Hipótese D: Ordem de Handlers Incorreta
```csharp
// Handler_MouseMove atualiza RaioPupila/RaioIris ANTES de RecalcularPoligonosComDeformacao()
if (handler.Tipo == "Pupila") viewModel.RaioPupila = novoRaio;
else viewModel.RaioIris = novoRaio;
```
- **Problema**: `GetRaioNominal()` retorna o raio ATUALIZADO, não o nominal do círculo perfeito
- **Possível solução**: Guardar raio nominal inicial (100px pupila, 200px íris) separadamente

---

## 🎯 ESPECIFICAÇÃO DO COMPORTAMENTO ESPERADO

### Caso de Teste 1: Handler Direita (0°)
```
Input:
- Handler na posição X=400, Y=300 (centro=300,300 → raio=100px)
- Arrastar para X=450, Y=300 (raio aumenta para 150px)

Esperado:
- Pontos com ângulo entre -22.5° e +22.5° (zona DIREITA) → raio aumenta
- Pontos com ângulo 90° (zona CIMA) → raio inalterado
- Pontos com ângulo 180° (zona ESQUERDA) → raio inalterado
```

### Caso de Teste 2: Handler Cima (90°)
```
Input:
- Handler na posição X=300, Y=200 (centro=300,300 → raio=100px)
- Arrastar para X=300, Y=150 (raio aumenta para 150px)

Esperado:
- Pontos com ângulo entre 67.5° e 112.5° (zona CIMA) → raio aumenta
- Pontos com ângulo 0° (zona DIREITA) → raio inalterado
- Pontos com ângulo 180° (zona ESQUERDA) → raio inalterado
```

---

## 🔧 INFORMAÇÕES AUXILIARES

### Sistema de Coordenadas WPF
```
Canvas 600x600:
(0,0) ────────────────► X
  │
  │    Centro = (300, 300)
  │
  ▼
  Y

Handlers inicializados em círculo perfeito:
- 0°   → X=RaioNominal, Y=0 (relativo ao centro)
- 45°  → X=Raio*cos(45°), Y=Raio*sin(45°)
- 90°  → X=0, Y=RaioNominal
- etc.
```

### Propriedades Relevantes
```csharp
// IrisdiagnosticoViewModel.cs
public double CentroPupilaX { get; set; } = 300.0;
public double CentroPupilaY { get; set; } = 300.0;
public double RaioPupila { get; set; } = 60.0;

public double CentroIrisX { get; set; } = 300.0;
public double CentroIrisY { get; set; } = 300.0;
public double RaioIris { get; set; } = 200.0;
```

### Logs de Debug (Exemplo)
```
🎯 Handler_MouseDown: Capturado handler Íris
🔧 Handler_MouseMove: pos=(350, 280), tipo=Íris
📍 POSITION UPDATE: X=342, Y=272
🧪 Tipo: Íris
🔄 Polígonos recalculados com nova calibração
```

---

## 📝 TAREFAS PARA O AGENTE

### 1. **Diagnosticar Root Cause** (Obrigatório)
- [ ] Adicionar logs de debug com ângulos calculados:
  ```csharp
  Console.WriteLine($"🔍 Ponto: angulo={angulo * 180 / Math.PI:F1}°");
  Console.WriteLine($"📍 Handler anterior: angulo={handlerAnterior.Angulo * 180 / Math.PI:F1}°");
  Console.WriteLine($"📍 Handler posterior: angulo={handlerPosterior.Angulo * 180 / Math.PI:F1}°");
  ```
- [ ] Verificar se ângulos calculados correspondem à posição visual dos handlers
- [ ] Confirmar se centro está correto (imprimir `centroX, centroY` usado)

### 2. **Propor Soluções** (Mínimo 3 alternativas)
- [ ] Solução A: Corrigir referencial de ângulos
- [ ] Solução B: Recalcular centro dinamicamente
- [ ] Solução C: Normalizar sistema de coordenadas polares
- [ ] Solução D: Guardar raio nominal separadamente

### 3. **Implementar Fix** (Após validação)
- [ ] Aplicar correção escolhida
- [ ] Adicionar testes de validação
- [ ] Documentar mudanças no código

---

## 🚨 RESTRIÇÕES IMPORTANTES

1. **NÃO ALTERAR**:
   - `Handler_MouseDown/MouseMove/MouseUp` (funcionam perfeitamente)
   - Estrutura de `CalibrationHandler`
   - Sistema de binding XAML

2. **PRIORIDADE**:
   - Corrigir deformação invertida (P0)
   - Manter performance (P1)
   - Código limpo/documentado (P2)

3. **CRITÉRIOS DE SUCESSO**:
   - Arrastar handler DIREITA → zona DIREITA estica ✅
   - Arrastar handler CIMA → zona CIMA estica ✅
   - Transição suave entre handlers adjacentes ✅
   - Mapa não desaparece durante drag ✅

---

## 📚 REFERÊNCIAS

### Ficheiros Relevantes
```
src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs
    - InterpolateRadiusFromHandlers() (linha ~1100)
    - RenderizarPoligonosComDeformacao() (linha ~1010)
    - RecalcularPoligonosComDeformacao() (linha ~992)

src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs
    - Handler_MouseMove() (linha ~183)
```

### Commit Atual
- **Branch**: `main`
- **Commit**: `2efc6e3`
- **Mensagem**: "WIP: Calibração handlers iridologia - tentativa interpolação deformação local"

---

## ❓ PERGUNTAS PARA O AGENTE

1. Qual das 4 hipóteses (A/B/C/D) é mais provável baseado na análise do código?
2. Existe alguma biblioteca WPF ou helper matemático que possa simplificar os cálculos polares?
3. Seria melhor usar `Transform` do WPF em vez de recalcular todos os pontos?
4. Como garantir que a interpolação é suave mesmo com apenas 8 handlers?

---

**Nota Final**: Este é um problema de geometria/trigonometria em WPF. A lógica de negócio está correta, mas há um bug matemático que inverte o comportamento. Análise meticulosa dos sistemas de coordenadas deve revelar o problema.
