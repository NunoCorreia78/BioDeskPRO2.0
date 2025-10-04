# 🧪 GUIA DE VALIDAÇÃO: Correção de Deformação Iridológica

**Objetivo**: Validar que a correção de inversão de eixo Y funciona corretamente.

---

## ⚡ TESTE RÁPIDO (5 minutos)

### Pré-requisitos
- Aplicação BioDeskPro2 compilada e executando
- Módulo Irisdiagnóstico aberto
- Modo de calibração ativo

### Passos

#### Teste 1: Handler DIREITA (0°)
1. **Localizar**: Handler no lado DIREITO do círculo da íris
2. **Ação**: Arrastar handler para a DIREITA (aumentar raio)
3. **Verificar**: 
   - ✅ Zona DIREITA do mapa estica/expande
   - ✅ Zonas ESQUERDA/TOPO/BAIXO permanecem relativamente inalteradas
   - ❌ (BUG ANTERIOR): Zonas distantes deformavam em vez da zona do handler

#### Teste 2: Handler TOPO (90°)
1. **Localizar**: Handler no TOPO do círculo da íris
2. **Ação**: Arrastar handler para CIMA (aumentar raio)
3. **Verificar**:
   - ✅ Zona TOPO do mapa estica/expande
   - ✅ Zonas DIREITA/ESQUERDA/BAIXO permanecem relativamente inalteradas
   - ❌ (BUG ANTERIOR): Zonas distantes deformavam

#### Teste 3: Handler ESQUERDA (180°)
1. **Localizar**: Handler no lado ESQUERDO do círculo da íris
2. **Ação**: Arrastar handler para a ESQUERDA (aumentar raio)
3. **Verificar**:
   - ✅ Zona ESQUERDA do mapa estica/expande
   - ✅ Outras zonas inalteradas

#### Teste 4: Handler BAIXO (270°)
1. **Localizar**: Handler na parte INFERIOR do círculo da íris
2. **Ação**: Arrastar handler para BAIXO (aumentar raio)
3. **Verificar**:
   - ✅ Zona INFERIOR do mapa estica/expande
   - ✅ Outras zonas inalteradas

---

## 🔬 TESTE DETALHADO (15 minutos)

### Preparação
1. Abrir BioDeskPro2
2. Navegar para aba Irisdiagnóstico
3. Carregar imagem de íris (se disponível)
4. Ativar modo calibração
5. Verificar que 8 handlers aparecem em cada círculo (pupila + íris)

### Teste A: Deformação Localizada (Crítico)

#### A.1: Handler 0° (DIREITA)
- **Posição inicial**: X≈470, Y≈300 (assumindo raio íris=270, centro=300,300)
- **Arrastar para**: X≈520, Y≈300 (+50px para direita)
- **Esperado**:
  - Pontos com ângulo -22.5° a +22.5° esticam ~18% (50/270)
  - Ponto em 0° exato estica totalmente
  - Pontos em 45° e 315° esticam parcialmente (interpolação)
  - Pontos em 90°, 180°, 270° não mudam

#### A.2: Handler 90° (TOPO)
- **Posição inicial**: X≈300, Y≈30
- **Arrastar para**: X≈300, Y≈-20 (+50px para cima, Y negativo OK)
- **Esperado**:
  - Pontos com ângulo 67.5° a 112.5° esticam
  - Pontos em 0°, 180°, 270° não mudam

#### A.3: Handler 180° (ESQUERDA)
- **Posição inicial**: X≈30, Y≈300
- **Arrastar para**: X≈-20, Y≈300
- **Esperado**:
  - Pontos com ângulo 157.5° a 202.5° esticam
  - Pontos em 0°, 90°, 270° não mudam

#### A.4: Handler 270° (BAIXO)
- **Posição inicial**: X≈300, Y≈570
- **Arrastar para**: X≈300, Y≈620
- **Esperado**:
  - Pontos com ângulo 247.5° a 292.5° esticam
  - Pontos em 0°, 90°, 180° não mudam

### Teste B: Interpolação Suave

1. **Arrastar handler 0° (DIREITA)** para raio=400
2. **Observar zonas intermediárias**:
   - Zona em 22.5° (entre 0° e 45°) → deformação moderada
   - Zona em 45° → deformação menor
   - Zona em 67.5° (entre 45° e 90°) → deformação mínima
3. **Verificar**: Transição gradual sem "saltos" visuais

### Teste C: Múltiplos Handlers

1. **Arrastar handler 0°** (DIREITA) para fora (+100px)
2. **Arrastar handler 180°** (ESQUERDA) para dentro (-50px)
3. **Verificar**: 
   - Zona DIREITA estica
   - Zona ESQUERDA encolhe
   - Zonas intermediárias interpolam corretamente

### Teste D: Reset de Calibração

1. **Deformar vários handlers**
2. **Clicar botão "Reset Calibração"**
3. **Verificar**:
   - Handlers voltam para posições circulares perfeitas
   - Mapa volta para círculos concêntricos
   - Sem erros no console

---

## 🐛 DEBUG (SE NECESSÁRIO)

### Ativar Logs de Debug

1. Abrir `IrisdiagnosticoViewModel.cs`
2. Navegar para linha ~1170
3. Descomentar os 4 `Console.WriteLine`:
   ```csharp
   Console.WriteLine($"🔍 Ponto: angulo={angulo * 180 / Math.PI:F1}°, raioOrig={raioOriginal:F1}");
   Console.WriteLine($"📍 Handler anterior: angulo={handlerAnterior.Angulo * 180 / Math.PI:F1}°, fator={fatorAnterior:F3}");
   Console.WriteLine($"📍 Handler posterior: angulo={handlerPosterior.Angulo * 180 / Math.PI:F1}°, fator={fatorPosterior:F3}");
   Console.WriteLine($"📏 t={t:F3}, fatorDeformacao={fatorDeformacao:F3}, raioFinal={raioOriginal * fatorDeformacao:F1}");
   ```
4. Recompilar aplicação
5. Executar e observar console ao arrastar handlers

### Logs Esperados (Exemplo - Handler 0° arrastado)

```
🔍 Ponto: angulo=0.0°, raioOrig=270.0
📍 Handler anterior: angulo=-22.5°, fator=1.185
📍 Handler posterior: angulo=22.5°, fator=1.185
📏 t=0.500, fatorDeformacao=1.185, raioFinal=320.0

🔍 Ponto: angulo=45.0°, raioOrig=270.0
📍 Handler anterior: angulo=22.5°, fator=1.185
📍 Handler posterior: angulo=67.5°, fator=1.000
📏 t=0.500, fatorDeformacao=1.093, raioFinal=295.0

🔍 Ponto: angulo=90.0°, raioOrig=270.0
📍 Handler anterior: angulo=67.5°, fator=1.000
📍 Handler posterior: angulo=112.5°, fator=1.000
📏 t=0.500, fatorDeformacao=1.000, raioFinal=270.0
```

**Análise**:
- ✅ Handler em 0° tem fator=1.185 (raio aumentou de 270 → 320)
- ✅ Ponto em 0° usa esse fator (raioFinal=320)
- ✅ Ponto em 45° interpola (fator=1.093)
- ✅ Ponto em 90° não muda (fator=1.000)

---

## 📊 CHECKLIST DE VALIDAÇÃO

### Funcionalidade Básica
- [ ] Aplicação compila sem erros
- [ ] Modo calibração inicia sem erros
- [ ] 16 handlers aparecem (8 pupila + 8 íris)
- [ ] Handlers são arrastáveis

### Correção de Deformação (CRÍTICO)
- [ ] Arrastar handler DIREITA → zona DIREITA deforma ✅
- [ ] Arrastar handler TOPO → zona TOPO deforma ✅
- [ ] Arrastar handler ESQUERDA → zona ESQUERDA deforma ✅
- [ ] Arrastar handler BAIXO → zona BAIXO deforma ✅

### Interpolação
- [ ] Transição suave entre handlers adjacentes
- [ ] Sem "saltos" ou descontinuidades visuais
- [ ] Zonas distantes dos handlers permanecem estáveis

### Estabilidade
- [ ] Mapa não desaparece durante drag
- [ ] Performance fluida (sem lag)
- [ ] Reset de calibração funciona corretamente
- [ ] Sem erros no console

---

## ✅ CRITÉRIOS DE SUCESSO

### Mínimo Aceitável
- ✅ Deformação na zona CORRETA (não invertida)
- ✅ Aplicação não crasha
- ✅ Interpolação funciona

### Ideal
- ✅ Transição perfeitamente suave
- ✅ Performance 60 FPS
- ✅ Todos os 8 handlers funcionais
- ✅ Reset funciona perfeitamente

---

## 🚨 PROBLEMAS CONHECIDOS (ESPERADOS)

### Limitações Atuais
1. **Apenas 8 handlers**: Controle fino limitado (cada handler controla ~45°)
2. **Interpolação linear**: Pode causar cantos "pontiagudos" em deformações extremas
3. **Sem undo/redo**: Não é possível desfazer deformações

### Problemas Conhecidos NÃO Relacionados à Correção
- Outros bugs do módulo Irisdiagnóstico (fora do escopo)
- Performance em imagens muito grandes (fora do escopo)

---

## 📞 REPORTAR PROBLEMAS

Se a validação FALHAR:

1. **Capturar screenshot** da deformação incorreta
2. **Copiar logs** do console (se debug ativo)
3. **Descrever**:
   - Qual handler foi arrastado
   - Para onde foi arrastado
   - Qual zona deformou (esperado vs real)
4. **Anexar** ao issue no GitHub

---

**Boa validação! 🎉**
