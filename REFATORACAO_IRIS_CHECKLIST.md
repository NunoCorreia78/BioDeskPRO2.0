# ✅ Refatoração Íris - Checklist de Progresso

## 📊 Visão Geral
- **Objetivo**: Simplificar calibração de 12 → 8 handlers, reduzir ~490 linhas
- **Status Geral**: 🟢 Fase 1 Completa | 🔴 Fases 2-5 Pendentes
- **Tempo Gasto**: ~2 horas (Fase 1)
- **Tempo Restante**: ~6-8 horas (Fases 2-5)

---

## ✅ FASE 1: Preparação e Fundação (COMPLETA)

### Código
- [x] Adicionar método `FromHandlers()` em `IridologyTransform.cs` (+70 linhas)
- [x] Atualizar `QuantidadeHandlersIris`: 12 → 8
- [x] Atualizar `QuantidadeHandlersPupila`: 12 → 8
- [x] Atualizar validação mínima: Math.Max(6) → Math.Max(8) (3 métodos)
- [x] Atualizar tooltips XAML: "5 handlers" → "8 handlers" (2 lugares)
- [x] Atualizar textos ajuda XAML: "5 handlers" → "8 handlers" (2 linhas)

### Documentação
- [x] Criar `REFATORACAO_IRIS_GUIA_COMPLETO.md` (11.5 KB)
- [x] Criar `REFATORACAO_IRIS_QUICKREF.md` (4.5 KB)
- [x] Criar `REFATORACAO_IRIS_RESUMO_FASE1.md` (10 KB)
- [x] Criar este checklist

### Commits
- [x] Commit 1: `5d9d881` - FromHandlers + Handlers 8x
- [x] Commit 2: `c725eb3` - Documentação completa
- [x] Commit 3: `78041ab` - Resumo Fase 1

**Status Fase 1**: ✅ COMPLETA

---

## 🔴 FASE 2: Integração Sistema Simplificado (CRÍTICA)

### Passo 1: Handler_MouseMove ⚠️ OBRIGATÓRIO
**Ficheiro**: `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs`

- [ ] Localizar método `Handler_MouseMove()`
- [ ] Adicionar after position update:
  ```csharp
  var pontosPupila = viewModel.HandlersPupila.Select(h => new Point(h.X + 8, h.Y + 8));
  var pontosIris = viewModel.HandlersIris.Select(h => new Point(h.X + 8, h.Y + 8));
  var elipsePupila = IridologyTransform.FromHandlers(pontosPupila);
  var elipseIris = IridologyTransform.FromHandlers(pontosIris);
  viewModel.AtualizarCalibracao(elipsePupila, elipseIris);
  ```
- [ ] Adicionar `using BioDesk.Services;` no topo
- [ ] Testar compilação

### Passo 2: Método AtualizarCalibracao ⚠️ OBRIGATÓRIO
**Ficheiro**: `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs`

- [ ] Adicionar método público:
  ```csharp
  public void AtualizarCalibracao(CalibrationEllipse pupila, CalibrationEllipse iris)
  {
      CentroPupilaX = pupila.Center.X;
      CentroPupilaY = pupila.Center.Y;
      CentroIrisX = iris.Center.X;
      CentroIrisY = iris.Center.Y;
      
      RaioPupilaHorizontal = pupila.RadiusX;
      RaioPupilaVertical = pupila.RadiusY;
      RaioIrisHorizontal = iris.RadiusX;
      RaioIrisVertical = iris.RadiusY;
      
      AtualizarTransformacoesGlobais();
  }
  ```
- [ ] Testar compilação

### Passo 3: Testes Básicos
- [ ] Build: `dotnet clean && dotnet build` → 0 erros
- [ ] Run: `dotnet run --project src/BioDesk.App`
- [ ] Abrir aba Íris
- [ ] Verificar 16 handlers aparecem (8 azuis + 8 verdes)
- [ ] Arrastar handler → mapa atualiza?

**Status Fase 2**: 🔴 PENDENTE (Tempo: ~1-2h)

---

## 🟡 FASE 3: Limpeza de Código Obsoleto (OPCIONAL)

### A. Remover Métodos Complexos (~400 linhas)
**Ficheiro**: `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs`

- [ ] Remover `InterpolateZoneWithHandlers()` (linha ~2270-2349, ~80 linhas)
- [ ] Remover `RecalcularPoligonosComDeformacao()` (linha ~2192-2235, ~43 linhas)
- [ ] Remover `RenderizarPoligonosComDeformacao()` (linha ~2236-2269, ~33 linhas)
- [ ] Remover `InterpolateRadiusFromHandlers()` (linha ~2398-2474, ~76 linhas)
- [ ] Remover `CalcularPesosRadiais()` (linha ~2358-2381, ~23 linhas)
- [ ] Remover `ConverterRaioParaPupila()` (linha ~2383-2391, ~8 linhas)
- [ ] Remover `GetRaioNominal()` (linha ~2479-2482, ~3 linhas)
- [ ] Remover `NormalizarAngulo()` se não usado
- [ ] Testar build após cada remoção

### B. Remover Propriedades Obsoletas
**Ficheiro**: `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs`

- [ ] Remover `_modoMoverMapa` (linha ~225)
- [ ] Remover `_modoCalibracaoAtivo` (linha ~200)
- [ ] Remover `_opacidadeMapa` (linha ~194)
- [ ] Remover `_tipoCalibracaoPupila` (linha ~206)
- [ ] Remover `_tipoCalibracaoIris` (linha ~212)
- [ ] Remover `_tipoCalibracaoAmbos` (linha ~218)
- [ ] Remover partial methods associados: `OnModoMoverMapaChanged()`, etc
- [ ] Testar build

### C. Remover Botões XAML (~200 linhas)
**Ficheiro**: `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml`

- [ ] Remover botão "🔍 Mostrar Mapa" (linha ~1091-1139)
- [ ] Remover botão "🖐️ Mover Mapa" (linha ~1141-1214)
- [ ] Remover checkbox "🎯 Ajuste Fino" (linha ~1442-1463)
- [ ] Remover StackPanel RadioButtons legacy (linha ~1466-1487)
- [ ] Remover botão "🔄 Reset Calibração" (linha ~1495-1528)
- [ ] Verificar XML válido: `tail -20 IrisdiagnosticoUserControl.xaml`
- [ ] Testar build

### D. Remover Constantes Obsoletas
**Ficheiro**: `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs`

- [ ] Verificar se ainda usadas: `RAIO_NOMINAL_PUPILA`, `RAIO_NOMINAL_IRIS`
- [ ] Verificar se ainda usadas: `PUPILA_NORMALIZED_THRESHOLD`, `PUPILA_TRANSITION_WIDTH`
- [ ] Remover se não referenciadas em outros lugares
- [ ] Testar build

### E. Remover Flags de Controle
**Ficheiro**: `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs`

- [ ] Verificar se usados: `_isDragging`, `_lastRenderTime`, `RenderThrottleMs`
- [ ] Remover se não necessários no novo sistema
- [ ] Testar build

**Status Fase 3**: 🟡 OPCIONAL (Tempo: ~3-4h, não bloqueia funcionalidade)

---

## 🟢 FASE 4: Validação Completa

### Build e Compilação
- [ ] `dotnet clean`
- [ ] `dotnet restore`
- [ ] `dotnet build` → Verificar 0 erros
- [ ] Warnings esperados: apenas AForge (câmera)

### Testes UI
- [ ] `dotnet run --project src/BioDesk.App`
- [ ] Dashboard → Abrir paciente qualquer
- [ ] Navegar para aba "Irisdiagnóstico"
- [ ] Botão "📷 Adicionar Imagem" → Selecionar imagem íris

### Validar Handlers
- [ ] **Quantidade**: 16 handlers visíveis total
- [ ] **Cores**: 8 azuis (pupila) + 8 verdes (íris)
- [ ] **Posições**: 0°, 45°, 90°, 135°, 180°, 225°, 270°, 315°
- [ ] **Tamanho**: 24x24 px (verificar visualmente)
- [ ] **Cursor**: Muda para "Hand" ao hover

### Validar Drag & Drop
- [ ] Arrastar handler azul → pupila move
- [ ] Arrastar handler azul → íris não move
- [ ] Arrastar handler verde → íris move
- [ ] Arrastar handler verde → pupila não move
- [ ] **Tempo real**: Mapa atualiza durante drag (não só ao soltar)
- [ ] **Latência**: < 50ms (visual smooth)
- [ ] **Performance**: > 30 FPS durante drag

### Validar Elipses
- [ ] **Círculo**: Arrastar handlers equidistantes → mapa circular
- [ ] **Elipse horizontal**: Arrastar 2 handlers horizontais mais longe
- [ ] **Elipse vertical**: Arrastar 2 handlers verticais mais longe
- [ ] **Elipse inclinada**: Arrastar handlers assimetricamente
- [ ] **Rotação**: Verificar que mapa roda com elipse

### Validar Funcionalidades Existentes
- [ ] Zoom mapa: Botões +/- funcionam
- [ ] Hover zonas: Tooltip aparece ao passar mouse
- [ ] Click zonas: Informação detalhada aparece
- [ ] Adicionar marcas: Click + observações funciona
- [ ] Menu contextual marcas: Editar/mudar cor/remover funciona
- [ ] Salvar imagem: Imagem persiste na base de dados

**Status Fase 4**: 🟢 PENDENTE (Tempo: ~1-2h)

---

## 📸 FASE 5: Screenshots e Finalização

### Screenshots a Tirar
- [ ] **Screenshot 1**: Vista geral - 16 handlers visíveis
- [ ] **Screenshot 2**: Drag em ação - cursor segurando handler
- [ ] **Screenshot 3**: Elipse circular - handlers equidistantes
- [ ] **Screenshot 4**: Elipse deformada - distâncias variadas
- [ ] **Screenshot 5**: Mapa renderizado - sobreposição na imagem
- [ ] Salvar screenshots em `/docs/refatoracao_iris/`

### Documentação Final
- [ ] Atualizar `README.md` se necessário
- [ ] Adicionar nota em `CHANGELOG.md` (se existir)
- [ ] Marcar issue como "Resolved" (se existir issue #)

### Code Review Final
- [ ] Self-review: ler diff completo da PR
- [ ] Verificar todos commits têm mensagens claras
- [ ] Verificar sem ficheiros temporários commitados
- [ ] Verificar sem hardcoded paths ou valores
- [ ] Verificar sem console.logs ou debugs esquecidos

**Status Fase 5**: 📸 PENDENTE (Tempo: ~30min)

---

## 📊 Métricas Finais (Para Preencher)

### Código
- Linhas adicionadas: **+70** (Fase 1) + **???** (Fases 2-5)
- Linhas removidas: **0** (Fase 1) + **???** (Fases 2-5)
- Métodos removidos: **0** (Fase 1) + **???** (Fase 3)
- Handlers por elipse: **12 → 8** ✅

### Performance (Medir após Fase 4)
- Latência drag: **??? ms** (meta: < 50ms)
- FPS durante drag: **??? FPS** (meta: > 30 FPS)
- Tempo inicialização handlers: **??? ms**

### Qualidade
- Erros build: **0** (meta) | Atual: **???**
- Warnings build: **??? AForge** (esperado)
- Cobertura testes: **N/A** (sem testes unitários)

---

## 🚨 Troubleshooting

### Problema: Build falha após Fase 2
**Sintoma**: Erro "CalibrationEllipse não encontrado"
**Solução**: 
- [ ] Adicionar `using BioDesk.Services;` em `IrisdiagnosticoUserControl.xaml.cs`
- [ ] Verificar namespace correto de `CalibrationEllipse`

### Problema: Mapa não atualiza ao arrastar
**Sintoma**: Handler move mas mapa fica estático
**Solução**:
- [ ] Verificar se `AtualizarCalibracao()` é chamado em `Handler_MouseMove`
- [ ] Adicionar log: `_logger.LogDebug("Elipse pupila: {C}", elipsePupila.Center);`
- [ ] Verificar se `AtualizarTransformacoesGlobais()` dispara rendering

### Problema: Handlers não aparecem
**Sintoma**: Imagem carregada mas sem handlers
**Solução**:
- [ ] Verificar log: `HandlersPupila.Count` e `HandlersIris.Count`
- [ ] Verificar binding XAML: `ItemsSource="{Binding HandlersPupila}"`
- [ ] Verificar Z-Index do Canvas (deve estar acima da imagem)

### Problema: Performance lenta (< 30 FPS)
**Sintoma**: Drag com lag visível
**Solução**:
- [ ] Adicionar throttling: max 30 FPS (33ms entre updates)
- [ ] Verificar se `FromHandlers()` está otimizado (deveria ser O(n))
- [ ] Considerar rendering assíncrono: `Dispatcher.InvokeAsync()`

---

## 📚 Recursos

### Documentação
- 📖 **Guia Completo**: `REFATORACAO_IRIS_GUIA_COMPLETO.md` (LER PRIMEIRO!)
- ⚡ **Quick Ref**: `REFATORACAO_IRIS_QUICKREF.md` (Resumo 1 página)
- 📊 **Resumo Fase 1**: `REFATORACAO_IRIS_RESUMO_FASE1.md` (O que foi feito)
- ✅ **Este Checklist**: `REFATORACAO_IRIS_CHECKLIST.md` (Você está aqui)

### Commits
- `5d9d881` - Fase 1: FromHandlers + Handlers 8x
- `c725eb3` - Documentação completa
- `78041ab` - Resumo Fase 1

### Ficheiros Chave
- `src/BioDesk.Services/IridologyTransform.cs` - Método FromHandlers
- `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs` - ViewModel principal
- `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml` - UI
- `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs` - Code-behind

---

## ✅ Conclusão Final

### Para Completar a Refatoração
1. ✅ **Fase 1**: Completa
2. 🔴 **Fase 2**: CRÍTICA - Fazer primeiro! (1-2h)
3. 🟡 **Fase 3**: Opcional - Pode fazer depois (3-4h)
4. 🟢 **Fase 4**: Validação - Obrigatória antes merge (1-2h)
5. 📸 **Fase 5**: Screenshots - Nice to have (30min)

### Tempo Total Estimado
- **Fase 1**: ✅ 2h (completa)
- **Fases 2-5**: 🔴 6-8h (pendente)
- **Total**: ~8-10 horas trabalho

### Prioridade de Execução
1. 🔴 **Fase 2 Passo 1-2** (CRÍTICO: ~1h) - Sistema funciona
2. 🟢 **Fase 4** (Validação: ~1h) - Confirma funcionamento
3. 🟡 **Fase 3** (Limpeza: ~3h) - Melhora qualidade (opcional)
4. 📸 **Fase 5** (Docs: ~30m) - Finaliza PR

---

**Status Geral**: 🟢 Fase 1 Completa | 🔴 Fases 2-5 Pendentes  
**Data Atualização**: 27 Outubro 2025  
**Próximo Passo**: Implementar Fase 2 (Handler_MouseMove + AtualizarCalibracao)
