# REFERÊNCIA RÁPIDA - Sistema Infalível (Agente)

## 🎯 CONFIRMAÇÃO: PODE PROCEDER COM REMOÇÃO

### ✅ Sistema Overlay JÁ ESTÁ 100% IMPLEMENTADO

**Ficheiros verificados**:
- `src/BioDesk.Services/Iridology/IrisOverlayService.cs` (400 linhas) ✅
- `src/BioDesk.ViewModels/Abas/IrisdiagnosticoViewModel.cs` (linhas 116-1183: overlay) ✅
- `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml` (linhas 1438-1605: UI) ✅
- `src/BioDesk.App/Views/Abas/IrisdiagnosticoUserControl.xaml.cs` (linha 51: handler) ✅
- `src/BioDesk.App/App.xaml.cs` (linha ~82: DI) ✅

---

## 🚫 NÃO TOCAR (Sistema Overlay - Protegido)

### ViewModel (IrisdiagnosticoViewModel.cs)
```
Linha 16: using BioDesk.Services.Iridology;
Linha 33: private readonly IrisOverlayService _overlayService;
Linha 116-134: Propriedades overlay (IsAlignmentActive, InstructionText, OverlayTransform)
Linha 324: Construtor - IrisOverlayService overlayService parameter
Linha 1051-1061: StartOverlayAlignmentCommand
Linha 1089-1124: AutoFitOverlayCommand
Linha 1126-1145: ConfirmAlignmentCommand
Linha 1147-1166: ResetAlignmentCommand
Linha 1168-1183: ProcessOverlayClick method
```

### XAML (IrisdiagnosticoUserControl.xaml)
```
Linha 1438-1605: 4 botões overlay (Iniciar, Auto-Fit, Confirmar, Reiniciar)
MapaOverlayCanvas: RenderTransform="{Binding OverlayTransform}"
MapaOverlayCanvas: MouseLeftButtonDown="MapaOverlayCanvas_Click"
```

### Code-Behind (IrisdiagnosticoUserControl.xaml.cs)
```
Linha 51: MapaOverlayCanvas_Click handler
```

### Service (IrisOverlayService.cs)
```
TODO O FICHEIRO - NÃO MODIFICAR (400 linhas perfeitas)
```

---

## ✅ PODE APAGAR (Sistema Antigo - ~1800 linhas)

### Classe CalibrationHandler (Fase 8)
```
Linha ~155-177: public class CalibrationHandler : ObservableObject { ... }
~18 linhas
```

### Propriedades (Fase 7 - ~163 linhas)
```
Modos:
- _modoCalibracaoAtivo
- _tipoCalibracaoPupila, _tipoCalibracaoIris, _tipoCalibracaoAmbos
- _modoMoverMapa

Handlers:
- HandlersPupila (ObservableCollection)
- HandlersIris (ObservableCollection)
- _quantidadeHandlersIris, _quantidadeHandlersPupila
- _escalaHandler

Centro/Raio Pupila:
- _centroPupilaX, _centroPupilaY
- _raioPupila, _raioPupilaHorizontal, _raioPupilaVertical
- _escalaPupilaX, _escalaPupilaY

Centro/Raio Íris:
- _centroIrisX, _centroIrisY
- _raioIris, _raioIrisHorizontal, _raioIrisVertical
- _escalaIrisX, _escalaIrisY

Transform Mapa:
- _mapaOffsetX, _mapaOffsetY, _mapaRotacao, _mapaZoom

Flags:
- _suspendHandlerUpdates, _atualizandoContagemHandlers
- _isDragging, _mostrarPoligonosDuranteArrasto
- _lastRenderTime, RenderThrottleMs

Constantes:
- MAPA_ZOOM_STEP, MAPA_MOVIMENTO_STEP, MAPA_ROTACAO_STEP
```

### Comandos Zoom/Movimento (Fase 3 - ~110 linhas)
```
Linha ~713: AumentarMapaCommand (ERRO 1 - vai resolver)
Linha ~719: DiminuirMapaCommand (ERRO 2 - vai resolver)
Linha ~725: ResetMapaCommand (ERRO 3 - vai resolver)
MoverMapaCima/Baixo/Esquerda/Direita Commands
RotacionarMapaHorario/AntiHorario Commands
ResetCalibracaoCommand
```

### Métodos Core Calibração (Fase 5 - ~535 linhas)
```
InicializarHandlers
OnQuantidadeHandlersIrisChanged, OnQuantidadeHandlersPupilaChanged
CriarHandlers
NormalizeAngleDegrees, NormalizeAngleRadians
LimparHandlers
OnHandlersCollectionChanged, OnHandlerPropertyChanged
TransladarCalibracao
RecalcularParametrosPelosHandlers
RecalcularCentroEraioIrisPelosHandlers
RecalcularCentroEraioNormalPelosHandlers
ResetCalibracaoInterna
```

### Métodos Renderização (Fase 9 - ~420 linhas)
```
RenderizarPoligonosComDeformacao (versão antiga com handlers)
InterpolateZoneWithHandlers
GetRaioNominalFixo, GetRaioNominal
CalcularPesosRadiais
ConverterRaioParaPupila
InterpolateRadiusFromHandlers
NormalizarAngulo
AtualizarTransformacoesGlobais
AtualizarTransformacaoIris, AtualizarTransformacaoPupila
RegistrarCalibracao
OnModoMoverMapaChanged, OnModoCalibracaoAtivoChanged
```

### Serialização (Fase 4 - ~31 linhas)
```
SerializarEstadoCalibracaoParaJson
ObterEstadoCalibracao
```

### Event Listeners (Fase 6 - 2 linhas)
```
Linha ~332-333 (no construtor):
HandlersIris.CollectionChanged += OnHandlersCollectionChanged;
HandlersPupila.CollectionChanged += OnHandlersCollectionChanged;
```

### XAML UI Antiga (Fase 10 - ~150-200 linhas)
```
ItemsControl HandlersPupila (binding + template)
ItemsControl HandlersIris (binding + template)
Botões: AumentarMapa, DiminuirMapa
Botões: MoverMapaCima/Baixo/Esquerda/Direita
Botões: RotacionarMapaHorario/AntiHorario
Botão: ResetCalibracao
CheckBox: ModoCalibracaoAtivo
ComboBox: TipoCalibração*
TextBox: QuantidadeHandlers*
```

---

## 🔴 ERROS ATUAIS (3) - RESOLVIDOS NA FASE 3

```
Linha 713: AjustarMapaZoom(MapaZoom + MAPA_ZOOM_STEP);  // em AumentarMapaCommand
Linha 719: AjustarMapaZoom(MapaZoom - MAPA_ZOOM_STEP);  // em DiminuirMapaCommand
Linha 725: AjustarMapaZoom(1.0);  // em ResetMapaCommand
```

**Razão**: Método `AjustarMapaZoom` foi deletado (Bloco 9, ontem)

**Solução**: Deletar os 3 comandos completos (Fase 3) - ~110 linhas

**Após Fase 3**: `dotnet build` - 0 erros ✅

---

## 📊 ESTATÍSTICAS ALVO

| Métrica | Antes | Depois | Δ |
|---------|-------|--------|---|
| ViewModel linhas | 2271 | ~900 | -1371 (-60%) |
| XAML linhas | 1606 | ~1400 | -206 (-13%) |
| Total removido | - | ~1800 | - |

---

## ✅ CHECKPOINTS CRÍTICOS

**Fase 3 (15 min)**:
- `dotnet build` deve compilar (0 erros AjustarMapaZoom)

**Fase 7 (30 min)**:
- Build vai FALHAR (esperado, muitas referências quebradas)

**Fase 9 (45 min)**:
- Build deve começar a compilar novamente

**Fase 11 (30 min)** - **CRÍTICO**:
- `dotnet build` - 0 erros
- `dotnet test` - PASS
- `dotnet run --project src/BioDesk.App` - executa sem crash
- Overlay funciona 100%

---

## 🔒 BACKUPS (Fase 1)

```bash
# Commit pré-refactor
git add -A
git commit -m "PRE-REFACTOR: Sistema overlay implementado, blocos 8-9 removidos"

# Branch backup
git checkout -b backup/pre-sistema-infalivel-completo-29out2025
git push origin backup/pre-sistema-infalivel-completo-29out2025
git checkout copilot/vscode1760912759554

# BD backup
Copy-Item "biodesk.db" "Backups/biodesk_pre_infalivel_29out2025.db"
```

---

## 📖 DOCUMENTOS DE REFERÊNCIA

- `PLANO_SISTEMA_INFALIVEL_COMPLETO_29OUT2025.md` - Plano detalhado completo
- `PLANO_OVERLAY_INFALIVEL_29OUT2025.md` - Contexto Steps 1-9 (implementação overlay)
- Este ficheiro - Referência rápida durante execução

---

## 🎯 ORDEM DE EXECUÇÃO

1. ✅ Fase 1: Backup (5 min)
2. ✅ Fase 2: Análise (10 min)
3. ✅ Fase 3: Comandos zoom (15 min) - **FIXA ERROS**
4. ✅ Fase 4: Serialização (5 min)
5. ✅ Fase 5: Métodos core (20 min)
6. ✅ Fase 6: Event listeners (2 min)
7. ✅ Fase 7: Propriedades (30 min) - **CRÍTICO**
8. ✅ Fase 8: Classe handler (3 min)
9. ✅ Fase 9: Renderização (45 min) - **COMPLEXO**
10. ✅ Fase 10: XAML (15 min)
11. ✅ Fase 11: Build + Testes (30 min) - **VERIFICAÇÃO**
12. ✅ Fase 12: Documentação (20 min)
13. ✅ Fase 13: Commit final (10 min)

**Total**: ~3-4 horas

---

## 🚀 PODE COMEÇAR!

**Autorização**: ✅ CONFIRMADA
**Sistema overlay**: ✅ 100% IMPLEMENTADO
**Código para remover**: ✅ IDENTIFICADO
**Plano**: ✅ DETALHADO
**Backups**: ✅ PREPARADOS

**BOA EXECUÇÃO! 💪**

---

*Documento criado: 29/10/2025 23:58*
*Para: GitHub Copilot Coding Agent*
*Referência: PR #14, Commit b91778f*
