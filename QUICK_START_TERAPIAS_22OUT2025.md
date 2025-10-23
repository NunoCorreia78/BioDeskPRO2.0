# ⚡ QUICK START - Testar UI Redesign Terapias

## 🚀 Execução Rápida (5 minutos)

### 1️⃣ Ativar Modo Dummy (Opcional mas Recomendado)

**Ficheiro**: `src/BioDesk.App/appsettings.json`

```json
{
  "TiePie": {
    "UseDummyTiePie": true,  // ✅ TRUE = testa sem hardware
    "AutoInitialize": true
  }
}
```

### 2️⃣ Executar App

```powershell
# Defina $ProjectPath para o caminho do projeto antes de executar, ex:
# $ProjectPath = "D:\\BioDeskPro2"
cd $ProjectPath
dotnet run --project src/BioDesk.App
```

### 3️⃣ Teste Rápido (2 minutos)

1. **Dashboard** → **Terapias** → **Programas**
2. Selecionar 1 programa (Ctrl+Click)
3. Clicar **"Iniciar Programas"**
4. **VERIFICAR**:
   - ✅ Card progresso expande
   - ✅ Frequência atualiza (ex: 432 Hz → 440 Hz → ...)
   - ✅ Tempo decrementa (18min 45s → 18min 44s → ...)
   - ✅ Barra de progresso enche
5. Clicar **"PARAR"** → Confirmar
6. **VERIFICAR**:
   - ✅ Terapia interrompe
   - ✅ Card volta ao estado compacto

---

## ✅ Se Teste Rápido Passar

**Status**: 🟢 UI Redesign Funcional

**Próximo**: Executar testes completos (6 testes) via:
```
GUIA_TESTE_UI_TERAPIAS_22OUT2025.md
```

---

## ❌ Se Teste Rápido Falhar

**Debug**:
1. Verificar Output do VS Code (erros de binding)
2. Verificar Problems Panel (squiggles)
3. Executar:
   ```bash
   dotnet clean && dotnet build
   ```
4. Revisar `VALIDACAO_UI_TERAPIAS_22OUT2025.md`

---

## 📚 Documentação Completa

| Documento | Finalidade |
|-----------|-----------|
| `SUMARIO_REDESIGN_UI_TERAPIAS_22OUT2025.md` | Visão geral executiva |
| `VALIDACAO_UI_TERAPIAS_22OUT2025.md` | Validação técnica detalhada |
| `GUIA_TESTE_UI_TERAPIAS_22OUT2025.md` | 6 testes práticos passo-a-passo |
| `REDESIGN_UI_TERAPIAS_20OUT2025.md` | Especificações originais |

---

**Data**: 22/10/2025 | **Build**: 0 Errors ✅ | **Status**: 🟢 PRONTO
