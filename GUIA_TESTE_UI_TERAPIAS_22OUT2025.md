# 🧪 GUIA DE TESTE PRÁTICO - UI REDESIGN TERAPIAS

## 📋 Pré-requisitos

1. **Build Limpo**: ✅ Concluído (0 Errors)
2. **Hardware HS3**: ⚠️ Opcional (pode usar modo dummy)
3. **Tempo Estimado**: 15-20 minutos

---

## 🔧 Configuração Inicial

### Ativar Modo Dummy (Recomendado para Testes)

**Localização**: `src/BioDesk.App/appsettings.json`

```json
{
  "TiePie": {
    "UseDummyTiePie": true,  // ✅ SET TRUE para testar sem hardware
    "AutoInitialize": true
  }
}
```

**Vantagens**:
- ✅ Testa lógica UI sem precisar hardware físico
- ✅ Evita conflitos com Inergetix Core
- ✅ Progresso e frequências são simulados

---

## 🚀 Executar Aplicação

```bash
# Defina $ProjectPath para o local do projeto (ex: D:\\BioDeskPro2) e execute:
cd $ProjectPath
dotnet run --project src/BioDesk.App
```

**Verificar**: Aplicação abre sem erros no Dashboard ✅

---

## 📝 Testes Sequenciais

### ✅ TESTE 1: Visualização Inicial (Estado Inativo)

**Objetivo**: Confirmar que o card de progresso está sempre visível (placeholder).

**Passos**:
1. Dashboard → Clicar em **"Terapias"**
2. Selecionar aba **"Programas"**

**Verificar**:
- [x] Controlos compactos no topo (1 linha horizontal)
  - ComboBox voltagem
  - Slider duração
  - RadioButtons tempo/frequência
  - TextBox ajuste ±Hz
  - Botão "Iniciar Programas" (verde)
  - Botão "PARAR" (vermelho, desabilitado)
- [x] Card progresso abaixo dos controlos
  - Background claro (`#F7F9F6`)
  - Mensagem: **"⏸ Aguardando início da terapia..."**
  - Altura compacta (~40-50px)
- [x] Lista de programas abaixo (DataGrid)

**Screenshot Sugerido**: `teste1_estado_inativo.png`

---

### ✅ TESTE 2: Iniciar Terapia (Card Expande)

**Objetivo**: Confirmar que o card progresso expande e mostra informação em tempo real.

**Passos**:
1. Na lista de programas, **Ctrl+Click** para selecionar 2-3 programas
   - Ex: `PROTO::AIDS secondary`, `PROTO::Malaria`
2. Configurar nos controlos:
   - Voltagem: **5V**
   - Duração: **30 min**
   - Tempo/Freq: **10s** (cada frequência dura 10 segundos)
   - Ajuste: **+2 Hz**
3. Clicar **"Iniciar Programas"**

**Verificar (Card Progresso Expandido)**:
- [x] **Linha 1**: `⚡ TERAPIA EM ANDAMENTO` (título)
- [x] **Linha 2**: `🎵 Frequência: 434.00 Hz (Original: 432 Hz, Ajuste: +2)`
  - Frequência atualiza a cada 10s
  - Original + Ajuste exibidos claramente
- [x] **Linha 3**: `📋 Programa: [Ciclo 1] PROTO::AIDS secondary`
  - Nome do programa atual
  - Indicador de ciclo
- [x] **Linha 4**: `📊 Progresso: 5/120 frequências (4.2%)`
  - Index atual / Total
  - Percentual calculado
- [x] **Linha 5**: `⏱ Falta: 18min 45s`
  - Tempo formatado (minutos + segundos)
  - Decrementa a cada segundo
- [x] **Linha 6**: Barra de progresso visual
  - `[████░░░░░░░░] 4.2%`
  - Enche gradualmente

**Ações Durante Terapia**:
- [x] Observar frequência mudando (ex: 432 → 440 → 728 Hz)
- [x] Observar tempo decrementando (18min 45s → 18min 44s → ...)
- [x] Observar barra de progresso enchendo

**Screenshot Sugerido**: `teste2_terapia_ativa.png`

---

### ✅ TESTE 3: Parar Terapia

**Objetivo**: Confirmar que botão PARAR interrompe terapia corretamente.

**Passos**:
1. Durante terapia ativa (Teste 2)
2. Clicar **"PARAR"** (botão vermelho)
3. Confirmar no diálogo: **"Sim"**

**Verificar**:
- [x] Terapia interrompe imediatamente
- [x] Card progresso volta ao estado compacto
- [x] Mensagem: **"⏸ Aguardando início da terapia..."**
- [x] Botão "Iniciar Programas" volta a ficar habilitado

**Screenshot Sugerido**: `teste3_parar_terapia.png`

---

### ✅ TESTE 4: Ajuste de Frequência ±Hz

**Objetivo**: Confirmar que ajuste ±Hz é aplicado e exibido corretamente.

**Passos**:
1. Selecionar 1 programa com frequência base conhecida (ex: 432 Hz)
2. Configurar **Ajuste: +5 Hz** nos controlos
3. Iniciar terapia

**Verificar (Card Progresso)**:
- [x] **Frequência exibida**: `437.00 Hz`
- [x] **Detalhamento**: `Original: 432 Hz, Ajuste: +5`
- [x] Cálculo correto: `432 + 5 = 437` ✅

**Teste Variação**:
- Ajuste: **-3 Hz** → Frequência: `429.00 Hz` (Original: 432 Hz, Ajuste: -3)

**Screenshot Sugerido**: `teste4_ajuste_hz.png`

---

### ✅ TESTE 5: Ressonantes (Sem Linha Programa)

**Objetivo**: Confirmar que `MostrarPrograma="False"` esconde linha de programa.

**Passos**:
1. Navegar para aba **"Ressonantes"**
2. Configurar sweep:
   - Início: **100 Hz**
   - Fim: **1000 Hz**
   - Passo: **10 Hz**
   - Tempo por frequência: **5s**
3. Clicar **"Iniciar Ressonantes"**

**Verificar (Card Progresso)**:
- [x] **Linha "Programa:" NÃO está visível** ✅
- [x] Frequência atual do sweep (ex: `150 Hz`)
- [x] Progresso baseado em pontos do sweep (ex: `5/90 frequências`)
- [x] Tempo restante formatado (ex: `7min 15s`)

**Screenshot Sugerido**: `teste5_ressonantes.png`

---

### ✅ TESTE 6: Biofeedback (Interface Minimalista)

**Objetivo**: Confirmar que tabela histórico foi removida e interface está minimalista.

**Passos**:
1. Navegar para aba **"Biofeedback"**

**Verificar**:
- [x] Controlos compactos no topo ✅
- [x] Card progresso (estado inativo) ✅
- [x] **Tabela histórico de sessões NÃO está visível** ✅
- [x] Apenas botão **"Iniciar Sessão Biofeedback"** visível
- [x] Interface limpa e minimalista

**Screenshot Sugerido**: `teste6_biofeedback_minimalista.png`

---

## 🎨 Verificação Visual (Design)

### Paleta de Cores Terroso Pastel
- [x] Fundo principal: `#FCFDFB` (branco levemente esverdeado)
- [x] Cartões: `#F7F9F6` (verde suave)
- [x] Bordas: `#E3E9DE` (verde claro)
- [x] Botão primário: `#9CAF97` (verde sálvia)
- [x] Texto principal: `#3F4A3D` (verde escuro)

### Espaçamento e Layout
- [x] Controlos compactos: 1 linha horizontal (sem scroll)
- [x] Card progresso: Espaçamento `Margin="0,0,0,15"`
- [x] Elementos alinhados verticalmente (3 rows)

---

## 📊 Resultados Esperados

### ✅ Funcionalidade
- [ ] Terapia inicia sem erros
- [ ] Frequência atualiza em tempo real
- [ ] Tempo decrementa a cada segundo
- [ ] Barra de progresso enche gradualmente
- [ ] Botão PARAR interrompe corretamente
- [ ] Ajuste ±Hz aplicado corretamente

### ✅ UI/UX
- [ ] Informação crítica sempre visível (sem scroll)
- [ ] Card progresso compacto quando inativo
- [ ] Card progresso expansível quando ativo
- [ ] Ressonantes: Linha programa escondida
- [ ] Biofeedback: Tabela histórico removida

---

## 🐛 Problemas Comuns e Soluções

### ❌ Problema: App não inicia
**Solução**:
```bash
dotnet clean
dotnet build
dotnet run --project src/BioDesk.App
```

### ❌ Problema: Binding não funciona (valores não atualizam)
**Debug**:
1. Verificar Output do VS Code → `Binding` errors
2. Verificar se ViewModel está conectado ao DataContext
3. Adicionar breakpoint no `set` da propriedade

### ❌ Problema: Card progresso não expande
**Solução**:
1. Verificar `TerapiaEmAndamento` no ViewModel
2. Verificar binding: `TerapiaEmAndamento="{Binding TerapiaEmAndamento}"`
3. Adicionar `Debug.WriteLine` no setter:
   ```csharp
   partial void OnTerapiaEmAndamentoChanged(bool value)
   {
       Debug.WriteLine($"🔄 TerapiaEmAndamento changed: {value}");
   }
   ```

### ❌ Problema: Hardware HS3 não detectado
**Solução**:
1. Fechar Inergetix Core
2. OU: Ativar `UseDummyTiePie: true` em `appsettings.json`

---

## 📸 Checklist de Screenshots (Opcional)

- [ ] `teste1_estado_inativo.png` - Card progresso compacto
- [ ] `teste2_terapia_ativa.png` - Card progresso expandido com dados
- [ ] `teste3_parar_terapia.png` - Diálogo confirmação
- [ ] `teste4_ajuste_hz.png` - Frequência com ajuste aplicado
- [ ] `teste5_ressonantes.png` - Sweep sem linha programa
- [ ] `teste6_biofeedback_minimalista.png` - Interface limpa

---

## ✅ Conclusão

Após completar todos os 6 testes:

1. Se **TODOS os testes passarem**: 🟢 **UI REDESIGN VALIDADO**
2. Se **algum teste falhar**: 🔴 **Documentar problema e debugar**

---

**Data**: 22 de Outubro de 2025
**Autor**: AI Copilot
**Status**: 🔄 Pronto para Execução Manual
