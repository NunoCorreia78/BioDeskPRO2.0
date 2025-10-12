# 🚀 PLANO DE IMPLEMENTAÇÃO - TERAPIAS BIOENERGÉTICAS (VERSÃO COMPLETA)
**Data**: 12 de Outubro de 2025
**Modalidade**: **PRODUÇÃO REAL** - Sem limitações, com Inergetix Core funcional
**Hardware**: TiePie HS3 + Alea RNG (opcional, código preparado)
**Excel**: Dados reais fornecidos pelo utilizador

---

## 🎯 DECISÕES TOMADAS

### ✅ **CONFIRMADO pelo Utilizador**:
1. **Excel Real**: Inúmeras questões de saúde + frequências disponíveis
2. **Inergetix Core**: Funciona perfeitamente no PC
3. **Alea RNG**: Opcional (código preparado mas não bloqueante)
4. **Modo**: **COMPLETO** - Aplicação real sem limitações
5. **Hardware**: TiePie HS3 disponível

### 🎯 **OBJETIVOS**:
- Sistema CoRe 5.0 moderno
- Processamento do Excel real do utilizador
- Integração TiePie HS3 real
- RNG determinístico + Alea opcional
- Value % + Improvement % funcionais
- UI profissional com LiveCharts2

---

## 📋 FASES DE IMPLEMENTAÇÃO

### **FASE 1: Infraestrutura Base** (6-8h)
**Prioridade**: CRÍTICA
**Dependências**: Nenhuma

#### 1.1 Entidades de Domínio
- [ ] `PlanoTerapia.cs`
- [ ] `ProtocoloTerapeutico.cs`
- [ ] `Terapia.cs`
- [ ] `SessaoTerapia.cs`
- [ ] `LeituraBioenergetica.cs`
- [ ] `EventoHardware.cs`
- [ ] `ImportacaoExcelLog.cs`

#### 1.2 Migrations EF Core
- [ ] Migration: `AddTerapiasBioenergeticasTables`
- [ ] Seed data inicial (5 protocolos exemplo)
- [ ] Índices otimizados

#### 1.3 Repositories
- [ ] `ITerapiaRepository` + implementação
- [ ] `IProtocoloRepository` + implementação
- [ ] `ISessaoTerapiaRepository` + implementação

**Output**: Build passa + BD com tabelas criadas

---

### **FASE 2: Importação Excel REAL** (5-7h)
**Prioridade**: CRÍTICA (tem dados para importar JÁ)
**Dependências**: Fase 1

#### 2.1 Serviço de Importação
- [ ] `IExcelImportService.cs` (interface)
- [ ] `ExcelImportService.cs` (EPPlus)
- [ ] Validador FluentValidation (schema v1)
- [ ] Mapeamento Excel → ProtocoloTerapeutico
- [ ] Upsert por `ExternalId` (idempotência)

#### 2.2 Validações
- [ ] Campos obrigatórios: Nome, FrequenciaHz
- [ ] Ranges: AmplitudeV (0-20), LimiteCorrenteMa (0-50), DuracaoMin (1-180)
- [ ] Enums: FormaOnda, Modulacao, Canal
- [ ] Defaults seguros se omitir

#### 2.3 Relatório de Importação
- [ ] Linhas OK / Warnings / Erros
- [ ] Preview antes de confirmar
- [ ] Log em `ImportacaoExcelLog`

**Output**: Excel do utilizador importado com sucesso

---

### **FASE 3: RNG & Algoritmos** (6-8h)
**Prioridade**: ALTA
**Dependências**: Fase 1

#### 3.1 Fontes de Aleatoriedade
- [ ] `IRandomSource.cs` (interface)
- [ ] `DeterministicCsprng.cs` (seed por sessão)
- [ ] `SystemRngSource.cs` (fallback)
- [ ] `AleaRngSource.cs` (wrapper Alea, opcional)
- [ ] Auto-deteção: Alea presente → usa; senão → Deterministic

#### 3.2 Algoritmo Value %
- [ ] Score base por item (RNG ou fisiológico)
- [ ] Normalização [0..100]
- [ ] Ordenação descendente
- [ ] Limiar configurável (default 30%)

#### 3.3 Algoritmo Improvement %
- [ ] EMA de métricas (RMS, Pico, FreqDom, GSR)
- [ ] Cálculo heurístico combinado
- [ ] Auto-desmarcar ao atingir alvo (95-100%)

**Output**: Algoritmos testados com unit tests

---

### **FASE 4: Integração TiePie HS3** (8-12h)
**Prioridade**: ALTA
**Dependências**: Fase 3

#### 4.1 Abstração Hardware
- [ ] `IMedicaoService.cs` (interface)
- [ ] Records: `LeituraConfig`, `SaidaConfig`, `LeituraAmostra`, `DeviceInfo`
- [ ] `MockMedicaoService.cs` (para testes sem hardware)

#### 4.2 TiePie Service Real
- [ ] `TiePieService.cs` (wrapper SDK)
- [ ] Descoberta de dispositivos
- [ ] Conexão/Desconexão
- [ ] Captura em background (Thread + CancellationToken)
- [ ] Configuração AWG (Hz, Vpp, Forma, Canal)
- [ ] Limites de segurança (20V max, 50mA max)

#### 4.3 Buffer & Downsampling
- [ ] Buffer circular para captura
- [ ] Downsampling para UI (não travar gráficos)
- [ ] Armazenamento bruto em ficheiro externo

#### 4.4 Eventos Hardware
- [ ] Connected/Disconnected/Error/Overlimit
- [ ] Log em `EventoHardware`

**Output**: TiePie funcional + testes com hardware real

---

### **FASE 5: UI Tab 7 Completa** (12-16h)
**Prioridade**: ALTA
**Dependências**: Fases 2, 3, 4

#### 5.1 XAML Layout
- [ ] `TerapiasUserControl.xaml` (3 colunas)
- [ ] Coluna 1: Catálogo + Fila + Importar Excel
- [ ] Coluna 2: Controlos + Biofeedback
- [ ] Coluna 3: Gráficos + Indicadores
- [ ] Paleta terroso pastel

#### 5.2 ViewModel
- [ ] `TerapiasViewModel.cs` (herda ViewModelBase)
- [ ] Propriedades observáveis: Estado, Fila, Controlo, Métricas
- [ ] Comandos: Importar, Adicionar, Guardar, Iniciar, Pausar, Parar
- [ ] ExecuteWithErrorHandlingAsync para todas operações

#### 5.3 LiveCharts2 Integração
- [ ] Gráfico tempo real (RMS, Pico)
- [ ] FFT (espectro de frequências)
- [ ] Improvement % por item (barras progressivas)
- [ ] Limitar pontos visíveis (performance)

#### 5.4 Bindings & Converters
- [ ] Converters para enums (FormaOnda, Modulacao)
- [ ] Formatadores de unidades (Hz, V, mA)
- [ ] Validação visual de campos

**Output**: Tab 7 funcional e profissional

---

### **FASE 6: Sessões & Relatórios** (4-6h)
**Prioridade**: MÉDIA
**Dependências**: Fase 5

#### 6.1 Gestão de Sessões
- [ ] Criar sessão ao iniciar
- [ ] Guardar Value % inicial por item
- [ ] Guardar Improvement % final
- [ ] Guardar parâmetros emitidos (Hz, V, mA, Forma, Tempo)
- [ ] Guardar seed/RNG info para reprodutibilidade

#### 6.2 Relatórios
- [ ] Relatório de sessão (PDF via QuestPDF)
- [ ] Gráfico de evolução Improvement %
- [ ] Lista de protocolos aplicados
- [ ] Estatísticas (tempo total, nº itens, média Improvement)
- [ ] Export para paciente

#### 6.3 Consentimento
- [ ] Link `SessaoTerapia` → `Consentimento`
- [ ] Validação obrigatória antes de iniciar

**Output**: Sessões rastreáveis e exportáveis

---

### **FASE 7: Polimento & Testes** (4-6h)
**Prioridade**: MÉDIA
**Dependências**: Todas anteriores

#### 7.1 Testes Automatizados
- [ ] Unit tests: ViewModels, Algoritmos, Validadores
- [ ] Contract tests: IMedicaoService (Mock vs TiePie)
- [ ] Golden tests: ficheiros Excel exemplo
- [ ] Integration tests: importação + BD

#### 7.2 Error Handling
- [ ] Mensagens de erro claras
- [ ] Retry automático em timeouts
- [ ] Fallbacks (Alea indisponível → Deterministic)

#### 7.3 Logging
- [ ] Categorias: Hardware, Algoritmo, Importacao, UI
- [ ] Códigos: HW_TIMEOUT, IMPORT_SCHEMA_INVALID, etc.
- [ ] Anexar logs à sessão em caso de falha

#### 7.4 Documentação
- [ ] Runbook de operação
- [ ] Troubleshooting comum
- [ ] Schema Excel atualizado

**Output**: Sistema robusto e documentado

---

## 📦 DEPENDÊNCIAS (NuGet Packages)

```bash
# Excel
dotnet add src/BioDesk.Services package EPPlus --version 7.0.0

# LiveCharts2
dotnet add src/BioDesk.App package LiveChartsCore.SkiaSharpView.WPF --version 2.0.0-rc2

# Math (FFT)
dotnet add src/BioDesk.Services package MathNet.Numerics --version 5.0.0

# TiePie SDK
# (Wrapper nativo - fornecer DLL separadamente ou via NuGet privado)
```

---

## 🗓️ CRONOGRAMA ESTIMADO

| Fase | Horas | Semana | Status |
|------|-------|--------|--------|
| Fase 1: Infraestrutura | 6-8h | Semana 1 | ⏸️ Aguarda |
| Fase 2: Excel Real | 5-7h | Semana 1 | ⏸️ Aguarda |
| Fase 3: RNG + Algoritmos | 6-8h | Semana 1-2 | ⏸️ Aguarda |
| Fase 4: TiePie HS3 | 8-12h | Semana 2 | ⏸️ Aguarda |
| Fase 5: UI Completa | 12-16h | Semana 2-3 | ⏸️ Aguarda |
| Fase 6: Sessões | 4-6h | Semana 3 | ⏸️ Aguarda |
| Fase 7: Polimento | 4-6h | Semana 3 | ⏸️ Aguarda |
| **TOTAL** | **45-63h** | **3 semanas** | |

**Nota**: Estimativa pode variar com complexidade do Excel e testes hardware.

---

## 🚀 PRÓXIMOS PASSOS IMEDIATOS

### **PASSO 1: Cole Seu Excel** (AGORA) ✅
1. Abra o Excel com suas questões de saúde + frequências
2. Cole em: `Templates/Terapias/PROTOCOLOS_FREQUENCIAS.xlsx`
3. Verifique se tem colunas: `Nome`, `FrequenciaHz` (mínimo)

### **PASSO 2: Verificar TiePie SDK** (5 min)
```bash
# Verificar se driver está instalado
# Verificar DLLs em C:\Program Files\TiePie\...
```

### **PASSO 3: Iniciar Fase 1** (6-8h)
- Criar entidades de domínio
- Migrations EF Core
- Repositories

---

## ❓ PERGUNTAS ANTES DE COMEÇAR

1. **Formato Excel**: Quantas colunas tem? Pode partilhar screenshot das primeiras linhas?
2. **TiePie SDK**: Versão instalada? Caminho das DLLs?
3. **Alea**: Se tiver, onde está instalado? SDK disponível?

---

## 🎯 DEFINIÇÃO DE SUCESSO

Ao final das 3 semanas:

✅ Excel importado com TODAS as suas questões
✅ TiePie HS3 emitindo frequências reais
✅ Value % + Improvement % funcionando
✅ Sessões guardadas com relatórios
✅ UI profissional e responsiva
✅ Alea opcional integrado (se disponível)
✅ Código auditável e reprodutível

---

**PRÓXIMA AÇÃO**: Cole seu Excel em `Templates/Terapias/` e confirme! 🚀
