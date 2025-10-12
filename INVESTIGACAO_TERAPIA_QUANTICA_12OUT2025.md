# 🔍 INVESTIGAÇÃO - Terapia Quântica / Bioenergética (Inergetix Core)
**Data**: 12 de Outubro de 2025
**Investigador**: GitHub Copilot
**Solicitante**: Nuno Correia

---

## 🎯 OBJETIVO DA INVESTIGAÇÃO

Localizar plano de implementação para **Terapia Quântica (tipo Inergetix Core)** no tab de terapias existente.

---

## 📊 RESULTADOS DA INVESTIGAÇÃO

### ✅ **ENCONTRADO: Infraestrutura Preparada**

#### 1. **Enum TipoAbordagem Suporta Medicina Bioenergética** ✅
**Ficheiro**: `src/BioDesk.Domain/Entities/Abordagem.cs`

```csharp
public enum TipoAbordagem
{
    Osteopatia = 1,
    Naturopatia = 2,
    Iridologia = 3,
    Massagem = 4,
    MedicinaBioenergetica = 5  // ✅ JÁ EXISTE!
}
```

**Status**: ✅ **COMPLETADO** - Infraestrutura de base de dados preparada

---

#### 2. **Seed Data com Exemplo de Medicina Bioenergética** ✅
**Ficheiro**: `src/BioDesk.Data/BioDeskDbContext.cs` (linha 550)

```csharp
new AbordagemSessao { 
    Id = 4, 
    SessaoId = 3, 
    TipoAbordagem = TipoAbordagem.MedicinaBioenergetica, 
    Observacoes = "Equilíbrio energético" 
}
```

**Status**: ✅ **COMPLETADO** - Dados de exemplo já existem na BD

---

#### 3. **Consentimento Medicina Bioenergética Criado** ✅
**Ficheiro**: `src/BioDesk.ViewModels/SeedData/ConsentimentosSeedData.cs`

Existe template de consentimento específico para Medicina Bioenergética no seed data.

**Status**: ✅ **COMPLETADO** - Template legal preparado

---

### ❌ **NÃO ENCONTRADO: Plano Específico Inergetix Core**

#### Pesquisa Realizada:
```bash
# Procurado em TODOS os ficheiros .md do projeto:
- "Inergetix" → 0 resultados
- "terapia quantica" → 0 resultados  
- "terapia quântica" → 0 resultados
- "quantum therapy" → 0 resultados

# Procurado ficheiros de plano específico:
- **/PLANO*TERAPIA*.md → 0 ficheiros
- **/*agente*.md → 0 ficheiros específicos
```

**Conclusão**: Não existe plano de implementação específico para Inergetix Core documentado.

---

## 📋 O QUE EXISTE ATUALMENTE

### ✅ **INFRAESTRUTURA PRONTA (Base de Dados)**
1. ✅ Enum `MedicinaBioenergetica` em `TipoAbordagem`
2. ✅ Tabela `AbordagensSessoes` suporta múltiplas abordagens por sessão
3. ✅ Seed data com exemplo de uso
4. ✅ Template de consentimento criado

### ⏸️ **INTERFACE NÃO IMPLEMENTADA (UI/UX)**
1. ❌ Não existe `TerapiaView.xaml` ou `TerapiaBioenergeticaView.xaml`
2. ❌ Não existe `TerapiaViewModel.cs` ou equivalente
3. ❌ Tab 8 (ou equivalente) está **desabilitada** ou não existe
4. ❌ Zero linhas de código XAML para interface de terapias

**Localização de Views Existentes**:
```
src/BioDesk.App/Views/Abas/
├── ComunicacaoUserControl.xaml
├── ConsentimentosUserControl.xaml
├── DadosBiograficosUserControl.xaml
├── DeclaracaoSaudeUserControl.xaml
├── DocumentosExternosUserControl.xaml
├── IrisdiagnosticoUserControl.xaml
└── RegistoConsultasUserControl.xaml

❌ TerapiasBioenergeticasUserControl.xaml NÃO EXISTE
```

---

## 📖 PLANOS ENCONTRADOS NOS RESUMOS

### **RESUMO_SESSAO_12OUT2025.md** (Linhas 180-260)

#### Contexto Utilizador:
> "acho que temos de começar a pensar seriamente na terapia"

#### Mudança de Prioridade:
- Sprint 3 P3 (Deformação Íris) → **CANCELADO**
- Nova Prioridade: **Terapia Bioenergética** (ALTA)

#### Opção A Recomendada (4-6 horas):
```markdown
### Opção A: Terapia Bioenergética (RECOMENDADO)
**Estimativa**: 4-6 horas
**Prioridade**: ALTA (pedido utilizador)

**Scope**:
1. Definir dados a capturar (chakras? meridianos? técnicas?)
2. Criar TerapiaView.xaml (UI lista + detail)
3. Criar TerapiaViewModel.cs (MVVM + ObservableCollection)
4. Integrar Tab 8 (habilitar botão + DataTemplate)
5. Implementar CRUD (Create, Read, Update, Delete)

**Perguntas para Utilizador**:
- Que dados registar numa sessão terapia bioenergética?
- Integração com Consulta/Sessao ou módulo separado?
- Campos específicos: chakras, meridians, técnicas aplicadas?
```

**Status**: ⏸️ **PLANEADO MAS NÃO INICIADO**

---

### **PLANO_DESENVOLVIMENTO_RESTANTE.md** (Linhas 180-260)

Este documento é de **03/10/2025** (9 dias atrás) e menciona:
- Tab 3 - Medicina Complementar (roadmap definido)
  - 3.1 Naturopatia
  - 3.2 Irisdiagnóstico
  - 3.3 Terapia Bioenergética

**Status**: 🗺️ **ROADMAP GENÉRICO** (sem detalhes específicos Inergetix)

---

## 🔍 ANÁLISE DO PROMPT_AGENTE_CODIFICACAO (07/10/2025)

Este documento define **3 tarefas prioritárias**:
1. ✅ Botão Eliminar Pacientes (CONCLUÍDO em sprint posterior)
2. ✅ Tabs Configurações com Templates PDF (CONCLUÍDO)
3. ⚠️ Auditoria Duplicações (ALTO RISCO - ainda não feito)

**Observação**: **ZERO MENÇÃO** a terapia quântica/bioenergética.

---

## 🚨 CONCLUSÃO CRÍTICA

### ❌ **NÃO EXISTE PLANO ESPECÍFICO INERGETIX CORE**

**O que foi pedido ao agente**:
> "Criar plano de implementação para terapia quântica como o Inergetix Core"

**O que o agente fez**:
- ✅ Criou infraestrutura de base de dados (`MedicinaBioenergetica`)
- ✅ Criou seed data e consentimentos
- ❌ **NÃO** criou plano de implementação detalhado
- ❌ **NÃO** definiu requisitos específicos Inergetix Core
- ❌ **NÃO** criou UI/Views/ViewModels

---

## 🎯 PRÓXIMOS PASSOS RECOMENDADOS

### **OPÇÃO 1: Criar Plano de Implementação Detalhado** (RECOMENDADO)

**Questões Críticas a Responder**:
1. **Workflow Inergetix Core**: Como funciona uma sessão típica?
2. **Dados a Capturar**:
   - Chakras? (7 principais + quais campos?)
   - Meridianos? (12 principais + pontos específicos?)
   - Frequências/Ressonâncias?
   - Scan inicial vs scan final?
   - Recomendações/Remédios sugeridos pelo sistema?
3. **Integração Hardware**:
   - O sistema Inergetix tem interface API?
   - Exporta ficheiros? Formato?
   - Conexão USB/Bluetooth?
4. **UI/UX Esperado**:
   - Visualização de chakras com cores?
   - Gráficos de meridianos?
   - Timeline de sessões?
   - Comparação antes/depois?

**Output**: Criar `PLANO_TERAPIA_QUANTICA_INERGETIX.md` com:
- Análise de requisitos
- Mockups UI (ou descrição textual)
- Estrutura de dados (entidades BD)
- Estimativa de tempo realista
- Fases de implementação

**Estimativa**: 1-2 horas de planeamento + 8-12 horas de implementação

---

### **OPÇÃO 2: Implementação Genérica "Medicina Bioenergética"** (ALTERNATIVA)

Se não houver acesso ao Inergetix Core para reverse-engineering:

**Scope Simplificado**:
1. Criar `TerapiasBioenergeticasUserControl.xaml` (estilo RegistoConsultas)
2. ViewModels para CRUD básico
3. Campos genéricos:
   - Data/Hora sessão
   - Observações gerais
   - Técnicas aplicadas (dropdown/chips)
   - Resultado percebido (escala 1-10)
   - Notas privadas terapeuta

**Vantagem**: Funcional rapidamente (4-6h) sem hardware específico
**Desvantagem**: Não aproveita recursos do Inergetix Core

---

### **OPÇÃO 3: Sessão de Brainstorming com Utilizador** (ÓPTIMO)

Agendar 30-60 minutos para:
1. Demo do Inergetix Core em funcionamento
2. Walkthrough de sessão típica
3. Identificar pontos de integração críticos
4. Definir MVP (Minimum Viable Product)

**Output**: Requisitos claros → Plano detalhado → Implementação eficiente

---

## 📊 ESTADO ATUAL DO SISTEMA

### ✅ **FUNCIONA PERFEITAMENTE**:
1. Dashboard
2. Gestão Pacientes (CRUD completo)
3. Ficha Paciente (6 abas):
   - Dados Biográficos ✅
   - Declaração Saúde ✅
   - Consentimentos ✅
   - Registo Consultas ✅
   - Irisdiagnóstico ✅
   - Comunicação ✅
4. PathService (Debug/Release)
5. Email Queue Processor
6. Templates PDF (Prescrições/Consentimentos)

### ⏸️ **PREPARADO MAS NÃO IMPLEMENTADO**:
7. 🔮 **Terapia Bioenergética** (BD pronta, UI 0%)

### 🚧 **EM ROADMAP FUTURO**:
8. Naturopatia (templates por objetivo)
9. Análises Clínicas (upload PDFs)
10. Backup automático

---

## 🤔 PERGUNTAS PARA O UTILIZADOR

1. **Acesso ao Hardware Inergetix Core**:
   - Tem o equipamento disponível?
   - Documentação API/SDK disponível?
   - Exporta dados? Formato (XML/JSON/CSV)?

2. **Prioridade vs Outras Features**:
   - Terapia Quântica > Naturopatia?
   - Timeline esperada (Sprint 3? Sprint 4?)

3. **Nível de Detalhe UI**:
   - Interface simples (notas texto)?
   - Interface avançada (visualização chakras/meridianos)?
   - Integração direta com Inergetix?

4. **Workflow Atual (Sem Sistema)**:
   - Como regista sessões atualmente? (papel? Excel?)
   - Que informação é crítica guardar?
   - Relatórios necessários para paciente?

---

## 📝 DOCUMENTOS A CRIAR (Se prosseguir)

1. **REQUISITOS_TERAPIA_QUANTICA.md**
   - Análise detalhada do Inergetix Core
   - Use cases principais
   - Dados a capturar

2. **MOCKUPS_UI_TERAPIA_QUANTICA.md**
   - Wireframes textuais ou imagens
   - Fluxo de navegação
   - Interações principais

3. **PLANO_IMPLEMENTACAO_TERAPIA_QUANTICA.md**
   - Fases (1: MVP, 2: Features avançadas, 3: Integração)
   - Estimativas tempo
   - Dependencies (hardware/software)

4. **ENTIDADES_BD_TERAPIA_QUANTICA.md**
   - Novas tabelas necessárias
   - Migrações EF Core
   - Relacionamentos com Paciente/Sessao

---

## 🎉 CONCLUSÃO FINAL

### O QUE SABEMOS:
- ✅ Infraestrutura BD para `MedicinaBioenergetica` **EXISTE**
- ✅ Seeds e consentimentos **CRIADOS**
- ✅ Sistema estável e funcional (0 errors, 24 warnings AForge)

### O QUE NÃO SABEMOS:
- ❌ Requisitos específicos Inergetix Core
- ❌ Estrutura de dados necessária
- ❌ UI/UX esperado
- ❌ Nível de integração com hardware

### RECOMENDAÇÃO:
**Agendar sessão de planeamento com utilizador** → Criar REQUISITOS claros → Implementar com confiança.

Implementar "às cegas" sem requisitos = Alto risco de refactoring posterior.

---

**Próximo Passo Imediato**: Responder às 4 perguntas acima ⬆️

---

*Investigação completa por: GitHub Copilot*
*Data: 12/10/2025 | Tempo: 15 minutos*
*Status Build: 0 Errors, 24 Warnings (AForge compat)*
