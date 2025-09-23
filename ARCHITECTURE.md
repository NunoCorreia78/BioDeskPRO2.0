# BioDesk PRO 2.0 — ARCHITECTURE.md
*(Português Europeu)*

## 1) Objetivo
Este documento define a **arquitetura**, o **contrato da UI** e as **regras imutáveis** do BioDesk PRO 2.0 (Windows Desktop), para que qualquer alteração de código respeite o desenho clínico e evite erros, duplicações e inconsistências.

## 2) Plataforma & Padrões
- **Windows Desktop:** WPF no .NET 8
- **Arquitetura:** MVVM + Injeção de Dependências (`Microsoft.Extensions.DependencyInjection`)
- **BD local:** SQLite + EF Core (ACID, `PRAGMA foreign_keys=ON`, `journal_mode=WAL`)
- **Offline-first:** tudo grava local; ações de rede vão para **Outbox**
- **PDFs:** uma única biblioteca (ex.: QuestPDF/PDFsharp) para todos os relatórios
- **Email:** MailKit (TLS), **Outbox** com retry/backoff
- **Logs:** estruturados, com **rotação** e níveis (Trace/Debug/Info/Warn/Error/Fatal)

## 3) Contrato da UI (Imutáveis)
- **Sem barra lateral fixa**. **Dashboard** minimalista no arranque.
- Todas as ações clínicas associadas a **Paciente + Encontro**. **Nada** fica “solto”.
- **Abas no topo** na Ficha: Visão Geral | Dados Biográficos | Histórico | Declaração & Consentimentos | Iridologia | Medicina Quântica | Documentos | Mensagens & Prescrições | Conhecimento.
- **IsDirty global**: ao sair/trocar de aba/fechar com alterações → **Guardar / Sair sem guardar / Cancelar**.
- **Paciente Ativo Obrigatório** para: Capturar Íris, Sessão Quântica, Prescrição, Enviar Mensagem.
- **Design System**: cinzas neutros + acento verde-esmeralda; **cards/caixas**; tipografia consistente; foco em **fluidez** e **clareza**.
- **Performance UI:** <100ms interações comuns; listas com **virtualização**; thumbs para imagens.

## 4) Serviços de Infra (contratos)
- `IPacienteContext` → `PacienteAtivo`, `EncontroAtivo`, Set/Reset.
- `IChangeTracker` → IsDirty global; subscrição por aba.
- `INavigationService` → navegação com **guard** (bloqueia se IsDirty).
- `IEmailOutboxService` → enfileirar/envio com retry/backoff.
- `IStorageService` → paths relativos; geração de **thumbnails**; export PDFs.
- `ICameraService` → captura/import de Íris (Demo/Real).
- `IQuantumDevice` + `IQuantumProtocolRepository` → sessões Quânticas (Demo/Real).
- `IKnowledgeEngine` → sugestões contextuais + **inserção de snippet** em Prescrição.

> **Regra:** todas as interfaces têm implementação **Demo** para UAT sem hardware/BD real.

## 5) Ecrãs & Fluxos (resumo operativo)
### 5.1 Dashboard
- Pesquisa global; **Pacientes Recentes**; **Estado do Sistema** (rede, Outbox, câmara, quântico); **Ações Rápidas**.
- Ações rápidas abrem modal “Escolher/Cria paciente” se não houver contexto.

### 5.2 Ficha do Paciente (Layout A)
**Cabeçalho:** Nome + Idade; chips de consentimentos; botões: **Guardar** (destacado se IsDirty), **Nova Captura Íris**, **Nova Sessão Quântica**, **Prescrição**, **Enviar Mensagem**; indicador “⚠ Alterações por guardar”.

**Abas:**
- **Visão Geral** → Timeline por Encontro + Sugestões do Conhecimento.
- **Dados Biográficos** → Identificação, Contacto, Origem, Observações (validação em tempo real).
- **Histórico** → “balões/segmentos”: Queixa/Evolução, Observações, **Prescrição HTML**, anexos, **Auto-draft** e **PDF**.
- **Declaração & Consentimentos** → questionário auto-preenchido; consentimentos com **placeholders** e **assinatura digital**.
- **Iridologia** → visor com zoom/pan; **calibração**; overlay mapas; **findings** estruturados; relatório PDF; **Inserir na Prescrição** do conhecimento.
- **Medicina Quântica** → dispositivo + protocolo; **Emitir/Pausar/Parar**; log; PDF; sugestões.
- **Documentos** → listagem/exportação; pacote ZIP do Encontro.
- **Mensagens & Prescrições** → composer com templates; anexos; **Outbox**.
- **Conhecimento** → pesquisa/tags; cards com **Inserir** e **snapshot**.

## 6) Fluxos Críticos (À prova de erros)
- **Criar Paciente:** normaliza Nome (sem acentos/minúsculas/trim) + DOB; verifica **UNIQUE** e **quase-igual** (Levenshtein ≤1); opções **Abrir / Fundir / Criar**.
- **Editar & Sair:** se IsDirty → modal padrão; `Guardar` valida **UI + domínio** e grava em transação.
- **Capturar Íris:** requer Paciente (+Encontro). Cria `IrisImage` + `CalibracaoJSON` + **thumb**; findings validados; relatório PDF atómico.
- **Sessão Quântica:** `CancellationToken` em toda I/O; **Parar** responsivo; log antes de PDF.
- **Enviar Email:** sanitiza HTML; valida anexos; **Outbox** quando offline (retry/backoff).

## 7) Base de Dados (esqueleto)
- **Paciente**(Id, NomeCompleto, NomeNormalizado, DataNascimento, Email?, Telemovel?, ComoConheceu?, TagsJSON, Observacoes, CriadoEm, Ativo)  
  `UNIQUE(NomeNormalizado, DataNascimento)` · `UNIQUE(Email)` (NULL ok)
- **Encontro**(Id, PacienteId FK, DataHora, Tipo, Notas)
- **Consulta**(Id, EncontroId UNIQUE FK, PrescricaoHTML, Rascunho)
- **IrisImage**(Id, PacienteId FK, EncontroId FK, Olho, Origem, PathOriginal, PathThumb, CalibracaoJSON, Qualidade, CapturadaEm)
- **IrisFinding**(Id, IrisImageId FK, Tipo, Angulo, Raio, Severidade, Nota, TagsJSON)
- **IrisReport**(Id, PacienteId FK, EncontroId FK, PathPDF, Resumo, VersaoConhecimentoUsada, CriadoEm)
- **QuantumProtocol**(Id, Nome, FrequenciasJSON, Indicacoes, Contraindicacoes, TagsJSON)
- **QuantumSession**(Id, PacienteId FK, EncontroId FK, DeviceId?, ProtocolId FK, ParametrosJSON, Inicio, Fim, ResultadoResumo, PathPDF, Nota)
- **Device**(Id, Tipo, Modelo, Porta, SettingsJSON, Estado)
- **ConsentimentoTipo**(Id, Nome UNIQUE, Versao, TextoModelo)
- **ConsentimentoPaciente**(Id, PacienteId FK, ConsentTipoId FK, AssinadoEm, AssinaturaPath?, Observacao)  
  `UNIQUE(PacienteId, ConsentTipoId, Versao)`
- **DeclaracaoSaude**(Id, PacienteId UNIQUE FK, RespostasJSON, AssinadoEm, Versao)
- **Documento**(Id, PacienteId FK, EncontroId?, Tipo, Path, CriadoEm, MetaJSON)
- **OutboxEmail**(Id, PacienteId FK, Assunto, CorpoHTML, AnexosJSON, Estado, Tentativas, UltimoErro?, CriadoEm, EnviadoEm?)
- **KnowledgeEntry**(EntryId PK, Titulo, Categoria, TagsJSON, CorpoMD, SnippetsJSON, Contraindicacoes, Referencias, Versao)
- **KnowledgeLink**(Id, PacienteId FK, EncontroId?, Entity, EntityId, EntryId FK, Justificacao)

**FTS5:** Paciente(NomeCompleto, Email), KnowledgeEntry(Titulo, CorpoMD, Tags), Consulta(PrescricaoHTML-plain).

## 8) Dispositivos (abstração)
- `ICameraService`: `GetDevices()`, `Connect()`, `CaptureAsync()`, `ImportAsync()`
- `IQuantumDevice`: `Connect(porta)`, `EmitirAsync(params, ct)`, `Pausar()`, `Parar()`, eventos de log
- Implementações **Demo** para aprovar layout/fluxo sem hardware.

## 9) Offline & Outbox
- Indicador global de rede; se offline → **fila Outbox**.
- Worker com **backoff exponencial**; estados Pendente/Enviado/Erro; limita tentativas.

## 10) Logs, Erros e Segurança
- **DEBUG:** Binding trace ativo (lança exceção em bindings partidos).
- Captura global de exceções (UI/AppDomain/TaskScheduler) → diálogo + log.
- **DPAPI** para cifrar Outbox e dados sensíveis em repouso.
- Sanitização de HTML (prescrições/emails).

## 11) Build, CI/CD e Branches
- **Branches:** `dev` (integra), `main` (estável), `release/x.y` (pré-produção).
- **Actions:** build + testes; publicar **build de aprovação** (zip) por PR.
- **Feature flags:** esconder módulos experimentais até aprovação.

## 12) DoR / DoD & Gates
- **DoR:** wireframe aprovado; campos/botões listados; mensagens de erro definidas.
- **DoD:** UI = mockup; IsDirty/validações ativas; testes ok; UAT entregue e aprovado.
- **Gate A:** Layout Review (Playground de Ecrãs). **Gate B:** UAT por ecrã.

## 13) Design System
- `ResourceDictionary` com cores (cinzas + verde-esmeralda), espaçamentos e tipografia.
- Controlo **Card**, **Dialog**, **Button** e **HtmlEditor** reutilizáveis.
- Alinhamento e contraste verificados; atalhos de teclado consistentes.
