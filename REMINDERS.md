# BioDesk PRO 2.0 — REMINDERS.md
*(Anti-erro · Anti-duplicação · Anti-inconsistência)*

## Globais
- **Nada solto**: toda ação/gravação ligada a **Paciente + Encontro** (quando aplicável).
- **IsDirty** em todas as views editáveis → modal **Guardar / Sair sem guardar / Cancelar** em qualquer navegação.
- **Paciente Ativo obrigatório** para Íris/Quântica/Prescrição/Enviar.
- **Normalizar** (trim, minúsculas, sem acentos) antes de comparar ou gravar.
- **Transações ACID** em gravações compostas; nunca deixar dados a meio.
- **Sanitizar HTML** (prescrições/emails) → whitelist.
- **Offline-first**: Outbox com backoff; UI mostra estado; nunca bloquear a app.
- **Logs rotativos**; Binding errors gritam em DEBUG.

## Por Fase
### Fase 1 — Fundação
- Guard de navegação (IsDirty) ativo desde o 1.º protótipo.
- Paths **relativos** em /data/pacientes/{PacienteId}/…
- `PRAGMA foreign_keys=ON`, `journal_mode=WAL`.

### Fase 2 — Pacientes
- `UNIQUE(NomeNormalizado, DataNascimento)` + `UNIQUE(Email)` (NULL ok).
- Anti-duplicado = **Abrir / Fundir / Criar**; merge em **transação**.
- DOB → Idade recalculada em todas as vistas.

### Fase 3 — Histórico
- **Auto-draft** periódico; recuperar rascunho.
- Consulta + Documento PDF no **mesmo** `SaveChanges()`.
- Editor HTML não bloqueia UI (async).

### Fase 4 — Declaração & Consentimentos
- Placeholders resolvidos (Nome, DOB, Data, Profissional) **antes** de assinar.
- Após assinatura: **bloquear** texto base; só adenda.
- `UNIQUE(PacienteId, ConsentTipoId, Versao)`.

### Fase 5 — Iridologia
- Import/Captura gera **thumbnail**; valida olho E/D e qualidade.
- Calibração guardada (centro/raio/escala); relatório bloqueado a essa versão.
- Findings com enums e limites validados (ângulo 0–360; severidade 0–5).

### Fase 6 — Medicina Quântica
- `CancellationToken` em todas as operações; **Parar** sempre responsivo.
- Log linha-a-linha antes do PDF.
- Timeouts e retries com limites (Polly).

### Fase 7 — Mensagens & Prescrições
- Verificar anexos (existem? tamanho?) antes de enfileirar.
- HTML sanitizado; `From/Reply-To` configuráveis.
- DPAPI para cifrar Outbox + limpeza de temporários.

### Fase 8 — Conhecimento
- Filtrar por **contraindicações** do paciente.
- Guardar **snapshot** do snippet + `VersaoConhecimentoUsada` em PDFs.
- Hot-reload com fallback seguro (não quebrar UI ao falhar parse).

### Fase 9 — Polimento/Perf
- Virtualização em listas; thumbs 512px; IO sempre async.
- Medir operações >200ms; nunca `Task.Result` na UI.

### Fase 10 — Deploy/Docs
- Backup da BD antes de migrar; rollback seguro.
- Crash reporter com consentimento; logs rotativos.

## Por Módulo
### Dashboard
- Ações rápidas pedem paciente se não houver.
- Estado do Sistema só leitura; link para Outbox quando houver pendentes.

### Dados Biográficos
- Validações inline (email/telefone/data).
- Normalização de nome + DOB.
- `Ctrl+S` em qualquer aba.

### Histórico (Consultas)
- “Nova Consulta” cria Encontro+balão com data/hora automática.
- Prescrição HTML sanitizada; PDF anexado ao Encontro.

### Declaração & Consentimentos
- Auto-preenchimento por dados do paciente.
- Chips de estado visíveis no cabeçalho.

### Iridologia
- Overlay de mapas opcional; guardar calibração junto da imagem.
- Relatório PDF inclui imagem anotada + lista de findings.

### Medicina Quântica
- Dispositivo emulado disponível para UAT.
- Parâmetros do protocolo versionados/salvos no JSON da sessão.

### Documentos
- Export múltiplo; gerar pacote ZIP por Encontro.
- Metadados em `MetaJSON` (tipo, versão, origem).

### Mensagens & Prescrições
- Templates com placeholders; merge com Prescrição da consulta.
- Outbox expõe estados (Pendente/Enviado/Erro).

### Conhecimento
- Tags consistentes entre Findings/Consultas/KnowledgeEntry.
- Inserção em Prescrição grava snapshot (texto+versão).
