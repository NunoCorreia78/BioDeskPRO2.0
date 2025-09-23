# Gate B - User Acceptance Testing (UAT)

## Objetivos do Gate B

O Gate B valida que todas as funcionalidades implementadas na **Fase 1 - Fundação Sólida** funcionam conforme especificado e que o sistema está pronto para a Fase 2.

## Checklist de Testes

### ✅ 1. Inicialização da Aplicação
- [ ] **APP_START_01:** Aplicação abre no Dashboard principal
- [ ] **APP_START_02:** Base de dados SQLite é criada automaticamente se não existir
- [ ] **APP_START_03:** Dados seed são inseridos na primeira execução
- [ ] **APP_START_04:** Logo e título aparecem corretamente
- [ ] **APP_START_05:** Estado inicial: "Nenhum paciente ativo"

### ✅ 2. Interface do Dashboard
- [ ] **UI_DASH_01:** Pesquisa global está visível e funcional
- [ ] **UI_DASH_02:** 6 ações rápidas estão organizadas em grid 3x2
- [ ] **UI_DASH_03:** Pacientes recentes aparecem na lista esquerda
- [ ] **UI_DASH_04:** Estado do sistema aparece no painel direito
- [ ] **UI_DASH_05:** Design system aplicado (cores, fontes, espaçamentos)

### ✅ 3. Contexto de Paciente
- [ ] **CONTEXT_01:** Clicar paciente na lista ativa o contexto
- [ ] **CONTEXT_02:** Paciente ativo aparece no cabeçalho
- [ ] **CONTEXT_03:** Botões contextuais ficam ativos/inativos conforme contexto
- [ ] **CONTEXT_04:** Novo Paciente sempre ativo (sem contexto necessário)
- [ ] **CONTEXT_05:** Nova Consulta/Iridologia/Quântica só ativas com paciente

### ✅ 4. Sistema IsDirty Global
- [ ] **DIRTY_01:** Clicar "Teste IsDirty" ativa o estado sujo
- [ ] **DIRTY_02:** Indicador visual (●) aparece no cabeçalho
- [ ] **DIRTY_03:** Botão "Guardar" fica ativo quando IsDirty=true
- [ ] **DIRTY_04:** Tentar sair com IsDirty mostra diálogo de confirmação
- [ ] **DIRTY_05:** Opções "Guardar / Sair sem guardar / Cancelar" funcionais
- [ ] **DIRTY_06:** "Guardar" limpa o estado IsDirty

### ✅ 5. Navegação e Guards
- [ ] **NAV_01:** NavigationService protege navegação com IsDirty
- [ ] **NAV_02:** Cancelar navegação mantém no ecrã atual
- [ ] **NAV_03:** Confirmar navegação (sem guardar) limpa IsDirty
- [ ] **NAV_04:** Guardar antes de navegar persiste alterações

### ✅ 6. Base de Dados
- [ ] **DB_01:** Conexão SQLite funcional
- [ ] **DB_02:** Entidades criadas com relacionamentos corretos
- [ ] **DB_03:** Foreign keys ativas (`PRAGMA foreign_keys=ON`)
- [ ] **DB_04:** Journal mode WAL ativo para performance
- [ ] **DB_05:** Dados seed inseridos (Protocolos, Consentimentos)

### ✅ 7. Injeção de Dependências
- [ ] **DI_01:** Todos os serviços registrados corretamente
- [ ] **DI_02:** IPacienteContext funcional
- [ ] **DI_03:** IChangeTracker funcional
- [ ] **DI_04:** IDialogService funcional
- [ ] **DI_05:** INavigationService funcional

### ✅ 8. Pesquisa Global
- [ ] **SEARCH_01:** Caixa de pesquisa aceita texto
- [ ] **SEARCH_02:** Binding bidirecional funcional
- [ ] **SEARCH_03:** Interface preparada para pesquisa em tempo real

### ✅ 9. Estados Visuais
- [ ] **VISUAL_01:** Botões têm hover effect
- [ ] **VISUAL_02:** Botões disabled visualmente distintos
- [ ] **VISUAL_03:** Cards têm sombras e cantos arredondados
- [ ] **VISUAL_04:** Cores consistentes com design system
- [ ] **VISUAL_05:** Tipografia Segoe UI aplicada

### ✅ 10. Performance e Estabilidade
- [ ] **PERF_01:** App carrega em < 3 segundos
- [ ] **PERF_02:** Interface responsiva (sem travamentos)
- [ ] **PERF_03:** Mudanças de contexto instantâneas
- [ ] **PERF_04:** Sem memory leaks em testes de 30min

## Cenários de Teste Manuais

### Cenário A: Primeiro Uso
1. **Fechar** aplicação se estiver aberta
2. **Apagar** `%AppData%/BioDesk/data/biodesk.db` se existir
3. **Abrir** BioDeskPro.UI.exe
4. **Verificar:** BD criada, dados seed inseridos, dashboard carregado

### Cenário B: Fluxo IsDirty Completo
1. **Abrir** aplicação
2. **Clicar** "Teste IsDirty"
3. **Verificar:** ● aparece no cabeçalho
4. **Tentar** fechar aplicação
5. **Verificar:** Diálogo aparece
6. **Clicar** "Cancelar"
7. **Verificar:** Aplicação continua aberta
8. **Clicar** "Guardar"
9. **Verificar:** ● desaparece

### Cenário C: Gestão de Contexto
1. **Verificar:** Botões contextuais inativos
2. **Clicar** "João Silva" na lista
3. **Verificar:** Contexto ativo no cabeçalho
4. **Verificar:** Botões contextuais ativos
5. **Clicar** espaço vazio para desselecionar
6. **Verificar:** Contexto limpo

## Critérios de Aprovação

Para **Gate B ser aprovado**, todos os itens devem ser ✅:

- **100% dos testes de interface** passarem
- **100% dos testes de funcionalidade** passarem  
- **100% dos cenários manuais** executados com sucesso
- **Zero crashes** durante testing session de 30 minutos
- **Zero memory leaks** detectados
- **Performance** dentro dos limites (< 3s startup)

## Ferramentas de Teste

### Automatizados
- **Build Test:** `dotnet build --configuration Release`
- **Unit Tests:** (a implementar na Fase 2)

### Manuais
- **Tester humano** executa checklist
- **Cronómetro** para testes de performance
- **Task Manager** para verificar memory usage
- **DB Browser for SQLite** para verificar estrutura da BD

## Entregáveis do Gate B

1. **✅ Checklist preenchido** (este documento)
2. **📱 App executable** (`BioDeskPro.UI.exe`)
3. **🗃️ Base de dados SQLite** funcional
4. **📋 Relatório de testes** com resultados
5. **🐛 Bug report** (se aplicável)

## Status Atual

**Estado:** 🟡 **PRONTO PARA TESTE**
**Próximo passo:** Executar checklist completo
**Responsável:** Nuno Correia
**Prazo:** 23 de Setembro de 2025

---

## Notas do Desenvolvedor

- ✅ Todos os serviços implementados e testados
- ✅ Compilação limpa (0 warnings, 0 errors)
- ✅ Arquitectura preparada para Phase 2
- ✅ Design system consistente aplicado
- ✅ IsDirty system totalmente funcional

**Quando Gate B for aprovado → Start Phase 2: Gestão de Pacientes**