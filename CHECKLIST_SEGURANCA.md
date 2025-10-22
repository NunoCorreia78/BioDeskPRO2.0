# ✅ Checklist de Segurança - BioDeskPro2

## 🔒 Verificação de Segurança das Credenciais

Este documento serve como checklist para garantir que as credenciais da aplicação estão protegidas corretamente.

---

## Para Desenvolvedores

### ✅ Configuração Inicial

- [ ] **User Secrets configurados**
  - Execute: `cd src/BioDesk.App && dotnet user-secrets list`
  - Deve mostrar as 4 chaves: `Email:Sender`, `Email:Password`, `Email:FromEmail`, `Email:FromName`
  
- [ ] **appsettings.json NÃO contém credenciais reais**
  - Abrir: `src/BioDesk.App/appsettings.json`
  - Campo `Password` deve estar vazio: `""`
  - Campo `Sender` deve estar vazio: `""`

- [ ] **Aplicação executa corretamente**
  - Execute: `dotnet run --project src/BioDesk.App`
  - Dashboard deve abrir sem erros
  - Testar envio de email nas Configurações

### ✅ Antes de Cada Commit

- [ ] **Verificar ficheiros staged**
  - Execute: `git status`
  - Confirmar que NÃO está a commitar:
    - ❌ `secrets.json`
    - ❌ `appsettings.json` com passwords
    - ❌ `appsettings.local.json`
    - ❌ `biodesk.db` (base de dados com credenciais)

- [ ] **Verificar diff antes de commit**
  - Execute: `git diff --staged`
  - Procurar por: `password`, `senha`, credenciais, tokens
  - Se encontrar algo sensível, remover antes de commitar

- [ ] **Usar .gitignore corretamente**
  - Confirmar que `.gitignore` está atualizado
  - Ficheiros com credenciais devem estar listados

### ✅ Boas Práticas

- [ ] **NUNCA** fazer hardcode de passwords no código
- [ ] **NUNCA** commitar ficheiros com credenciais
- [ ] **NUNCA** partilhar User Secrets por email/chat
- [ ] **SEMPRE** usar User Secrets em desenvolvimento
- [ ] **SEMPRE** verificar git status antes de commit
- [ ] **SEMPRE** revisar diffs antes de push

---

## Para Utilizadores Finais

### ✅ Instalação

- [ ] **Instalar aplicação**
  - Executar o instalador BioDeskPro2
  - Verificar que a pasta de instalação tem permissões corretas

- [ ] **Configurar credenciais via interface**
  - Abrir BioDeskPro2
  - Ir para Configurações → Email
  - Preencher campos:
    - Email remetente
    - App Password do Gmail
    - Nome do remetente
  
- [ ] **Testar envio de email**
  - Clicar em "Testar Conexão"
  - Verificar que email de teste foi recebido
  - Clicar em "Gravar" se teste passou

### ✅ Segurança da Base de Dados

- [ ] **Localização da BD**
  - Verificar onde está `biodesk.db`:
    - **Debug**: Pasta do projeto `BioDeskPro2/`
    - **Release**: `C:\ProgramData\BioDeskPro2\`

- [ ] **Permissões da BD**
  - Apenas o utilizador atual deve ter acesso
  - Verificar permissões no Windows Explorer:
    - Clique direito em `biodesk.db` → Propriedades → Segurança

- [ ] **Backups regulares**
  - Fazer backup semanal de `biodesk.db`
  - Armazenar backups em local seguro/encriptado
  - Testar restauro de backup periodicamente

---

## Para Administradores de Sistema

### ✅ Servidor/Produção

- [ ] **Variáveis de ambiente configuradas** (se aplicável)
  ```powershell
  $env:Email__Sender
  $env:Email__Password
  $env:Email__FromEmail
  $env:Email__FromName
  ```

- [ ] **Permissões de ficheiros**
  - `biodesk.db`: Apenas administrador e utilizador da aplicação
  - Pastas `Documentos/`, `Backups/`: Acesso restrito

- [ ] **Auditoria de segurança**
  - Logs de acesso à base de dados
  - Monitorização de tentativas de acesso não autorizado
  - Alertas para mudanças em ficheiros críticos

### ✅ Backup e Recuperação

- [ ] **Backup automático configurado**
  - Usar script PowerShell ou Task Scheduler
  - Encriptar backups sensíveis
  - Testar restauro regularmente

- [ ] **Plano de recuperação de desastre**
  - Documentar procedimento de restauro
  - Testar procedimento pelo menos 1x por trimestre
  - Manter backups offline/offsite

---

## 🚨 Em Caso de Comprometimento de Credenciais

Se suspeitar que as credenciais foram expostas:

### Ação Imediata

1. **Revogar App Password comprometida**
   - Ir para [Google Account Security](https://myaccount.google.com/security)
   - Remover a App Password do BioDeskPro2
   
2. **Gerar nova App Password**
   - Criar nova App Password no Google
   - Atualizar User Secrets ou configuração da aplicação

3. **Verificar acessos suspeitos**
   - Verificar histórico de envio de emails
   - Procurar emails enviados não autorizados
   - Verificar logs da aplicação

4. **Notificar equipa** (se aplicável)
   - Informar outros desenvolvedores
   - Atualizar documentação de incidentes
   - Revisar processo de segurança

### Prevenção Futura

- [ ] Revisar permissões de acesso ao repositório
- [ ] Implementar code review obrigatório
- [ ] Ativar notificações de commits suspeitos
- [ ] Considerar usar vault de credenciais (Azure Key Vault, etc.)

---

## 📊 Status de Segurança do Projeto

### ✅ Implementado

- [x] User Secrets configurados no projeto
- [x] Credenciais removidas de `appsettings.json`
- [x] `.gitignore` protege ficheiros sensíveis
- [x] Documentação completa criada
- [x] Scripts de migração disponíveis
- [x] Template `appsettings.example.json` criado

### 🔄 Em Progresso

- [ ] Validação em ambiente Windows (requer teste manual)
- [ ] Teste de envio de email com User Secrets
- [ ] Verificação de compatibilidade com build/publicação

### 📋 Melhorias Futuras (Opcional)

- [ ] Integração com Azure Key Vault
- [ ] Autenticação OAuth 2.0 para Gmail (mais seguro que App Password)
- [ ] Encriptação da base de dados SQLite
- [ ] Logs de auditoria para acessos às credenciais
- [ ] Alertas automáticos para commits com credenciais

---

## 📞 Recursos e Suporte

### Documentação do Projeto
- [CONFIGURACAO_SEGURA_EMAIL.md](./CONFIGURACAO_SEGURA_EMAIL.md) - Guia completo
- [CONFIGURACAO_INICIAL.md](./CONFIGURACAO_INICIAL.md) - Setup rápido
- [README.md](./README.md) - Documentação geral

### Documentação Externa
- [.NET User Secrets](https://docs.microsoft.com/en-us/aspnet/core/security/app-secrets)
- [Google App Passwords](https://support.google.com/accounts/answer/185833)
- [OWASP Security Practices](https://owasp.org/www-project-top-ten/)

### Scripts Úteis
- `Scripts/MigrarCredenciais.ps1` - Migrar de appsettings.json para User Secrets
- `Scripts/BackupCredenciais.ps1` - Criar backup encriptado

---

**Data de Criação**: 21 de Outubro de 2025  
**Última Revisão**: 21 de Outubro de 2025  
**Versão**: 1.0

---

## ✍️ Assinatura de Verificação

Este checklist deve ser revisto:
- [ ] Por cada novo desenvolvedor ao juntar-se ao projeto
- [ ] Antes de cada release para produção
- [ ] Após qualquer incidente de segurança
- [ ] Pelo menos 1x por trimestre

**Última verificação por**: _______________  
**Data**: _______________  
**Status**: ⬜ OK | ⬜ Ação Necessária
