# ✅ Checklist: Testar Sistema de Envio de Emails

## 📋 Pré-Requisitos

- [ ] **Ler primeiro**: `RESUMO_CORRECAO_EMAILS_PT.md` (instruções completas)
- [ ] **Verificar credenciais SMTP** em `appsettings.json` ou User Secrets:
  - [ ] Email:Sender configurado
  - [ ] Email:Password configurado (App Password, 16 caracteres)
  - [ ] Email:FromEmail configurado
  - [ ] Email:FromName configurado

**Se não tiver credenciais**: Criar App Password em https://myaccount.google.com/apppasswords

---

## 🔧 Passo 1: Compilar e Executar

```powershell
dotnet clean
dotnet restore
dotnet build
dotnet run --project src/BioDesk.App
```

- [ ] Aplicação arrancou sem erros
- [ ] Console mostra: `✅ ========== EMAIL QUEUE PROCESSOR ATIVO ==========`

**Se não aparecer** → Reportar! EmailQueueProcessor não está a funcionar.

---

## 🎨 Passo 2: Adicionar Botão de Teste (OPCIONAL mas RECOMENDADO)

**Ficheiro**: `src/BioDesk.App/Views/Abas/ComunicacaoUserControl.xaml`

Adicionar antes da tag de fecho `</StackPanel>` ou `</Grid>`:

```xml
<!-- BOTÃO TEMPORÁRIO - REMOVER APÓS DEBUG -->
<Button Content="🔧 Processar Fila (DEBUG)" 
        Command="{Binding ProcessarFilaManualmenteCommand}"
        Background="#FFA500"
        Foreground="White"
        Padding="10,5"
        Margin="10,0,0,0"
        ToolTip="Força processamento imediato dos emails agendados"/>
```

- [ ] Botão adicionado
- [ ] Recompilado: `dotnet build`
- [ ] Botão aparece na interface

---

## 📧 Passo 3: Enviar Email de Teste

1. [ ] Abrir ficha de um paciente
2. [ ] Ir para aba **"Comunicação"** (última aba)
3. [ ] Preencher formulário:
   - [ ] **Destinatário**: Seu email (ex: `teste@gmail.com`)
   - [ ] **Assunto**: `Teste de envio`
   - [ ] **Corpo**: `Mensagem de teste - ignorar`
4. [ ] Clicar **"Enviar Email"**

---

## 🔍 Passo 4: Verificar Logs IMEDIATAMENTE

### Console (janela preta)

Procurar por estas linhas:

#### Cenário A: Email Enviado ✅
```
📧 [EnviarViaSMTP] Iniciando envio para teste@gmail.com
✅ [EnviarViaSMTP] Email enviado com SUCESSO!
```
- [ ] Email enviado com sucesso
- [ ] Verificar caixa de entrada do destinatário
- [ ] ✅ **SISTEMA OK!**

#### Cenário B: Credenciais Inválidas ❌
```
❌ [EnviarViaSMTP] SMTP Exception: Authentication failed
```
OU
```
❌ [EnviarViaSMTP] SMTP Exception: Mailbox Unavailable
```
- [ ] Erro SMTP encontrado
- [ ] Copiar mensagem de erro completa
- [ ] **AÇÃO**: Verificar credenciais em `appsettings.json`

#### Cenário C: Email Agendado ⏰
```
📝 [EnviarEmail] Criando comunicação na BD:
   Status: Agendado, IsEnviado: False
   TentativasEnvio: 1, ProximaTentativa: HH:MM:SS
```
- [ ] Email foi agendado para retry
- [ ] Anotar hora de ProximaTentativa: __:__:__

---

## 🤖 Passo 5: Testar Processamento Automático

### Opção A: Aguardar (2 minutos)
- [ ] Aguardar 2 minutos desde o envio
- [ ] Procurar nos logs: `🔄 [EmailQueueProcessor] EXECUTANDO AGORA`

### Opção B: Botão de Teste (RECOMENDADO)
- [ ] Clicar no botão **"🔧 Processar Fila (DEBUG)"**
- [ ] Ver logs instantaneamente

---

## 📊 Passo 6: Interpretar Logs de Processamento

### Sucesso ✅
```
🔍 [ProcessarFila] TOTAL de emails na BD: 1
📬 [ProcessarFila] Encontrei 1 mensagens na fila
📧 [ProcessarFila] Tentando enviar Email ID 123...
✅ [ProcessarFila] SMTP OK!
✅ VERIFICAÇÃO BD: Status=Enviado
```
- [ ] Email foi processado e enviado
- [ ] ✅ **SISTEMA FUNCIONA PERFEITAMENTE!**

### Email Continua Agendado ❌
```
🔍 [ProcessarFila] TOTAL de emails na BD: 1
📊 [ProcessarFila] Filtros:
   ProximaTentativa<=Now: 0 emails  ← PROBLEMA!
```
- [ ] ProximaTentativa ainda no futuro
- [ ] **AÇÃO**: Aguardar mais tempo OU clicar botão novamente

### SMTP Falha ❌
```
❌ [ProcessarFila] ERRO ao enviar Email ID 123: Authentication failed
   Tentativa 2/3. Próximo retry: HH:MM:SS
```
- [ ] SMTP falha consistentemente
- [ ] **AÇÃO**: Verificar credenciais + App Password

### EmailQueueProcessor OFF ❌
```
(Nenhuma linha com "EmailQueueProcessor" após 1 minuto)
```
- [ ] Robô não está a executar
- [ ] **AÇÃO URGENTE**: Reportar com logs completos!

---

## 📝 Passo 7: Recolher Informações para Reportar

- [ ] **Copiar logs do console** (TUDO desde o arranque)
- [ ] **Print screen** do histórico de comunicações
- [ ] **Identificar cenário**: A, B, C ou D (acima)
- [ ] **Verificar ficheiro de log**: `Logs/biodesk-{data}.log`

---

## 📤 Passo 8: Reportar Resultados

**Formato**:
```
CENÁRIO: (A, B, C ou D)

CREDENCIAIS CONFIGURADAS: Sim/Não

LOGS DO CONSOLE:
[copiar tudo aqui desde "🚀 EmailQueueProcessor iniciado..."]

OBSERVAÇÕES:
[ex: "Email ficou agendado por 2 minutos e depois enviou OK"]
```

**Anexar**:
- [ ] Print screen do histórico de comunicações
- [ ] Ficheiro `Logs/biodesk-{data}.log` (se muito grande, zip)

---

## ✅ Checklist Final

- [ ] Lido: `RESUMO_CORRECAO_EMAILS_PT.md`
- [ ] Credenciais SMTP verificadas
- [ ] Aplicação executada com sucesso
- [ ] Botão de teste adicionado (opcional)
- [ ] Email de teste enviado
- [ ] Logs verificados imediatamente
- [ ] Processamento automático testado
- [ ] Logs completos recolhidos
- [ ] Cenário identificado
- [ ] Resultados reportados

---

## 🎯 Próximos Passos (Após Reportar)

Com os logs e informações recolhidas, será possível:

1. Identificar a **causa exata** do problema
2. Implementar a **correção específica**
3. Testar a correção
4. Remover botão de debug (opcional)
5. ✅ Sistema de emails a funcionar 100%!

---

**Dúvidas?** Consultar `RESUMO_CORRECAO_EMAILS_PT.md` para explicações detalhadas!
