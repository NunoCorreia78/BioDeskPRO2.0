# 📧 Correção do Sistema de Envio de Emails - RESUMO EXECUTIVO

## ❌ Problema Original

**Sintomas**:
- Emails ficam com status "Agendado" indefinidamente
- Nunca são enviados automaticamente
- Quando cancelados manualmente, aparecem como "Falhados"

---

## ✅ O Que Foi Feito (Português Europeu, Linguagem Clara)

### Fase 1: Investigação Profunda do Código ✅

Auditei minuciosamente 3 componentes críticos:

1. **EmailService.cs** (170 linhas) - Serviço que envia emails via SMTP
2. **EmailQueueProcessor.cs** (65 linhas) - Robô que processa fila a cada 30 segundos
3. **ComunicacaoViewModel.cs** (1067 linhas) - Interface que cria emails na base de dados

**Descobertas**:
- ❌ Faltavam logs detalhados para perceber onde falha
- ❌ Não havia forma de testar processamento sem esperar 30 segundos
- ❌ Não era possível saber se o robô (EmailQueueProcessor) estava a funcionar
- ❌ Não havia verificação se os dados eram gravados corretamente na BD

### Fase 2: Adição de Diagnósticos Completos ✅

**1. Logs Detalhados em TODOS os Pontos Críticos**

**Antes** ❌:
```
Tentando enviar email...
Erro ao enviar
```

**Agora** ✅:
```
📧 [EnviarViaSMTP] Iniciando envio para teste@example.com
   Host: smtp.gmail.com:587, From: seu-email@gmail.com
   Anexos: 0
📤 [EnviarViaSMTP] Enviando via SMTP...
❌ [EnviarViaSMTP] SMTP Exception: Mailbox Unavailable - Email inválido
   Stack: System.Net.Mail.SmtpClient.SendMailAsync...
```

**Resultado**: Agora consegue VER EXATAMENTE o que está a falhar!

---

**2. Diagnóstico da Query SQL que Procura Emails**

O robô (EmailQueueProcessor) procura emails na BD com esta condição:
```sql
Status = 'Agendado' 
AND IsEnviado = false 
AND TentativasEnvio < 3 
AND ProximaTentativa <= AGORA
```

**Agora com logs**, consegue ver:
```
🔍 [ProcessarFila] TOTAL de emails na BD: 1
   Email ID 123: Status=Agendado, IsEnviado=False, Tentativas=1, ProximaTentativa=23:05:00
🕐 [ProcessarFila] DateTime.Now = 23:03:00
📊 [ProcessarFila] Filtros:
   !IsEnviado: 1 emails           ← Passa ✅
   Status==Agendado: 1 emails     ← Passa ✅
   TentativasEnvio<3: 1 emails    ← Passa ✅
   ProximaTentativa<=Now: 0 emails ← FALHA ❌ (ainda faltam 2 minutos!)
📬 [ProcessarFila] Encontrei 0 mensagens na fila
```

**Resultado**: Sabe QUAL filtro está a bloquear o processamento!

---

**3. Verificação de Gravação na Base de Dados**

**Antes** ❌:
```
Salvando na BD...
OK
```

**Problema**: Não sabíamos se foi mesmo gravado!

**Agora** ✅:
```
💾 [EnviarEmail] Salvando comunicação na BD...
✅ [EnviarEmail] SaveChanges executado: 1 entidade(s) afetada(s), ID=123
   ✅ VERIFICAÇÃO BD: Status=Agendado, TentativasEnvio=1, ProximaTentativa=23:05:00
```

**Resultado**: Confirmação EXPLÍCITA que foi gravado!

---

**4. Robô (EmailQueueProcessor) Mostra Se Está a Funcionar**

**Antes** ❌:
```
(silêncio... não sabíamos se estava a correr)
```

**Agora** ✅:
```
🔄 [EmailQueueProcessor] ========== CICLO INICIADO ==========
🔄 [EmailQueueProcessor] EXECUTANDO AGORA - 23:03:00
🔄 [EmailQueueProcessor] Thread ID: 7
```

**Resultado**: Confirmação a cada 30 segundos que o robô está VIVO!

---

**5. NOVO: Botão de Teste Imediato 🔧**

Adicionei um comando para **forçar o processamento IMEDIATO** da fila, sem esperar 30 segundos!

**Como usar**:
1. Adicionar botão temporário na interface (ver instruções abaixo)
2. Clicar no botão "🔧 Processar Fila (DEBUG)"
3. Ver logs instantaneamente

**Código do botão** (adicionar em `ComunicacaoUserControl.xaml`):
```xml
<Button Content="🔧 Processar Fila (DEBUG)" 
        Command="{Binding ProcessarFilaManualmenteCommand}"
        Margin="10"
        Background="#FFA500"
        Foreground="White"
        Padding="10,5"/>
```

---

## 📋 Como Testar (Passo-a-Passo SIMPLES)

### Passo 1: Verificar Credenciais SMTP

**ANTES de fazer qualquer coisa**, confirmar que tem credenciais configuradas:

1. Abrir **appsettings.json** (pasta raiz do projeto)
2. OU: Clicar direito no projeto → "Manage User Secrets"
3. Verificar se tem isto:
   ```json
   {
     "Email": {
       "Sender": "seu-email@gmail.com",
       "Password": "xxxx xxxx xxxx xxxx",
       "FromEmail": "seu-email@gmail.com",
       "FromName": "Nuno Correia - Terapias Naturais"
     }
   }
   ```

**⚠️ IMPORTANTE**: 
- `Password` deve ser uma **App Password** do Gmail (16 caracteres com espaços)
- **NÃO é a password normal do Gmail!**
- Criar aqui: https://myaccount.google.com/apppasswords

**Se não tiver credenciais**: Todos os emails irão FALHAR! Configure primeiro.

---

### Passo 2: Compilar e Executar

```powershell
# 1. Limpar
dotnet clean

# 2. Restaurar pacotes
dotnet restore

# 3. Compilar
dotnet build

# 4. Executar
dotnet run --project src/BioDesk.App
```

**Deve aparecer no console**:
```
🚀 EmailQueueProcessor iniciado. Aguardando 10s para DB inicializar...
✅ ========== EMAIL QUEUE PROCESSOR ATIVO ==========
✅ Verificando fila a cada 30 segundos...
```

**Se NÃO aparecer** → EmailQueueProcessor está OFF! ❌ Reportar!

---

### Passo 3: Adicionar Botão de Teste (OPCIONAL mas RECOMENDADO)

No ficheiro `src/BioDesk.App/Views/Abas/ComunicacaoUserControl.xaml`:

Procurar a secção de botões (perto do botão "Enviar Email") e adicionar:

```xml
<!-- BOTÃO DE TESTE - REMOVER APÓS DEBUG -->
<Button Content="🔧 Processar Fila (DEBUG)" 
        Command="{Binding ProcessarFilaManualmenteCommand}"
        Background="#FFA500"
        Foreground="White"
        Padding="10,5"
        Margin="10,0,0,0"
        ToolTip="Força o processamento imediato dos emails agendados (apenas para testes)"/>
```

**Guardar e recompilar**: `dotnet build`

---

### Passo 4: Enviar Email de Teste

1. Abrir ficha de um paciente
2. Ir para aba **"Comunicação"** (última aba)
3. Preencher:
   - **Destinatário**: `seu-email@gmail.com` (para testar)
   - **Assunto**: `Teste de envio`
   - **Corpo**: `Mensagem de teste - ignorar`
4. Clicar **"Enviar Email"**

---

### Passo 5: Verificar Logs IMEDIATAMENTE

#### Console (janela preta):
Procurar por:

**Cenário A - Email Enviado com Sucesso** ✅:
```
📧 [EnviarViaSMTP] Iniciando envio para seu-email@gmail.com
✅ [EnviarViaSMTP] Email enviado com SUCESSO!
📝 [EnviarEmail] Criando comunicação na BD:
   Status: Enviado, IsEnviado: True
```
→ **TUDO OK!** Verificar caixa de entrada.

**Cenário B - Credenciais Inválidas** ❌:
```
📧 [EnviarViaSMTP] Iniciando envio para seu-email@gmail.com
❌ [EnviarViaSMTP] SMTP Exception: Mailbox Unavailable
```
→ **PROBLEMA**: Credenciais erradas! Verificar App Password.

**Cenário C - Email Agendado** ⏰:
```
📧 [EnviarViaSMTP] Iniciando envio...
❌ [EnviarViaSMTP] SMTP Exception: ...
📝 [EnviarEmail] Criando comunicação na BD:
   Status: Agendado, IsEnviado: False
   TentativasEnvio: 1, ProximaTentativa: 23:05:00
```
→ Email falhou, foi agendado para retry em 2 minutos.

---

### Passo 6: Testar Processamento Automático

**Opção A - Aguardar 2 minutos** (tempo de retry):
- Esperar 2 minutos
- Procurar nos logs:
```
🔄 [EmailQueueProcessor] ========== CICLO INICIADO ==========
🔍 [ProcessarFila] TOTAL de emails na BD: 1
```

**Opção B - Clicar no botão de teste** (RECOMENDADO):
- Clicar em **"🔧 Processar Fila (DEBUG)"**
- Ver logs instantaneamente

---

### Passo 7: Interpretar Resultados

#### Resultado 1: Email Enviado ✅
```
✅ [ProcessarFila] SMTP OK! Atualizando status...
   ANTES: IsEnviado=False, Status=Agendado, Tentativas=1
   DEPOIS: IsEnviado=True, Status=Enviado, DataEnvio=23:05:00
✅ [ProcessarFila] SaveChangesAsync executado: 1 entidade(s) afetada(s)
✅ VERIFICAÇÃO BD: Status=Enviado
```
**CONCLUSÃO**: Sistema a funcionar perfeitamente! ✅

---

#### Resultado 2: Email Continua Agendado ❌
```
🔍 [ProcessarFila] TOTAL de emails na BD: 1
   Email ID 123: Status=Agendado, IsEnviado=False, Tentativas=1, ProximaTentativa=23:05:00
🕐 [ProcessarFila] DateTime.Now = 23:03:00
📊 [ProcessarFila] Filtros:
   ProximaTentativa<=Now: 0 emails  ← PROBLEMA!
```
**CONCLUSÃO**: Email ainda está no futuro. Aguardar mais 2 minutos OU clicar no botão novamente.

---

#### Resultado 3: SMTP Falha Sempre ❌
```
❌ [EnviarViaSMTP] SMTP Exception: Authentication failed
❌ [ProcessarFila] ERRO ao enviar Email ID 123: Authentication failed
   Tentativa 2/3. Próximo retry: 23:10:00
```
**CONCLUSÃO**: Credenciais SMTP inválidas! Configurar App Password corretamente.

---

#### Resultado 4: EmailQueueProcessor OFF ❌
```
(Nenhuma linha com "EmailQueueProcessor" no console após 1 minuto)
```
**CONCLUSÃO**: Robô não está a executar! Problema crítico no registo do serviço.

---

## 🎯 O Que Fazer com os Logs

### Se Email Enviado com Sucesso ✅
**Ação**: Nada! Sistema está OK. Testar com mais emails.

### Se Credenciais Inválidas ❌
**Ação**:
1. Ir a https://myaccount.google.com/apppasswords
2. Criar nova App Password
3. Copiar código (16 caracteres com espaços)
4. Colar em `appsettings.json` ou User Secrets
5. Reiniciar aplicação
6. Testar novamente

### Se EmailQueueProcessor OFF ❌
**Ação**: Reportar IMEDIATAMENTE com logs completos do arranque da aplicação!

### Se Emails Ficam Agendados ❌
**Ação**: 
1. Copiar TODOS os logs (console completo)
2. Fazer print screen do histórico de comunicações
3. Reportar com estas informações

---

## 📝 Resumo das Alterações (Técnico)

### Ficheiros Modificados:
1. `src/BioDesk.Services/Email/EmailService.cs` (+77 linhas)
   - Logging detalhado em EnviarViaSMTPAsync()
   - Diagnóstico completo em ProcessarFilaAsync()
   - Verificação pós-SaveChanges

2. `src/BioDesk.Services/Email/EmailQueueProcessor.cs` (+3 linhas)
   - Log de início de ciclo
   - Log de Thread ID

3. `src/BioDesk.ViewModels/Abas/ComunicacaoViewModel.cs` (+25 linhas)
   - Novo comando: ProcessarFilaManualmenteAsync()
   - Logging de criação de emails

### Ficheiros Criados:
1. `CORRECAO_ENVIO_EMAILS_DIAGNOSTICO.md` (documentação completa)
2. `RESUMO_CORRECAO_EMAILS_PT.md` (este ficheiro)

---

## ✅ Garantias

**O Que NÃO Foi Alterado** (conforme pedido):
- ✅ Histórico de comunicações → Intacto
- ✅ Sistema de anexos → Intacto
- ✅ Lógica de agendamento → Intacta
- ✅ Templates de email → Intactos

**Apenas adicionados**:
- ✅ Logs detalhados
- ✅ Verificações de estado
- ✅ Comando de teste manual

**Não há risco de**:
- ❌ Perder emails antigos
- ❌ Corromper anexos
- ❌ Alterar templates
- ❌ Quebrar funcionalidades existentes

---

## 🚀 Próximos Passos

1. ✅ **Executar testes** seguindo este guia
2. ✅ **Recolher logs** (console + ficheiro `Logs/biodesk-{data}.log`)
3. ✅ **Reportar resultados**:
   - Cenário que ocorreu (1, 2, 3 ou 4 acima)
   - Logs completos
   - Print screen do histórico
4. ✅ **Implementar correção final** baseada nos logs

---

## 📞 Como Reportar

**Formato ideal**:

```
CENÁRIO: (1, 2, 3 ou 4)

LOGS DO CONSOLE:
[copiar tudo aqui]

PRINT SCREEN:
[anexar imagem do histórico]

CREDENCIAIS CONFIGURADAS: Sim/Não
```

Com estas informações, consigo identificar a causa exata e implementar a correção definitiva!

---

**Data**: 21 de Outubro de 2025  
**Autor**: GitHub Copilot Workspace Agent  
**Estado**: ✅ Fase de Diagnóstico Completa - Aguardando Testes
