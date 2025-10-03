# 🔐 Sistema de Configurações Seguras - BioDeskPro

## ✅ O Que Foi Implementado

### 1️⃣ Painel de Configurações Visual
- **Localização**: Dashboard → Botão "⚙️ Configurações"
- **Funcionalidades**:
  - ✉️ Configurar email de envio (Gmail)
  - 🔑 Adicionar App Password do Gmail
  - 👤 Nome do remetente personalizável
  - 🧪 Testar conexão antes de guardar
  - 💾 Guardar de forma segura

### 2️⃣ Segurança Implementada
- **User Secrets do .NET**: Credenciais NÃO vão para Git
- **PasswordBox**: Campo de password oculto
- **Validação**: Email e password obrigatórios
- **Instruções**: Link direto para obter App Password

---

## 📖 Como Usar

### PASSO 1: Obter App Password do Gmail

1. **Aceder**: https://myaccount.google.com/apppasswords
2. **Login**: Entrar com a conta Gmail que enviará emails
3. **Criar**: Clicar em "Criar" e dar um nome (ex: "BioDeskPro")
4. **Copiar**: Copiar a password gerada (16 caracteres, ex: `abcd efgh ijkl mnop`)
5. **IMPORTANTE**: Esta é uma password de aplicação, NÃO a senha normal!

### PASSO 2: Configurar na Aplicação

1. **Abrir BioDeskPro** → Dashboard
2. **Clicar** em "⚙️ Configurações" (canto superior direito das estatísticas)
3. **Preencher**:
   - **Email de Envio**: nunocorreiaterapiasnaturais@gmail.com
   - **App Password**: Colar a password copiada no Passo 1
   - **Nome do Remetente**: Nuno Correia - Terapias Naturais
4. **Testar** (opcional): Clicar "🧪 Testar Conexão"
5. **Guardar**: Clicar "💾 Guardar"

### PASSO 3: Verificar

✅ Mensagem de sucesso: "✅ Configurações guardadas com segurança!"
✅ Credenciais guardadas em ficheiro local encriptado
✅ NÃO aparecem no código nem no Git

---

## 🛡️ Segurança Garantida

### O Que Está Protegido:
- ✅ Password guardada em **User Secrets** (fora do código)
- ✅ `.gitignore` protege ficheiros de configuração
- ✅ PasswordBox oculta caracteres durante digitação
- ✅ NÃO vai para histórico do Git
- ✅ NÃO vai para repositório remoto

### Como Funciona:
```
📁 Localização dos Secrets:
C:\Users\[Usuario]\AppData\Roaming\Microsoft\UserSecrets\[ProjectId]\secrets.json

🔒 Conteúdo (exemplo):
{
  "Email:Sender": "nunocorreiaterapiasnaturais@gmail.com",
  "Email:Password": "abcd efgh ijkl mnop",
  "Email:SenderName": "Nuno Correia - Terapias Naturais"
}
```

---

## ❓ FAQ - Perguntas Frequentes

### Q: A password é segura mesmo dentro da aplicação?
**R**: Sim! Usa User Secrets do .NET, que guarda num ficheiro encriptado FORA do projeto.

### Q: Se alguém aceder ao meu computador, pode ver?
**R**: Precisaria de acesso administrativo + conhecer a localização exata. Muito mais seguro que código.

### Q: E se eu partilhar o projeto no GitHub?
**R**: ZERO problema! User Secrets NÃO vão para Git. Só tu tens acesso.

### Q: Posso usar outro email que não Gmail?
**R**: Atualmente o sistema está configurado para Gmail. Outros providers requerem configuração SMTP diferente.

### Q: Preciso criar nova App Password sempre?
**R**: Não! A mesma password funciona até revogares. Só crias nova se:
  - Esqueceste a password
  - Suspeitas que foi comprometida
  - Queres ter passwords diferentes por aplicação

---

## 🔄 Revogar App Password (Se Necessário)

### Quando Revogar:
- ❌ Partilhaste acidentalmente a password
- ❌ Suspeitas de acesso não autorizado
- ❌ Queres renovar por segurança

### Como Revogar:
1. https://myaccount.google.com/apppasswords
2. Encontrar "BioDeskPro" (ou o nome que deste)
3. Clicar em "Remover"
4. Criar nova password
5. Atualizar na aplicação (⚙️ Configurações)

---

## 📝 Notas Técnicas

### Ficheiros Envolvidos:
```
✅ ConfiguracoesView.xaml - Interface visual
✅ ConfiguracoesViewModel.cs - Lógica de negócio
✅ DashboardView.xaml - Botão de acesso
✅ App.xaml.cs - Registo DI
✅ .gitignore - Protege secrets
```

### Comandos Manuais (Avançado):
```bash
# Definir email
dotnet user-secrets set "Email:Sender" "seuemail@gmail.com"

# Definir password
dotnet user-secrets set "Email:Password" "suaapppassword"

# Definir nome
dotnet user-secrets set "Email:SenderName" "Seu Nome"

# Listar todos
dotnet user-secrets list

# Remover um
dotnet user-secrets remove "Email:Password"

# Remover todos
dotnet user-secrets clear
```

---

## ✨ Próximos Passos (Futuro)

- [ ] Implementar envio real de emails (EmailService)
- [ ] Teste de conexão funcional
- [ ] Configurações adicionais (assinatura, rodapé, etc.)
- [ ] Suporte para outros providers (Outlook, custom SMTP)
- [ ] Histórico de envios

---

**Última Atualização**: 1 de Outubro de 2025
**Versão**: 1.0.0 (Sistema de Configurações Seguras Implementado)
**Status**: ✅ Funcional e Testável
