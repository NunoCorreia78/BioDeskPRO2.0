# 🚀 Sistema de Templates PDF - Guia Completo de Implementação

**Data:** 07/10/2025  
**Status:** ✅ IMPLEMENTADO (Backend + ViewModel)  
**Próximo:** UI Integration

---

## 📊 Resumo Executivo

Foi implementado um **sistema completo de gestão de templates PDF** para o BioDeskPro2, permitindo:

1. ✅ **Envio automático** de materiais educativos/terapêuticos para pacientes via e-mail
2. ✅ **Cópia de templates** para a pasta pessoal de cada paciente
3. ✅ **Anexação de templates** aos e-mails personalizados
4. ✅ **Categorização e metadados** (tamanho, data criação, descrição)
5. ✅ **Integração total** com EmailService e sistema de Comunicações

---

## 🏗️ Arquitetura Implementada

### Camadas

```
┌─────────────────────────────────────┐
│  ComunicacaoUserControl.xaml (UI)   │  ← PRÓXIMO PASSO
├─────────────────────────────────────┤
│  ComunicacaoViewModel               │  ✅ COMPLETO
│  - CarregarTemplatesAsync()         │
│  - EnviarTemplateAsync()            │
│  - CopiarTemplateParaPacienteAsync()│
│  - AnexarTemplate()                 │
├─────────────────────────────────────┤
│  ITemplateService / TemplateService │  ✅ COMPLETO
│  - ListarTemplatesAsync()           │
│  - EnviarTemplateParaPacienteAsync()│
│  - CopiarTemplateParaPacienteAsync()│
├─────────────────────────────────────┤
│  IEmailService (já existente)       │  ✅ INTEGRADO
├─────────────────────────────────────┤
│  BioDeskDbContext (Comunicacoes)    │  ✅ INTEGRADO
└─────────────────────────────────────┘
```

---

## 📁 Ficheiros Criados/Modificados

### ✅ Novos Ficheiros

1. **`CONFIGURACAO_SMTP_GMAIL.md`**
   - Guia completo de configuração de User Secrets
   - Troubleshooting de erros SMTP comuns
   - Instruções para obter App Password do Gmail

2. **`Templates/README.md`**
   - Catálogo de templates disponíveis
   - Instruções para criar novos templates
   - Exemplos de conteúdo por categoria

3. **`Templates/Exercicios_Escoliose.md`**
   - Template placeholder com estrutura sugerida
   - Lista de exercícios terapêuticos
   - A substituir por PDF real

4. **`Templates/Plano_Alimentar_Cardiaco.md`**
   - Template placeholder para dieta cardiovascular
   - Menu semanal exemplo
   - Alimentos a incluir/evitar

5. **`src/BioDesk.Services/Templates/ITemplateService.cs`**
   - Interface do serviço
   - Métodos: Listar, Enviar, Copiar, Verificar
   - Classe TemplateInfo com metadados

6. **`src/BioDesk.Services/Templates/TemplateService.cs`**
   - Implementação completa
   - Integração com EmailService
   - Geração automática de mensagens HTML
   - Gravação em base de dados

### ✅ Ficheiros Modificados

1. **`src/BioDesk.App/App.xaml.cs`**
   - Linha 256: Registado `ITemplateService` no DI container
   ```csharp
   services.AddScoped<Services.Templates.ITemplateService, Services.Templates.TemplateService>();
   ```

2. **`src/BioDesk.ViewModels/Abas/ComunicacaoViewModel.cs`**
   - Adicionado `using BioDesk.Services.Templates;`
   - Injetado `ITemplateService` no construtor
   - Adicionadas propriedades:
     - `TemplatesDisponiveis` (ObservableCollection)
     - `TemplateSelecionadoInfo`
     - `CarregandoTemplates`
   - Adicionados comandos (RelayCommand):
     - `CarregarTemplatesAsync`
     - `EnviarTemplateAsync`
     - `CopiarTemplateParaPacienteAsync`
     - `AnexarTemplate`

---

## 🎯 Funcionalidades Implementadas

### 1. Listar Templates Disponíveis

```csharp
var templates = await _templateService.ListarTemplatesAsync();
// Retorna: List<TemplateInfo> com:
// - Nome: "Exercicios_Escoliose.pdf"
// - NomeAmigavel: "Exercícios Escoliose"
// - Categoria: "Exercícios"
// - TamanhoBytes: 1234567
// - TamanhoFormatado: "1.2 MB"
// - DataCriacao: DateTime
// - Descricao: "Exercícios terapêuticos para..."
```

**Lógica de Categorização:**
- Nome começa com `Exercicios_` → Categoria "Exercícios"
- Nome contém `Dieta|Plano|Alimentar` → Categoria "Nutrição"
- Nome contém `Prescricao` → Categoria "Prescrições"
- Nome contém `Consentimento` → Categoria "Consentimentos"
- Nome contém `Relatorio` → Categoria "Relatórios"
- Outros → Categoria "Geral"

---

### 2. Enviar Template por E-mail (Direto)

```csharp
bool sucesso = await _templateService.EnviarTemplateParaPacienteAsync(
    pacienteId: 1,
    templateNome: "Exercicios_Escoliose.pdf",
    emailDestinatario: null,  // usa email do paciente.Contacto
    assunto: null,            // assunto automático: "Informação Terapêutica - Exercícios Escoliose"
    mensagem: null            // mensagem HTML formatada automática
);
```

**O que acontece:**
1. Valida paciente (existe? tem e-mail?)
2. Valida template (existe no disco?)
3. Gera mensagem HTML personalizada com:
   - Nome do paciente
   - Nome do template
   - Logo/assinatura do terapeuta
4. Chama `IEmailService.EnviarAsync()` com anexo
5. Grava na tabela `Comunicacoes` com status "Enviado"
6. Grava na tabela `AnexoComunicacao` (relação 1-N)

**Mensagem HTML gerada:**
```html
<html>
<body style='font-family: Arial; color: #3F4A3D;'>
    <div style='background-color: #F7F9F6; border: 2px solid #E3E9DE;'>
        <h2 style='color: #9CAF97;'>🌿 Nuno Correia - Terapias Naturais</h2>
        <p>Olá <strong>João Silva Santos</strong>,</p>
        <p>Conforme conversado na consulta, segue em anexo o documento:</p>
        <div style='background: #FCFDFB; border-left: 4px solid #9CAF97;'>
            <strong>📄 Exercícios Escoliose</strong>
        </div>
        <p>Este material foi preparado especialmente para si...</p>
        <hr/>
        <p>
            <strong>Nuno Correia</strong><br/>
            Naturopatia • Osteopatia • Medicina Bioenergética<br/>
            📧 nunocorreiaterapiasnaturais@gmail.com<br/>
            📞 +351 964 860 387<br/>
            🌿 <em>Cuidar de si, naturalmente</em>
        </p>
    </div>
</body>
</html>
```

---

### 3. Copiar Template para Pasta do Paciente

```csharp
string caminhoDestino = await _templateService.CopiarTemplateParaPacienteAsync(
    pacienteId: 1,
    templateNome: "Plano_Alimentar_Cardiaco.pdf"
);
// Retorna: "Pacientes/Joao_Silva_Santos/Documentos/20251007_153045_Plano_Alimentar_Cardiaco.pdf"
```

**O que acontece:**
1. Valida paciente
2. Cria pasta `Pacientes/{NomeCompleto}/Documentos/` (se não existir)
3. Copia template com prefixo de timestamp: `YYYYMMDD_HHmmss_NomeOriginal.pdf`
4. Retorna caminho completo do ficheiro copiado

**Vantagens:**
- ✅ Paciente tem cópia permanente no seu histórico
- ✅ Ficheiro não é apagado se template original mudar
- ✅ Timestamp evita conflitos de nomes

---

### 4. Anexar Template a E-mail Personalizado

```csharp
_templateService.AnexarTemplate(templateInfo);
// Adiciona caminho do template à lista Anexos do ViewModel
// Utilizador pode depois editar assunto/corpo do e-mail antes de enviar
```

**Workflow:**
1. Utilizador seleciona template na lista
2. Clica "📎 Anexar ao E-mail"
3. Template é adicionado à lista `Anexos`
4. Utilizador pode escrever mensagem personalizada
5. Clica "📤 Enviar Email" (usa comando existente `EnviarEmailAsync`)

---

## 🔧 Integração com EmailService

O `TemplateService` **não duplica lógica** de envio de e-mail. Em vez disso:

```csharp
// TemplateService.EnviarTemplateParaPacienteAsync()
var emailMessage = new EmailMessage
{
    To = emailFinal,
    ToName = paciente.NomeCompleto,
    Subject = assuntoFinal,
    Body = mensagemFinal,
    IsHtml = true,
    Attachments = new List<string> { caminhoTemplate } // ← Template como anexo
};

var resultado = await _emailService.EnviarAsync(emailMessage);
```

**Benefícios:**
- ✅ Reutiliza toda a lógica de retry automático
- ✅ Reutiliza sistema de fila offline
- ✅ Reutiliza logging e error handling
- ✅ Zero código duplicado

---

## 📊 Gravação Automática na Base de Dados

Quando template é enviado, sistema grava automaticamente:

**Tabela `Comunicacoes`:**
```sql
INSERT INTO Comunicacoes (
    PacienteId, Tipo, Destinatario, Assunto, Corpo,
    DataCriacao, IsEnviado, Status, DataEnvio
) VALUES (
    1, 'Email', 'joao@example.com', 'Informação Terapêutica - Exercícios Escoliose',
    '<html>...</html>', '2025-10-07 15:30:45', 1, 'Enviado', '2025-10-07 15:30:47'
);
```

**Tabela `AnexoComunicacao`:**
```sql
INSERT INTO AnexoComunicacao (
    ComunicacaoId, CaminhoArquivo, NomeArquivo, TamanhoBytes, DataCriacao
) VALUES (
    123, 'C:\BioDeskPro2\Templates\Exercicios_Escoliose.pdf',
    'Exercicios_Escoliose.pdf', 1234567, '2025-10-07 15:30:45'
);
```

**Resultado:**
- ✅ Histórico completo na aba "Comunicação & Seguimento"
- ✅ Rastreabilidade (quem recebeu, quando, qual template)
- ✅ Estatísticas (templates mais enviados, etc.)

---

## 🎨 Próximo Passo: UI Integration

### Componentes UI Necessários

**1. Secção de Templates no ComunicacaoUserControl.xaml**

```xaml
<!-- Novo Expander: Templates PDF -->
<Expander Header="📚 Templates PDF" IsExpanded="False" Margin="0,10,0,0">
    <StackPanel>
        <!-- Botão Carregar Templates -->
        <Button Command="{Binding CarregarTemplatesCommand}"
                Background="#9CAF97" Foreground="White"
                Margin="0,5,0,10">
            <StackPanel Orientation="Horizontal">
                <TextBlock Text="🔄" Margin="0,0,5,0"/>
                <TextBlock Text="Carregar Templates"/>
            </StackPanel>
        </Button>

        <!-- ListBox com Templates -->
        <ListBox ItemsSource="{Binding TemplatesDisponiveis}"
                 SelectedItem="{Binding TemplateSelecionadoInfo}"
                 MaxHeight="300">
            <ListBox.ItemTemplate>
                <DataTemplate>
                    <Grid Margin="5">
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <!-- Informação do Template -->
                        <StackPanel Grid.Column="0">
                            <TextBlock Text="{Binding NomeAmigavel}" FontWeight="Bold"/>
                            <TextBlock Text="{Binding Categoria}" Foreground="#5A6558" FontSize="10"/>
                            <TextBlock Text="{Binding Descricao}" TextWrapping="Wrap" FontSize="11"/>
                            <TextBlock Text="{Binding TamanhoFormatado}" Foreground="#5A6558" FontSize="10"/>
                        </StackPanel>

                        <!-- Botões de Ação -->
                        <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                            <!-- Enviar Direto -->
                            <Button Command="{Binding DataContext.EnviarTemplateCommand, RelativeSource={RelativeSource AncestorType=UserControl}}"
                                    CommandParameter="{Binding}"
                                    Background="#9CAF97" Foreground="White"
                                    ToolTip="Enviar template diretamente"
                                    Margin="5,0">
                                <TextBlock Text="📤"/>
                            </Button>

                            <!-- Anexar ao E-mail -->
                            <Button Command="{Binding DataContext.AnexarTemplateCommand, RelativeSource={RelativeSource AncestorType=UserControl}}"
                                    CommandParameter="{Binding}"
                                    Background="#FFB74D" Foreground="White"
                                    ToolTip="Anexar ao e-mail atual"
                                    Margin="5,0">
                                <TextBlock Text="📎"/>
                            </Button>

                            <!-- Copiar para Pasta -->
                            <Button Command="{Binding DataContext.CopiarTemplateParaPacienteCommand, RelativeSource={RelativeSource AncestorType=UserControl}}"
                                    CommandParameter="{Binding}"
                                    Background="#64B5F6" Foreground="White"
                                    ToolTip="Copiar para documentos do paciente"
                                    Margin="5,0">
                                <TextBlock Text="📋"/>
                            </Button>
                        </StackPanel>
                    </Grid>
                </DataTemplate>
            </ListBox.ItemTemplate>
        </ListBox>

        <!-- Loading Indicator -->
        <TextBlock Text="A carregar templates..."
                   Visibility="{Binding CarregandoTemplates, Converter={StaticResource BoolToVisibilityConverter}}"
                   HorizontalAlignment="Center"
                   Margin="10"/>
    </StackPanel>
</Expander>
```

---

## 🧪 Testes Manuais Recomendados

### Teste 1: Listar Templates
1. Abrir aplicação → Ficha de paciente → Aba "Comunicação"
2. Clicar "🔄 Carregar Templates"
3. **Esperado:** Lista vazia (ainda não há PDFs reais)
4. Adicionar ficheiro `Teste.pdf` em `Templates/`
5. Clicar novamente "🔄 Carregar Templates"
6. **Esperado:** Lista mostra "Teste.pdf" com metadados

### Teste 2: Enviar Template (Direto)
1. Configurar User Secrets SMTP (ver CONFIGURACAO_SMTP_GMAIL.md)
2. Criar `Templates/Teste.pdf` (qualquer PDF)
3. Abrir paciente com e-mail válido
4. Carregar templates → Selecionar "Teste.pdf"
5. Clicar "📤 Enviar"
6. **Esperado:**
   - ✅ Mensagem "Template enviado com sucesso!"
   - ✅ E-mail chega na caixa do paciente com PDF anexo
   - ✅ Novo registo no histórico de comunicações

### Teste 3: Copiar Template
1. Carregar templates → Selecionar "Teste.pdf"
2. Clicar "📋 Copiar para Pasta"
3. **Esperado:**
   - ✅ Mensagem "Template copiado para: 20251007_..."
   - ✅ Ficheiro aparece na secção "Documentos do Paciente"
   - ✅ Caminho: `Pacientes/{NomeCompleto}/Documentos/`

### Teste 4: Anexar Template
1. Carregar templates → Selecionar "Teste.pdf"
2. Clicar "📎 Anexar ao E-mail"
3. Escrever assunto e corpo personalizados
4. Clicar "📤 Enviar Email" (botão normal)
5. **Esperado:**
   - ✅ E-mail enviado com template + mensagem personalizada
   - ✅ Template aparece como anexo

---

## 📝 Criação de Templates PDF Reais

### Ferramentas Recomendadas

1. **Canva** (https://canva.com)
   - Templates prontos de "Health Guide", "Fitness Plan"
   - Fácil de usar, sem conhecimentos de design
   - Exportar como PDF alta qualidade

2. **Microsoft Word**
   - Criar documento A4
   - Inserir imagens/ilustrações
   - Guardar como PDF

3. **Google Docs**
   - Criar online
   - Colaboração em tempo real
   - Ficheiro → Transferir → PDF

### Estrutura Recomendada

```
Cabeçalho (em todas as páginas):
  🌿 Nuno Correia - Terapias Naturais
  Naturopatia • Osteopatia • Medicina Bioenergética

Corpo:
  - Margens: 2.5cm
  - Fonte: Arial ou Calibri, 11-12pt
  - Títulos: 14-16pt, cor #9CAF97
  - Espaçamento: 1.5 linhas

Rodapé:
  📧 nunocorreiaterapiasnaturais@gmail.com | 📞 +351 964 860 387
  🌿 Cuidar de si, naturalmente
```

### Passos Rápidos (Canva)

1. Aceder a https://canva.com
2. Criar → Design Personalizado → A4 (210 x 297 mm)
3. Procurar template: "Health Guide" ou "Fitness Plan"
4. Personalizar:
   - Substituir logo
   - Alterar cores para #9CAF97 (verde pastel)
   - Adicionar conteúdo terapêutico
5. Transferir → PDF Print → Alta qualidade
6. Guardar como `Exercicios_Escoliose.pdf` em `Templates/`

---

## 🚀 Roadmap Futuro

### Fase 2: UI Avançada
- [ ] Preview de templates (mostrar PDF inline)
- [ ] Filtros por categoria
- [ ] Pesquisa de templates
- [ ] Estatísticas de uso (templates mais enviados)

### Fase 3: Personalização
- [ ] Campos variáveis: `{NomePaciente}`, `{DataConsulta}`
- [ ] Editor visual de templates
- [ ] Versionamento de templates

### Fase 4: Analytics
- [ ] Taxa de abertura de e-mails com templates
- [ ] Templates mais eficazes (feedback pacientes)
- [ ] Relatórios mensais

---

## 📞 Suporte

Dúvidas sobre implementação ou criação de templates?

**GitHub Copilot Agent**  
**Versão BioDeskPro2:** v1.0  
**Data:** 07/10/2025

---

**✅ Sistema pronto para uso assim que PDFs reais forem adicionados à pasta `Templates/`!**
