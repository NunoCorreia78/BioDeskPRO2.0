# BioDeskPRO2.0
🏥 BioDesk PRO - Sistema de Gestão Clínica Holística em .NET 8 com MVVM e SQLite

## Visão Geral

O BioDeskPRO 2.0 é um sistema profissional de gestão clínica desenvolvido especificamente para práticas de Terapia Natural e Complementar (TNC). O sistema implementa uma arquitetura robusta à prova de erros, com interface organizada em seções bem definidas e navegação intuitiva.

## Características Principais

### ✅ Implementadas na Versão Atual

- **Arquitetura Robusta**: Sistema multicamadas com separação clara de responsabilidades
- **Base de Dados Escalável**: SQLite local com possibilidade de migração futura
- **Módulo de Cadastro de Pacientes**: Completo com dados biográficos essenciais
- **Interface Intuitiva**: Organizada em "caixas" para facilitar a navegação
- **Validação de Dados**: Robusta com tratamento de erros abrangente
- **Conformidade LGPD/GDPR**: Sistema de consentimentos implementado
- **Cálculo Automático de Idade**: Baseado na data de nascimento
- **Sistema de Busca**: Pesquisa por nome, email ou telefone
- **Logs e Monitoramento**: Sistema de logging integrado

### 🚧 Em Desenvolvimento

- **Histórico Clínico**: Gestão de consultas e tratamentos
- **Módulo de Iridologia**: Análise de íris e captura de imagens
- **Módulo Quântico**: Terapias energéticas e análises vibracionais
- **Centro de Comunicação**: Envio de prescrições e orientações

## Arquitetura Técnica

### Tecnologias Utilizadas

- **.NET 8**: Framework principal
- **Entity Framework Core**: ORM para acesso à base de dados
- **SQLite**: Base de dados local (pode migrar para SQL Server/PostgreSQL)
- **Dependency Injection**: Container de injeção de dependências
- **xUnit**: Framework de testes unitários
- **Moq**: Framework para mocking em testes

### Estrutura do Projeto

```
BioDeskPRO/
├── Models/           # Entidades do domínio
├── Data/            # Contexto da base de dados
├── Services/        # Lógica de negócio
├── UI/              # Interface do utilizador
└── Program.cs       # Ponto de entrada

BioDeskPRO.Tests/    # Testes unitários e de integração
```

### Padrões Implementados

- **Repository Pattern**: Através dos serviços
- **Dependency Injection**: Para desacoplamento
- **Circuit Breaker**: Tratamento robusto de erros
- **Transaction Pattern**: Para operações atômicas
- **Async/Await**: Para operações não-bloqueantes

## Funcionalidades Detalhadas

### Gestão de Pacientes

#### Dados Biográficos Essenciais
- Nome completo (obrigatório)
- Data de nascimento com cálculo automático da idade
- Estado civil (opções pré-definidas)
- Telefone e telemóvel
- Email com validação de formato
- Como conheceu a clínica (para insights de marketing)
- Observações gerais

#### Validações Implementadas
- Nome obrigatório
- Data de nascimento no passado
- Idade entre 0-150 anos
- Formato de email válido
- Formato de telefone válido
- Email único por paciente

#### Operações Disponíveis
- Criar novo paciente
- Listar todos os pacientes
- Buscar pacientes por termo
- Editar dados existentes
- Ver detalhes completos

### Sistema de Consentimentos

Implementado para conformidade com LGPD/GDPR:

- **Consentimento LGPD/GDPR**: Obrigatório para processamento de dados
- **Consentimento de Tratamento**: Para tratamentos naturopáticos
- **Consentimento de Marketing**: Opcional para comunicações

## Como Executar

### Pré-requisitos

- .NET 8 SDK instalado
- Visual Studio, VS Code ou qualquer IDE que suporte .NET

### Executar a Aplicação

```bash
cd BioDeskPRO
dotnet run
```

### Executar Testes

```bash
cd BioDeskPRO.Tests
dotnet test
```

## Base de Dados

### Estrutura

- **Pacientes**: Dados biográficos principais
- **Consultas**: Histórico de atendimentos (futuro)
- **TiposConsentimento**: Tipos de consentimento disponíveis
- **AssinaturasConsentimento**: Rastreamento de consentimentos assinados

### Localização

A base de dados SQLite é criada automaticamente como `BioDeskPRO.db` na pasta da aplicação.

## Tratamento de Erros

### Estratégias Implementadas

- **Try-Catch Abrangente**: Em todas as operações críticas
- **Transações**: Para operações de escrita
- **Logging Detalhado**: Para diagnóstico
- **Mensagens Amigáveis**: Para o utilizador final
- **Recuperação Graceful**: Sistema continua funcionando mesmo com erros

### Exemplos de Proteções

- Validação de conexão à base de dados
- Recuperação de falhas de gravação
- Timeouts configuráveis
- Retry logic para operações críticas

## Segurança e Privacidade

### Conformidade LGPD/GDPR

- Sistema de consentimentos rastreável
- Armazenamento seguro de dados pessoais
- Possibilidade de remoção de dados
- Logs de acesso e modificações

### Boas Práticas

- Consultas parametrizadas (prevenção SQL Injection)
- Validação de entrada rigorosa
- Timestamps automáticos
- Integridade referencial

## Expansibilidade

### Preparação para o Futuro

- Arquitetura modular permite adição de novos módulos
- Base de dados normalizada e extensível
- Interface de serviços desacoplada
- Configuração por dependency injection

### Migração de Base de Dados

O sistema foi desenhado para permitir migração futura:
- SQLite → SQL Server
- SQLite → PostgreSQL
- SQLite → Nuvem (Azure SQL, AWS RDS)

## Contribuição

### Estrutura de Desenvolvimento

1. **Models**: Adicionar novas entidades em `Models/`
2. **Services**: Implementar lógica de negócio em `Services/`
3. **UI**: Criar interfaces em `UI/`
4. **Tests**: Adicionar testes em `BioDeskPRO.Tests/`

### Padrões de Código

- Async/await para operações de I/O
- Dependency injection obrigatória
- Tratamento de erros em todos os métodos públicos
- Logging adequado
- Testes unitários para nova funcionalidade

## Licença

Este projeto é proprietário e destinado ao uso em clínicas de Terapia Natural e Complementar.

## Suporte

Para questões técnicas ou funcionais, contactar a equipa de desenvolvimento.

---

**BioDeskPRO 2.0** - Transformando a gestão clínica holística através da tecnologia.