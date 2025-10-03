# 🔧 Debug Scripts - BioDeskPro 2.0

**Pasta de scripts temporários para debug e investigação**

---

## 📂 Conteúdo

### Scripts C# Interativos (.csx)
- **InvestigarPaciente.csx** - Investigação de dados de pacientes na BD
- **VerificarEmails.csx** - Verificação de emails agendados e enviados
- **VerificarPacientes.csx** - Verificação rápida de dados de pacientes
- **VerificarPacientesRapido.csx** - Versão otimizada da verificação
- **VerificarTodasBDs.csx** - Análise completa de todas as tabelas
- **TestCommand.csx** - Testes rápidos de comandos

### Scripts C# Standalone (.cs)
- **CheckDB.cs** - Verificação de integridade da base de dados
- **InvestigarPaciente.cs** - Versão compilável do investigador
- **VerificarBD.cs** - Verificação simples de estrutura BD

### Projetos de Debug
- **InvestigacaoDB/** - Projeto console para investigação avançada da BD

---

## 🚀 Como Usar

### Scripts .csx (C# Interactive)
```bash
# Executar com dotnet-script (se instalado)
dotnet script InvestigarPaciente.csx

# Ou abrir no VS Code e executar com C# Dev Kit
```

### Scripts .cs
```bash
# Compilar e executar
dotnet run CheckDB.cs
```

### Projeto InvestigacaoDB
```bash
cd InvestigacaoDB
dotnet run
```

---

## ⚠️ IMPORTANTE

- **NÃO COMMITAR** estes scripts no repositório principal
- Apenas para debug local e investigação temporária
- Dados sensíveis podem estar em outputs - **CUIDADO**

---

## 🗑️ Limpeza

Scripts podem ser deletados após debug:
```bash
# Limpar todos os scripts
rm -r Debug_Scripts/
```

---

*Criado: 2025-10-02*  
*Organizado automaticamente pelo GitHub Copilot*
