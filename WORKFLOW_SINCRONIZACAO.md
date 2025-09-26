# 🔄 BioDeskPro2 - Workflow de Sincronização Automática

## 🎯 Comandos Essenciais

### 📤 Fim do Trabalho (qualquer PC):
```bash
# Método 1 - Automático:
.\ENVIAR_MUDANCAS.bat

# Método 2 - Manual:
git add .
git commit -m "Trabalho do dia $(Get-Date -Format 'dd/MM')"
git push origin main
```

### 📥 Início do Trabalho (qualquer PC):
```bash
# Método 1 - Automático:
.\SINCRONIZAR_PC_ATUAL.bat

# Método 2 - Manual:
git pull origin main
dotnet build
```

## 🔥 REGRA DE OURO:
**SEMPRE** fazer `git push` antes de mudar de PC!
**SEMPRE** fazer `git pull` ao voltar ao PC!

## 🚨 Troubleshooting:

### Conflitos de Merge:
1. `git status` - ver ficheiros conflituosos
2. Abrir no VS Code - resolve visualmente
3. `git add .` - marcar como resolvido  
4. `git commit` - finalizar merge

### Esqueceu de fazer Push:
```bash
git stash        # Guardar mudanças locais
git pull         # Baixar mudanças remotas  
git stash pop    # Aplicar mudanças locais
# Resolver conflitos
git add . && git commit && git push
```

### Histórico Limpo:
```bash
git log --oneline -10  # Ver últimos commits
git status             # Ver estado atual
```

## ⚡ Pro Tips:

- **VS Code**: Ícone Source Control mostra mudanças
- **Terminal**: `git status` antes de qualquer comando
- **Commits**: Mensagens descritivas "Fix: bug paciente" 
- **Frequência**: Push/Pull diário mínimo!

## 🎉 Resultado:
**2 PCs = 1 Projeto Sincronizado = Produtividade Máxima!** 🚀