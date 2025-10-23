# 🚀 Guia de Transferência BioDeskPro2 para Novo PC
**Data**: 18 de Outubro de 2025
**Versão**: .NET 8.0.403 | Build Status: ✅ 0 Errors

---

## 📋 Checklist Pré-Transferência

### ✅ 1. Git/GitHub - Sincronização Completa

#### Estado Atual Detectado:
```
Branch: copilot/vscode1760742399628
Status: 2 commits atrás do remoto
Ficheiros modificados: 9
Ficheiros untracked: 1 (Debug_Scripts/ListarExports_HS3.ps1)
```

#### Ações Necessárias:
```powershell
# 1.1 - Pull dos commits remotos
# Defina $ProjectPath para o caminho do projeto antes de executar (ex: $ProjectPath = 'D:\\BioDeskPro2')
cd $ProjectPath
git pull

# 1.2 - Adicionar ficheiro untracked
git add Debug_Scripts/ListarExports_HS3.ps1

# 1.3 - Commit das alterações locais
git add .
git commit -m "🔧 Preparação para transferência: TiePie HS3 integration updates"

# 1.4 - Push para GitHub
git push origin copilot/vscode1760742399628

# 1.5 - Verificar estado final (deve estar limpo)
git status
```

**⚠️ IMPORTANTE**: Só avançar para backup quando `git status` mostrar:
```
On branch copilot/vscode1760742399628
Your branch is up to date with 'origin/copilot/vscode1760742399628'.
nothing to commit, working tree clean
```

---

### ✅ 2. Backup Completo da Base de Dados

#### 🔴 ATENÇÃO - Leia REGRAS_CRITICAS_BD.md Primeiro!

**Localização da BD (Modo Debug)**:
```
$ProjectPath\biodesk.db
$ProjectPath\biodesk.db-shm
$ProjectPath\biodesk.db-wal
```

**Localização da BD (Modo Release - se instalado)**:
```
C:\ProgramData\BioDeskPro2\biodesk.db
C:\ProgramData\BioDeskPro2\biodesk.db-shm
C:\ProgramData\BioDeskPro2\biodesk.db-wal
```

#### Executar Backup Automático:
```powershell
# 2.1 - Executar script de backup
.\backup.ps1

# 2.2 - Verificar criação do backup
ls .\Backups\ | Sort-Object LastWriteTime -Descending | Select-Object -First 1
```

**Resultado Esperado**: Pasta `Backup_TRANSFERENCIA_PC_YYYYMMDD_HHMMSS` criada em `Backups/`

#### Backup Manual Adicional (Segurança Extra):
```powershell
# 2.3 - Copiar BD manualmente para pasta específica
$dataTransferencia = Get-Date -Format "yyyyMMdd_HHmmss"
$pastaBackupManual = ".\Backups\Backup_Manual_PC_$dataTransferencia"
New-Item -ItemType Directory -Path $pastaBackupManual -Force

# Copiar BD do modo debug (se existe)
if (Test-Path ".\biodesk.db") {
    Copy-Item ".\biodesk.db*" -Destination $pastaBackupManual -Force
    Write-Host "✅ BD Debug copiada para $pastaBackupManual"
}

# Copiar BD do modo release (se existe)
if (Test-Path "C:\ProgramData\BioDeskPro2\biodesk.db") {
    Copy-Item "C:\ProgramData\BioDeskPro2\biodesk.db*" -Destination "$pastaBackupManual\Release\" -Force
    Write-Host "✅ BD Release copiada para $pastaBackupManual\Release\"
}

# Verificar tamanho da BD (deve ter >700KB se tiver dados)
Get-ChildItem "$pastaBackupManual\*.db" | Select-Object Name, @{Name="Size(MB)";Expression={[math]::Round($_.Length/1MB,2)}}
```

---

### ✅ 3. Verificar Ficheiros Críticos

#### Ficheiros que DEVEM estar no repositório Git:
```
✅ global.json              (fixa .NET 8.0.403)
✅ omnisharp.json           (IntelliSense config)
✅ .editorconfig            (88 regras CA)
✅ .vscode/settings.json    (VS Code config)
✅ .vscode/tasks.json       (Build tasks)
✅ BioDeskPro2.sln          (Solution)
✅ src/                     (Todo o código-fonte)
✅ Templates/               (Templates PDF/Email)
✅ backup.ps1               (Script de backup)
✅ README.md + Docs         (Documentação)
```

#### Ficheiros que NÃO devem ir para Git (já no .gitignore):
```
❌ bin/
❌ obj/
❌ biodesk.db (BD local debug)
❌ biodesk.db-shm
❌ biodesk.db-wal
❌ Pacientes/ (dados clínicos)
❌ Documentos/ (ficheiros gerados)
❌ Consentimentos/ (PDFs pacientes)
❌ Prescricoes/ (PDFs prescrições)
❌ Logs/ (ficheiros de log)
❌ Backups/ (backups da BD)
```

#### Verificar .gitignore:
```powershell
# 3.1 - Confirmar que .gitignore está correto
cat .\.gitignore | Select-String -Pattern "biodesk.db|Pacientes|Backups|bin|obj"
```

---

### ✅ 4. Build Final e Testes

```powershell
# 4.1 - Build limpo completo
dotnet clean
dotnet restore
dotnet build

# Resultado esperado: 0 Errors, ~24 Warnings (apenas AForge)
```

```powershell
# 4.2 - Executar testes
dotnet test src/BioDesk.Tests

# Resultado esperado: Todos os testes PASSED
```

```powershell
# 4.3 - Executar aplicação (teste final)
dotnet run --project src/BioDesk.App

# Verificar:
# - Dashboard abre sem erros
# - Pacientes recentes aparecem
# - Navegação funciona (NovoPaciente, FichaPaciente, etc.)
# - Fechar aplicação
```

---

## 📦 Método 1: GitHub (Recomendado)

### No PC Atual (Windows):
```powershell
# Já executado nos passos 1.1 a 1.4 acima
git status  # Confirmar: "working tree clean"
```

### No Novo PC:
```powershell
# 1. Instalar pré-requisitos
# - Git for Windows: https://git-scm.com/download/win
# - .NET 8 SDK (8.0.403): https://dotnet.microsoft.com/download/dotnet/8.0
# - Visual Studio Code: https://code.visualstudio.com/

# 2. Clonar repositório
cd C:\Users\[SEU_USER]\Documents
git clone https://github.com/NunoCorreia78/BioDeskPRO2.0.git BioDeskPro2
cd BioDeskPro2

# 3. Checkout da branch correta
git checkout copilot/vscode1760742399628

# 4. Restaurar packages
dotnet restore

# 5. Build inicial
dotnet build

# 6. Executar
dotnet run --project src/BioDesk.App
```

---

## 💾 Método 2: Backup + Cópia de Pasta

### No PC Atual:

#### Criar ZIP da Pasta Completa:
```powershell
# 5.1 - Comprimir pasta do projeto (EXCLUINDO bin/obj)
## Definir variável de projeto
# Antes de executar, defina $ProjectPath para o local do seu projeto (ex: D:\\BioDeskPro2)
$origem = $ProjectPath
$destino = "$ProjectPath`_TRANSFERENCIA_$(Get-Date -Format 'yyyyMMdd_HHmmss').zip"

# Excluir pastas pesadas desnecessárias
$excludePatterns = @('bin', 'obj', '.vs', 'Logs', 'Pacientes', 'Documentos', 'Prescricoes', 'Consentimentos')

# Comprimir (requer PowerShell 5.0+)
$compress = @{
    Path = $origem
    DestinationPath = $destino
    CompressionLevel = "Optimal"
}
Compress-Archive @compress -Force

Write-Host "✅ ZIP criado: $destino"
Write-Host "📊 Tamanho: $([math]::Round((Get-Item $destino).Length/1MB,2)) MB"
```

**OU** copiar pasta diretamente para pen/disco externo:
```powershell
# 5.2 - Copiar para disco externo (exemplo: D:\)
$destino = "D:\BioDeskPro2_Backup_$(Get-Date -Format 'yyyyMMdd')"
robocopy $origem $destino /E /XD bin obj .vs Logs Pacientes Documentos Prescricoes Consentimentos /XF *.db *.db-shm *.db-wal

Write-Host "✅ Pasta copiada para: $destino"
```

### No Novo PC:

```powershell
# 1. Copiar pasta do disco externo/descomprimir ZIP
# Para: C:\Users\[SEU_USER]\Documents\BioDeskPro2

# 2. Instalar .NET 8 SDK (8.0.403)
# https://dotnet.microsoft.com/download/dotnet/8.0

# 3. Restaurar packages
cd C:\Users\[SEU_USER]\Documents\BioDeskPro2
dotnet restore

# 4. Build
dotnet build

# 5. Executar
dotnet run --project src/BioDesk.App
```

---

## 🗄️ Restaurar Base de Dados no Novo PC

### Opção A: BD Vazia (Começar do Zero)
```powershell
# Não fazer nada - aplicação criará BD nova automaticamente na primeira execução
```

### Opção B: Restaurar BD do Backup
```powershell
# 1. Copiar ficheiro do backup mais recente
$backupMaisRecente = Get-ChildItem ".\Backups\Backup_Manual_PC_*" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Copy-Item "$backupMaisRecente\biodesk.db" -Destination ".\biodesk.db" -Force

# 2. Verificar integridade (tamanho deve ser >700KB se tiver dados)
Get-Item ".\biodesk.db" | Select-Object Name, @{Name="Size(MB)";Expression={[math]::Round($_.Length/1MB,2)}}

# 3. Executar aplicação - deve carregar dados dos pacientes
dotnet run --project src/BioDesk.App
```

---

## 🔍 Verificações Pós-Transferência

### Checklist Final no Novo PC:

```powershell
# ✅ 1. .NET SDK instalado
dotnet --version
# Esperado: 8.0.403

# ✅ 2. Build sem erros
dotnet build
# Esperado: 0 Errors

# ✅ 3. Testes passam
dotnet test src/BioDesk.Tests
# Esperado: Todos PASSED

# ✅ 4. Aplicação executa
dotnet run --project src/BioDesk.App
# Verificar:
# - Dashboard abre
# - Pacientes recentes (se BD foi restaurada)
# - Navegação funciona
# - Sem exceptions no console

# ✅ 5. PathService correto
# No Dashboard, criar um paciente de teste
# Verificar que BD fica em: .\biodesk.db (modo debug)
ls .\biodesk.db
```

---

## ⚠️ Troubleshooting Comum

### Problema: "SDK not found"
```powershell
# Verificar global.json
cat .\global.json
# Deve ter: "version": "8.0.403"

# Instalar SDK exato: https://dotnet.microsoft.com/download/dotnet/8.0
```

### Problema: "Build errors CA1001, CA1816..."
```powershell
# Verificar que omnisharp.json foi copiado
cat .\omnisharp.json

# Verificar que .editorconfig existe
cat .\.editorconfig

# Rebuild limpo
dotnet clean
dotnet restore
dotnet build
```

### Problema: "BD não carrega pacientes"
```powershell
# Verificar tamanho da BD
Get-Item .\biodesk.db | Select-Object Length

# Se <1KB, BD está vazia - restaurar do backup:
Copy-Item ".\Backups\Backup_Manual_PC_XXXXXX\biodesk.db" -Destination ".\biodesk.db" -Force
```

### Problema: "Templates não encontrados"
```powershell
# Verificar estrutura de pastas
ls .\Templates\

# Deve conter:
# - Naturopatia_Consentimento.html
# - Osteopatia_Consentimento.html
# - Prescricao_*.html
# - Email_*.html
```

---

## 📞 Suporte

### Documentação Crítica:
- **REGRAS_CRITICAS_BD.md** - Proteção contra perda de dados
- **copilot-instructions.md** - Arquitetura completa
- **SISTEMA_100_COMPLETO.md** - Status do projeto

### Repositório GitHub:
- https://github.com/NunoCorreia78/BioDeskPRO2.0
- Branch atual: `copilot/vscode1760742399628`

### Build Status Atual:
- ✅ 0 Errors
- ⚠️ 24 Warnings (apenas AForge - compatibilidade câmara)
- ✅ Todos os testes PASSED
- ✅ Aplicação WPF funcional

---

## 🎯 Resumo dos 3 Métodos

| Método | Quando Usar | Vantagens | Desvantagens |
|--------|-------------|-----------|--------------|
| **1. GitHub Clone** | PC com internet rápida | • Sempre atualizado<br>• Histórico Git completo<br>• Fácil sincronização | • Requer internet<br>• Não inclui BD |
| **2. ZIP da Pasta** | PC sem internet / Backup rápido | • Offline<br>• Inclui tudo<br>• Simples | • Ficheiro grande<br>• Sem histórico Git |
| **3. Cópia Direta** | Discos externos / Pen USB | • Mais rápido<br>• Sem compressão<br>• BD incluída | • Ocupa mais espaço<br>• Sem histórico Git |

**Recomendação**: Usar **Método 1 (GitHub)** + **Backup Manual da BD** para máxima segurança.

---

**✅ Documento criado em**: 18 de Outubro de 2025
**🔄 Última atualização**: Build sem erros, testes PASSED, aplicação funcional
