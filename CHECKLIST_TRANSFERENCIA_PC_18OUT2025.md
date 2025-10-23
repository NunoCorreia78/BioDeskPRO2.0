# ✅ Checklist de Transferência de PC - BioDeskPro2
**Data**: 18 de outubro de 2025
**Status Build**: ✅ 0 Errors, 150 Testes Passaram
**Backup Criado**: ✅ `C:\Backups\BioDeskPro2\backup_20251018_120523.zip` (149 MB)

---

## 📋 CHECKLIST COMPLETO

### 🔴 PASSO 1: Commit e Push Git (PC ANTIGO)

#### 1.1 Verificar Estado Git
```powershell
- ```powershell
# Antes de executar os comandos abaixo, defina a variável `$ProjectPath` para o caminho onde o projeto está localizado no seu PC.
# Exemplo:
#   $ProjectPath = "D:\\BioDeskPro2"             # se copiou para disco externo
#   $ProjectPath = "C:\\Users\\<USERNAME>\\OneDrive\\Documentos\\BioDeskPro2"  # se usa OneDrive
# Depois use `$ProjectPath` em vez de caminhos hardcoded.

cd $ProjectPath
git status
```

**Estado Atual**:
- ⚠️ Branch `copilot/vscode1760742399628` está **2 commits atrás** do remoto
- ⚠️ **9 ficheiros modificados** não commitados
- ⚠️ **2 ficheiros untracked**

#### 1.2 Fazer Pull dos Commits Remotos
```powershell
git pull origin copilot/vscode1760742399628
```

#### 1.3 Adicionar Ficheiros ao Staging
```powershell
# Adicionar ficheiros modificados
git add DEBUG_DOCUMENTOS.txt
git add src/BioDesk.App/BioDesk.App.csproj
git add src/BioDesk.App/Views/Terapia/EmissaoConfiguracaoUserControl.xaml
git add src/BioDesk.App/Views/Terapia/ProgramasView.xaml.cs
git add src/BioDesk.Services/Audio/FrequencyEmissionService.cs
git add src/BioDesk.Services/Hardware/TiePie/HS3Native.cs
git add src/BioDesk.Services/Hardware/TiePie/TiePieHS3Service.cs
git add src/BioDesk.ViewModels/UserControls/Terapia/EmissaoConfiguracaoViewModel.cs

# Adicionar ficheiros novos
git add Debug_Scripts/ListarExports_HS3.ps1
git add GUIA_TRANSFERENCIA_PC_18OUT2025.md

# Remover ficheiro deletado
git rm src/BioDesk.ViewModels/Debug/TesteHS3ViewModel.cs
```

#### 1.4 Fazer Commit
```powershell
git commit -m "✨ Preparação para transferência PC - Integração TiePie HS3 completa

- ✅ 150 testes passaram
- ✅ Build sem erros
- ✅ Backup criado: backup_20251018_120523.zip
- 🔧 Ajustes finais integração HS3Native
- 📝 Documentação de transferência
- 🗑️ Remoção TesteHS3ViewModel (componente debug)"
```

#### 1.5 Push para GitHub
```powershell
git push origin copilot/vscode1760742399628
```

**✅ CHECKPOINT**: Verificar no GitHub que o commit apareceu.

---

### 🟡 PASSO 2: Backup Base de Dados (PC ANTIGO)

#### 2.1 Verificar Localização da BD
```powershell
# Usar a variável $ProjectPath (defina-a antes de usar os comandos)
# Se trabalhar em modo Debug (VS Code)
Get-ChildItem "$ProjectPath\biodesk.db" -ErrorAction SilentlyContinue

# Se em modo Release (instalado)
Get-ChildItem "C:\ProgramData\BioDeskPro2\biodesk.db" -ErrorAction SilentlyContinue
```

#### 2.2 Copiar BD para Backup
```powershell
# Criar pasta de backup BD
New-Item -Path "C:\Backups\BioDeskPro2\BD_Manual" -ItemType Directory -Force

# Copiar BD (ajustar caminho conforme localização) - usa $ProjectPath
Copy-Item "$ProjectPath\biodesk.db" `
          "C:\Backups\BioDeskPro2\BD_Manual\biodesk_PRE_TRANSFERENCIA_18OUT2025.db"

# Verificar tamanho (deve ter >700KB se tiver dados)
(Get-Item "C:\Backups\BioDeskPro2\BD_Manual\biodesk_PRE_TRANSFERENCIA_18OUT2025.db").Length / 1KB
```

**✅ CHECKPOINT**: Tamanho da BD verificado (deve ser >700KB).

#### 2.3 Backup Documentos de Pacientes
```powershell
# Copiar pastas documentais (se existirem) - use $ProjectPath para os caminhos de projeto
$PastasDocumentais = @(
    "$ProjectPath\Pacientes",
    "$ProjectPath\Documentos",
    "$ProjectPath\Prescricoes",
    "$ProjectPath\Consentimentos",
    "C:\ProgramData\BioDeskPro2\Pacientes",
    "C:\ProgramData\BioDeskPro2\Documentos"
)

foreach ($Pasta in $PastasDocumentais) {
    if (Test-Path $Pasta) {
        $NomePasta = Split-Path $Pasta -Leaf
        Copy-Item -Path $Pasta -Destination "C:\Backups\BioDeskPro2\BD_Manual\$NomePasta" -Recurse -Force
        Write-Host "✅ Copiado: $NomePasta" -ForegroundColor Green
    }
}
```

---

### 🟢 PASSO 3: Cópia da Pasta do Projeto (PC ANTIGO)

#### 3.1 Copiar Pasta Completa para Dispositivo Externo
```powershell
# Opção 1: Copiar para pendrive (ex: E:\)
$Destino = "E:\\BioDeskPro2_Transferencia_18OUT2025"
# Use $ProjectPath definido no topo do ficheiro. Por exemplo:
#   $ProjectPath = "D:\\BioDeskPro2"  # disco externo
#   $ProjectPath = "C:\\Users\\<USERNAME>\\OneDrive\\Documentos\\BioDeskPro2"  # OneDrive
Copy-Item -Path $ProjectPath `
          -Destination $Destino -Recurse -Force

# Opção 2: Copiar para rede/serviço de nuvem (ex.: OneDrive) — defina $ProjectPath conforme necessário
# Verificar: $ProjectPath (ou o caminho onde a pasta do projeto foi copiada)
```

#### 3.2 Verificar Cópia
```powershell
# Contar ficheiros na origem e destino
(Get-ChildItem $ProjectPath -Recurse -File).Count
(Get-ChildItem $Destino -Recurse -File).Count

# Verificar tamanho total
(Get-ChildItem $ProjectPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1GB
(Get-ChildItem $Destino -Recurse | Measure-Object -Property Length -Sum).Sum / 1GB
```

**✅ CHECKPOINT**: Número de ficheiros e tamanho coincidem.

---

### 🔵 PASSO 4: Instalação no PC NOVO

#### 4.1 Pré-requisitos
- [ ] **.NET 8 SDK** instalado → https://dotnet.microsoft.com/download/dotnet/8.0
- [ ] **Git** instalado → https://git-scm.com/download/win
- [ ] **Visual Studio Code** instalado → https://code.visualstudio.com/
- [ ] **GitHub** configurado (SSH ou token)

#### 4.2 Verificar .NET 8
```powershell
dotnet --version
# Deve mostrar: 8.0.xxx
```

#### 4.3 Clonar Repositório (MÉTODO 1 - Recomendado)
```powershell
# Navegar para pasta de trabalho
# Defina $ProjectPath antes de usar. Exemplo:
#   $ProjectPath = "C:\\Users\\[NOVO_USERNAME]\\Documents\\BioDeskPro2"
cd $ProjectPath

# Clonar repositório
git clone https://github.com/NunoCorreia78/BioDeskPRO2.0.git BioDeskPro2
cd BioDeskPro2

# Fazer checkout da branch correta
git checkout copilot/vscode1760742399628
git pull origin copilot/vscode1760742399628
```

#### 4.4 OU Copiar Pasta (MÉTODO 2 - Se Clonar falhar)
```powershell
# Copiar do dispositivo externo
# Se copiar do dispositivo externo, use $ProjectPath como destino
Copy-Item -Path "E:\BioDeskPro2_Transferencia_18OUT2025" `
          -Destination $ProjectPath -Recurse

cd $ProjectPath

# Verificar estado Git
git status
git pull origin copilot/vscode1760742399628
```

---

### 🟣 PASSO 5: Restaurar Base de Dados (PC NOVO)

#### 5.1 Copiar BD para Localização Correta
```powershell
# Se for trabalhar em modo Debug (VS Code)
Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\biodesk_PRE_TRANSFERENCIA_18OUT2025.db" `
          "$ProjectPath\biodesk.db"

# Verificar tamanho
(Get-Item "$ProjectPath\biodesk.db").Length / 1KB
```

#### 5.2 Restaurar Pastas Documentais
```powershell
$PastasProjeto = $ProjectPath

Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\Pacientes" "$PastasProjeto\Pacientes" -Recurse -Force
Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\Documentos" "$PastasProjeto\Documentos" -Recurse -Force
Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\Prescricoes" "$PastasProjeto\Prescricoes" -Recurse -Force
Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\Consentimentos" "$PastasProjeto\Consentimentos" -Recurse -Force
```

---

### 🟠 PASSO 6: Compilar e Testar (PC NOVO)

#### 6.1 Restaurar Dependências
```powershell
cd $ProjectPath

dotnet clean
dotnet restore
```

#### 6.2 Build Completo
```powershell
dotnet build
```

**✅ Verificar**: 0 Errors (warnings AForge são normais)

#### 6.3 Executar Testes
```powershell
dotnet test src/BioDesk.Tests
```

**✅ Verificar**: 150 testes passam (Passed: 150)

#### 6.4 Executar Aplicação
```powershell
dotnet run --project src/BioDesk.App
```

**✅ Verificar**:
- Dashboard abre
- Pesquisa de pacientes funciona
- Dados da BD aparecem (pacientes recentes)

---

### 🟤 PASSO 7: Configurar VS Code (PC NOVO)

#### 7.1 Abrir Projeto
```powershell
code $ProjectPath
```

#### 7.2 Instalar Extensões Recomendadas
- **C# Dev Kit** (Microsoft)
- **C#** (Microsoft)
- **GitLens** (GitKraken)
- **GitHub Copilot** (GitHub)

#### 7.3 Verificar OmniSharp
- Abrir ficheiro `.cs` qualquer
- Verificar no canto inferior direito: "OmniSharp: Running"
- Esperar IntelliSense carregar (1-2 min primeira vez)

#### 7.4 Verificar Problems Panel
- `Ctrl+Shift+M` para abrir Problems
- Verificar: Sem erros vermelhos (apenas warnings AForge)

---

## 📊 CHECKLIST RESUMO

### PC ANTIGO
- [ ] Git pull executado
- [ ] Ficheiros commitados e push feito
- [ ] Backup automático criado (`backup.ps1`)
- [ ] BD copiada manualmente para `C:\Backups\BioDeskPro2\BD_Manual`
- [ ] Pastas documentais copiadas
- [ ] Pasta projeto copiada para dispositivo externo (ou serviço de nuvem) e $ProjectPath atualizado

### PC NOVO
- [ ] .NET 8 SDK instalado
- [ ] Git e VS Code instalados
- [ ] Repositório clonado OU pasta copiada
- [ ] Branch `copilot/vscode1760742399628` checkout
- [ ] `dotnet restore` executado
- [ ] `dotnet build` sem erros
- [ ] `dotnet test` → 150 testes passaram
- [ ] BD restaurada (`biodesk.db` no lugar certo)
- [ ] Pastas documentais restauradas
- [ ] Aplicação executa (`dotnet run`)
- [ ] VS Code configurado com extensões
- [ ] IntelliSense funciona

---

## 🚨 REGRAS CRÍTICAS

### ⚠️ NUNCA Fazer
1. **NUNCA alterar `PathService.cs`** → Causa perda de acesso à BD
2. **NUNCA alterar `App.xaml.cs` linha DbContext** → Cria BD nova vazia
3. **NUNCA deletar `biodesk.db`** sem backup → PERDA DE DADOS IRREVERSÍVEL

### ✅ SEMPRE Fazer
1. **SEMPRE verificar tamanho da BD** após copiar (>700KB se tiver dados)
2. **SEMPRE executar testes** após restaurar no PC novo
3. **SEMPRE fazer backup** antes de qualquer alteração crítica
4. **SEMPRE verificar branch Git** correta (`copilot/vscode1760742399628`)

---

## 📁 Ficheiros Críticos a Transferir

### Código (Via Git)
- Todo `src/` (6 projetos)
- `BioDeskPro2.sln`
- `global.json` (.NET 8 fixo)
- `omnisharp.json` (IntelliSense config)
- `.editorconfig` (88 regras CA)
- `.vscode/` (tasks, settings)

### Dados (Cópia Manual)
- **`biodesk.db`** (BASE DE DADOS - CRÍTICO!)
- `Pacientes/` (fotos íris, documentos)
- `Documentos/` (PDFs gerados)
- `Prescricoes/` (prescrições médicas)
- `Consentimentos/` (assinaturas digitais)
- `Templates/` (templates PDF)

---

## 🆘 Troubleshooting

### Problema: Build falha no PC novo
**Solução**:
```powershell
dotnet clean
dotnet restore --force
dotnet build --no-incremental
```

### Problema: BD vazia após transferência
**Solução**:
```powershell
# Verificar se BD foi copiada
Get-Item "$ProjectPath\biodesk.db"

# Verificar tamanho (deve ser >700KB)
(Get-Item "biodesk.db").Length / 1KB

# Se tamanho < 10KB, restaurar backup
Copy-Item "C:\Backups\BioDeskPro2\BD_Manual\biodesk_PRE_TRANSFERENCIA_18OUT2025.db" `
          "biodesk.db" -Force
```

### Problema: IntelliSense não funciona
**Solução**:
1. Fechar VS Code
2. Deletar pasta `.vs/` e `bin/`, `obj/` de todos os projetos
3. Reabrir VS Code
4. `Ctrl+Shift+P` → "OmniSharp: Restart OmniSharp"

### Problema: Git authentication falha
**Solução**:
```powershell
# Configurar credenciais
git config --global user.name "NunoCorreia78"
git config --global user.email "seu_email@exemplo.com"

# Se usar SSH
ssh-keygen -t ed25519 -C "seu_email@exemplo.com"
# Adicionar chave em: https://github.com/settings/keys

# Se usar HTTPS
# Criar Personal Access Token: https://github.com/settings/tokens
```

---

## 📞 Suporte

- **Documentação**: Ver `GUIA_TRANSFERENCIA_PC_18OUT2025.md` (guia detalhado)
- **Issues GitHub**: https://github.com/NunoCorreia78/BioDeskPRO2.0/issues
- **Pull Request Ativa**: #12 (Auditoria TiePie HS3)

---

**Data de Criação**: 18/10/2025
**Última Build**: ✅ 0 Errors, 150 Tests Passed
**Backup**: `C:\Backups\BioDeskPro2\backup_20251018_120523.zip`
**Status**: ✅ PRONTO PARA TRANSFERÊNCIA
