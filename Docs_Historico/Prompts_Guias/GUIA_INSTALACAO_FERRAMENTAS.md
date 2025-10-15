# 🛠️ GUIA DE INSTALAÇÃO - FERRAMENTAS DESENVOLVIMENTO

## ✅ FERRAMENTAS JÁ INSTALADAS (CONFIRMADO)
- ✅ .NET 8 SDK
- ✅ Visual Studio Code
- ✅ C# Extension (OmniSharp)
- ✅ PowerShell 5.1 (Windows integrado)

---

## 📦 FERRAMENTAS OPCIONAIS (RECOMENDADAS)

### 1. 🗄️ DB Browser for SQLite (INTERFACE GRÁFICA - RECOMENDADO)

**Propósito**: Visualizar/editar base de dados sem linha de comando

**Download**: https://sqlitebrowser.org/dl/

**Instalação**:
1. Descarrega `DB.Browser.for.SQLite-3.12.2-win64.msi`
2. Instala com Next → Next → Install
3. Abre `DB Browser for SQLite`
4. File → Open Database → `biodesk.db`

**Uso**:
- Tab "Browse Data" → Seleciona tabela `IrisImagens`
- Tab "Execute SQL" → Copia as queries de diagnóstico
- Tab "Database Structure" → Ver todas as tabelas

---

### 2. 🖥️ SQLite3 CLI (LINHA DE COMANDO - OPCIONAL)

**Propósito**: Executar queries SQL no PowerShell/Terminal

#### OPÇÃO A: Instalação via WinGet (Windows 10+)
```powershell
winget install SQLite.SQLite
```

#### OPÇÃO B: Instalação Manual
1. Descarrega: https://www.sqlite.org/download.html
   - `sqlite-tools-win32-x86-3430200.zip`
2. Extrai para `C:\sqlite\`
3. Adiciona ao PATH:
   ```powershell
   [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\sqlite", "User")
   ```
4. Reinicia PowerShell
5. Verifica: `sqlite3 --version`

**Uso**:
```powershell
# Abrir base de dados
sqlite3 .\biodesk.db

# Executar query (dentro do sqlite3>)
SELECT COUNT(*) FROM IrisImagens;

# Sair
.quit
```

---

### 3. 🔧 dotnet-script (C# SCRIPTING - JÁ PODES USAR)

**Propósito**: Executar ficheiros `.cs` como scripts

#### Instalação:
```powershell
dotnet tool install -g dotnet-script
```

#### Verificação:
```powershell
dotnet script --version
```

#### Uso:
```powershell
dotnet script .\Debug_Scripts\CheckDB.cs
```

**NOTA**: O script `CheckDB.cs` que acabei de atualizar usa isto!

---

### 4. 📊 PowerShell 7+ (MODERNO - OPCIONAL MAS ÚTIL)

**Propósito**: Versão moderna do PowerShell (suporta emojis, melhor performance)

#### Instalação via WinGet:
```powershell
winget install Microsoft.PowerShell
```

#### Instalação Manual:
https://aka.ms/PSWindows

**Vantagens**:
- ✅ Suporta emojis nos scripts (✅ 🚨 💡 📊)
- ✅ Melhor performance
- ✅ Cross-platform (funciona em Linux/Mac)
- ✅ Não substitui PowerShell 5.1 (ambos coexistem)

**Uso**:
- Abre "PowerShell 7" no menu iniciar (não "Windows PowerShell")
- Ou digita `pwsh` no terminal

---

## 🎯 RECOMENDAÇÃO PARA O TEU CASO

### SOLUÇÃO IMEDIATA (SEM INSTALAR NADA):

#### OPÇÃO 1: DB Browser for SQLite (5 minutos)
```
1. Download: https://sqlitebrowser.org/dl/
2. Instala e abre
3. File → Open Database → biodesk.db
4. Tab "Browse Data" → IrisImagens
5. Vês imediatamente quantas imagens tens
```

#### OPÇÃO 2: dotnet script (já tens .NET 8)
```powershell
# Instalar dotnet-script (só precisa 1 vez)
dotnet tool install -g dotnet-script

# Executar diagnóstico
dotnet script .\Debug_Scripts\CheckDB.cs
```

---

## 🚀 SETUP COMPLETO PROFISSIONAL

Se quiseres ter um ambiente completo:

```powershell
# 1. PowerShell 7
winget install Microsoft.PowerShell

# 2. SQLite3 CLI
winget install SQLite.SQLite

# 3. dotnet-script
dotnet tool install -g dotnet-script

# 4. Verificar tudo
pwsh -Command "sqlite3 --version; dotnet script --version"
```

---

## 📋 VERIFICAÇÃO PÓS-INSTALAÇÃO

```powershell
# Verificar .NET
dotnet --version          # Deve mostrar 8.0.x

# Verificar dotnet-script (se instalaste)
dotnet script --version   # Deve mostrar 1.5.x

# Verificar SQLite3 (se instalaste)
sqlite3 --version         # Deve mostrar 3.x.x

# Verificar PowerShell
$PSVersionTable.PSVersion # 5.1.x (integrado) ou 7.x.x (novo)
```

---

## ⚡ QUICK START - VERIFICAR BASE DE DADOS AGORA

### SEM INSTALAR NADA (usa o que já tens):

#### 1. Via Visual Studio Code + Extension
```
1. Instala extensão "SQLite" (alexcvzz.vscode-sqlite)
2. Ctrl+Shift+P → "SQLite: Open Database"
3. Seleciona biodesk.db
4. Clica em "IrisImagens" no painel SQLite EXPLORER
```

#### 2. Via C# Script (mais rápido):
```powershell
# Instala dotnet-script (1 vez só)
dotnet tool install -g dotnet-script

# Executa diagnóstico
dotnet script .\Debug_Scripts\CheckDB.cs
```

#### 3. Via DB Browser (interface gráfica):
```
Download: https://sqlitebrowser.org/dl/
Instala → Abre → File → Open Database → biodesk.db
```

---

## 🎓 O QUE EU RECOMENDO PARA TI

**AGORA (próximos 5 minutos)**:
```powershell
# Opção mais simples - instala dotnet-script
dotnet tool install -g dotnet-script

# Depois executa o diagnóstico que já preparei
dotnet script .\Debug_Scripts\CheckDB.cs
```

**PARA O FUTURO (quando tiveres tempo)**:
1. Instala **DB Browser for SQLite** → Interface gráfica excelente
2. Instala **PowerShell 7** → Melhor que PowerShell 5.1
3. (Opcional) Instala **SQLite3 CLI** → Se gostas de linha de comando

---

## ❓ PERGUNTAS FREQUENTES

**P: Preciso MESMO de instalar algo?**
R: Não! Posso criar queries SQL e tu executa-las no DB Browser (que é gráfico e simples).

**P: Qual é a forma mais simples de ver a base de dados?**
R: DB Browser for SQLite (interface gráfica, sem terminal).

**P: Qual é a forma mais rápida?**
R: `dotnet tool install -g dotnet-script` e depois `dotnet script .\Debug_Scripts\CheckDB.cs`

**P: O que escolhes tu?**
R: DB Browser para visualizar, dotnet-script para diagnósticos automáticos.

---

## 🔥 SOLUÇÃO ULTRA-RÁPIDA (30 segundos)

Se quiseres ver a base de dados AGORA sem instalar nada:

1. Abre VS Code
2. Ctrl+Shift+X (Extensions)
3. Procura "SQLite" (autor: alexcvzz)
4. Instala
5. Ctrl+Shift+P → "SQLite: Open Database"
6. Seleciona `biodesk.db`
7. Painel esquerdo → SQLite EXPLORER → IrisImagens → Clica direito → "Show Table"

**Vês imediatamente se tens imagens ou não!**
