# 🗄️ Soluções para Erro "sqlite3 não reconhecido"

## ❓ O Problema
Quando tentamos usar `sqlite3` no terminal PowerShell, recebemos:
```
sqlite3: The term 'sqlite3' is not recognized as a name of a cmdlet, function, script file, or executable program.
```

## ✅ 3 Soluções Profissionais

### 1. **Usar DB Browser for SQLite** (⭐ RECOMENDADO)
Interface gráfica profissional, zero configuração.

**Instalar Manualmente** (Chocolatey não disponível):
1. 🌐 **Abrir** página de download: https://sqlitebrowser.org/dl/
2. 📥 **Baixar**: "DB Browser for SQLite - Standard installer for 64-bit Windows"
   - Ficheiro: `DB.Browser.for.SQLite-xxx-win64.msi` ou `.exe`
3. ▶️ **Executar** instalador (duplo clique)
4. ✅ **Instalar**: Seguir assistente (Next → Next → Install)

**Abrir a BD do BioDeskPro2**:
```powershell
# Localização da nossa BD
C:\Users\Nuno Correia\OneDrive\Documentos\BioDeskPro2\src\BioDesk.App\biodesk.db

# 1. Abrir DB Browser (ícone no Desktop ou Menu Iniciar)
# 2. File → Open Database
# 3. Navegar até o caminho acima
# 4. Browse Data → Selecionar tabela "Pacientes"
```

**Vantagens**:
- ✅ Interface gráfica intuitiva
- ✅ Visualiza tabelas/dados sem SQL
- ✅ Editor SQL integrado
- ✅ Export/Import fácil
- ✅ Zero configuração PATH

---

### 2. **Instalar SQLite CLI Oficialmente**
Para quem prefere linha de comando.

**Instalar via Chocolatey**:
```powershell
# No PowerShell como Administrador
choco install sqlite
```

**Instalar Manualmente**:
1. Baixar: https://www.sqlite.org/download.html
   - Procure: "sqlite-tools-win-x64-*.zip"
2. Extrair para `C:\sqlite\`
3. Adicionar ao PATH:
   ```powershell
   # PowerShell como Admin
   [Environment]::SetEnvironmentVariable("Path", "$env:Path;C:\sqlite", "Machine")
   ```
4. Reiniciar terminal

**Uso**:
```bash
sqlite3 biodesk.db
.tables
SELECT * FROM Pacientes;
.exit
```

---

### 3. **Usar EF Core CLI** (✅ JÁ TEMOS)
O Entity Framework Core já tem tudo que precisamos!

**Verificar Base de Dados**:
```powershell
# Ver migrações aplicadas
dotnet ef database update --project src/BioDesk.Data

# Gerar SQL das migrações
dotnet ef migrations script --project src/BioDesk.Data

# Listar migrações
dotnet ef migrations list --project src/BioDesk.Data
```

**Executar SQL Direto (via C# Script)**:
```csharp
// Criar: VerificarBD.csx
#r "nuget: Microsoft.Data.Sqlite, 8.0.8"

using Microsoft.Data.Sqlite;

var connectionString = "Data Source=src/BioDesk.App/biodesk.db";
using var connection = new SqliteConnection(connectionString);
connection.Open();

var command = connection.CreateCommand();
command.CommandText = "SELECT * FROM Pacientes";
using var reader = command.ExecuteReader();

while (reader.Read())
{
    Console.WriteLine($"{reader["Id"]} - {reader["Nome"]}");
}
```

**Executar**:
```powershell
dotnet script VerificarBD.csx
```

---

### 4. **PowerShell + .NET Direto** (⚡ RÁPIDO)
Sem instalar nada extra.

**Criar script**: `VerificarBD.ps1`
```powershell
Add-Type -Path "C:\Users\Nuno Correia\.nuget\packages\microsoft.data.sqlite.core\8.0.8\lib\net8.0\Microsoft.Data.Sqlite.dll"

$connectionString = "Data Source=src/BioDesk.App/biodesk.db"
$connection = New-Object Microsoft.Data.Sqlite.SqliteConnection($connectionString)
$connection.Open()

$command = $connection.CreateCommand()
$command.CommandText = "SELECT * FROM Pacientes"
$reader = $command.ExecuteReader()

while ($reader.Read()) {
    Write-Host "$($reader['Id']) - $($reader['Nome'])"
}

$connection.Close()
```

**Executar**:
```powershell
.\VerificarBD.ps1
```

---

## 🎯 Recomendação Final

Para **BioDeskPro2**, recomendo:

1. **Durante desenvolvimento**:
   - **DB Browser for SQLite** (GUI rápida para ver dados)
   - **EF Core CLI** (migrações e schema)

2. **Para scripts de teste**:
   - **C# Scripts** (`dotnet script`) - já usamos!
   - **PowerShell + .NET** - zero dependências

3. **NÃO instalar SQLite CLI** a menos que precise muito de linha de comando pura.

---

## 📦 Quick Start - DB Browser for SQLite

### ✅ OPÇÃO 1: Download Manual (RECOMENDADO)
1. 🌐 Abrir: https://sqlitebrowser.org/dl/
2. 📥 Baixar instalador Windows 64-bit (.msi ou .exe)
3. ▶️ Instalar (Next → Next → Install)
4. 🗄️ Abrir: Menu Iniciar → "DB Browser"
5. 📂 File → Open Database → Selecionar: `src/BioDesk.App/biodesk.db`

### ✅ OPÇÃO 2: Script PowerShell (SEM INSTALAÇÃO)
```powershell
# Visualizar BD sem instalar nada
.\VerBD.ps1                    # Ver tabela Pacientes
.\VerBD.ps1 -Tabela Consultas  # Ver tabela específica
```

**Script criado**: `VerBD.ps1` (raiz do projeto)

---

## 🔍 Alternativa: VS Code Extension

**SQLite Viewer** (extension):
- ID: `qwtel.sqlite-viewer`
- Abre `.db` files direto no VS Code
- Click direito no `biodesk.db` → "Open with SQLite Viewer"

```powershell
code --install-extension qwtel.sqlite-viewer
```

---

## ✅ Conclusão

O erro `sqlite3 not recognized` é **extremamente comum** porque:
- SQLite CLI **não** vem instalado no Windows por padrão
- É uma ferramenta separada, não parte do .NET SDK
- Maioria dos projetos usa EF Core ou ferramentas GUI

**Solução mais rápida**: DB Browser for SQLite (GUI) ou VS Code Extension.
