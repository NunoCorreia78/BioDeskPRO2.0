# 🗄️ GESTÃO DA BASE DE DADOS - BioDeskPro2

## 📍 Localização ÚNICA da BD

**⚠️ IMPORTANTE**: O sistema usa **APENAS UMA** base de dados:

```
📂 src/BioDesk.App/biodesk.db  ✅ ÚNICA FONTE VERDADE
```

### ❌ NÃO usar:
- `./biodesk.db` (raiz do projeto) - **APAGADA em 30/09/2025**
- Qualquer outra cópia em pastas temporárias

---

## 🔧 Configuração no Código

**App.xaml.cs** (linha 215):
```csharp
services.AddDbContext<BioDeskDbContext>(options =>
    options.UseSqlite("Data Source=biodesk.db")); // ⚠️ Relativo à pasta da app
```

**Path absoluto em runtime**: `C:\Users\[USER]\...\BioDeskPro2\src\BioDesk.App\biodesk.db`

---

## 🛠️ Comandos EF Core Migrations

### ✅ SEMPRE usar com `--startup-project`:

```powershell
# Criar nova migration
dotnet ef migrations add NomeDaMigration `
  --project src/BioDesk.Data `
  --startup-project src/BioDesk.App

# Aplicar migrations (atualizar BD)
dotnet ef database update `
  --project src/BioDesk.Data `
  --startup-project src/BioDesk.App

# Reverter para migration específica
dotnet ef database update NomeDaMigration `
  --project src/BioDesk.Data `
  --startup-project src/BioDesk.App

# Remover última migration (se não aplicada)
dotnet ef migrations remove `
  --project src/BioDesk.Data `
  --startup-project src/BioDesk.App
```

### 🎯 Porquê `--startup-project src/BioDesk.App`?

- Garante que o EF usa a **connection string correta** (App.xaml.cs)
- A BD é criada/atualizada na **localização certa** (pasta da app)
- Evita duplicação de BDs em múltiplas pastas

---

## 📋 Estrutura da BD (Schema)

### Tabelas Principais

1. **Pacientes**
   - Seed: 3 pacientes iniciais (Ana Silva, João Ferreira, Maria Costa)
   - Índice único: `NumeroProcesso` (PAC-YYYY-XXX)

2. **Contactos** (1:1 com Pacientes)
   - EmailPrincipal, TelefonePrincipal, Morada

3. **HistoricosMedicos** (1:1 com Pacientes)
   - DoencasCronicas, Alergias, Cirurgias, Medicacao

4. **Sessoes** (1:N com Pacientes)
   - Tipo: Consulta, Tratamento, Avaliação
   - Observações, Prescrições

5. **Consentimentos** (1:N com Pacientes)
   - Naturopatia, Osteopatia, RGPD
   - DataAssinatura, AssinaturaDigital

6. **IrisAnalises** (1:N com Pacientes)
   - ImagemOlhoEsquerdo, ImagemOlhoDireito
   - Diagnóstico, Recomendações

---

## 🔍 Verificar Estado da BD

### PowerShell - Listar pacientes:

```powershell
cd "C:\Users\[USER]\...\BioDeskPro2\src\BioDesk.App"

# Usando .NET Interactive
dotnet script
#r "nuget: Microsoft.Data.Sqlite"
using Microsoft.Data.Sqlite;
var conn = new SqliteConnection("Data Source=biodesk.db");
conn.Open();
var cmd = conn.CreateCommand();
cmd.CommandText = "SELECT COUNT(*) FROM Pacientes";
Console.WriteLine($"Total pacientes: {cmd.ExecuteScalar()}");
```

---

## 🚨 Troubleshooting

### Problema: "Table not found"

**Causa**: Migrations não aplicadas  
**Solução**:
```powershell
dotnet ef database update --project src/BioDesk.Data --startup-project src/BioDesk.App
```

### Problema: BD com dados antigos

**Causa**: Cache da app ou BD obsoleta  
**Solução**:
```powershell
# ATENÇÃO: Apaga TODOS os dados!
rm src/BioDesk.App/biodesk.db
dotnet ef database update --project src/BioDesk.Data --startup-project src/BioDesk.App
```

### Problema: 2 BDs em localizações diferentes

**Causa**: Migrations executadas sem `--startup-project`  
**Solução**: Ver secção **Consolidação** abaixo

---

## 🔄 Consolidação de BDs (30/09/2025)

### Histórico do Problema

Existiam **2 cópias** da BD:
- `./biodesk.db` (raiz) - 172 KB, modificado 17:07:39
- `./src/BioDesk.App/biodesk.db` (app) - 172 KB, modificado 17:01:18

**App usava**: `src/BioDesk.App/biodesk.db`  
**Migrations criavam**: `./biodesk.db` (quando executadas sem `--startup-project`)

### Ação Tomada

✅ **Backup criado**: `biodesk.db.backup_20250930_220437`  
✅ **BD raiz apagada**: Apenas `src/BioDesk.App/biodesk.db` permanece  
✅ **`.gitignore` atualizado**: `*.db`, `biodesk.db`, `*.db.backup_*`

### Regra de Ouro

**SEMPRE usar `--startup-project src/BioDesk.App` em comandos EF!**

---

## 📊 Seed Data

Executado automaticamente no arranque da app (`App.xaml.cs`):

```csharp
await SeedDataAsync(scope.ServiceProvider);
```

### Pacientes Seed (se BD vazia):

1. **Ana Silva** (PAC-2025-001)
   - Nascimento: 15/05/1990
   - Email: ana.silva@email.com
   - Telefone: 912345678

2. **João Ferreira** (PAC-2025-002)
   - Nascimento: 22/11/1985
   - Email: joao.ferreira@email.com
   - Telefone: 923456789

3. **Maria Costa** (PAC-2025-003)
   - Nascimento: 08/03/1978
   - Email: maria.costa@email.com
   - Telefone: 934567890

---

## 🔐 Backup e Segurança

### Backup Manual

```powershell
cd src/BioDesk.App
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
Copy-Item biodesk.db "biodesk.db.backup_$timestamp"
```

### Backup Automático (TODO)

Implementar rotina diária:
- Copiar BD para pasta `Backups/`
- Manter últimos 30 dias
- Compressão ZIP com senha

---

## 📚 Referências

- **EF Core Docs**: https://learn.microsoft.com/ef/core/
- **SQLite Docs**: https://www.sqlite.org/docs.html
- **Migrations Guide**: https://learn.microsoft.com/ef/core/managing-schemas/migrations/

---

**Última atualização**: 30/09/2025 22:04  
**Autor**: GitHub Copilot + Nuno Correia
