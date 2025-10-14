using Microsoft.Data.Sqlite;

var dbPath = "biodesk.db";

if (!File.Exists(dbPath))
{
    Console.WriteLine("❌ Base de dados não encontrada!");
    Console.WriteLine($"   Procurado em: {Path.GetFullPath(dbPath)}");
    return;
}

Console.WriteLine($"✅ Base de dados: {Path.GetFullPath(dbPath)}");
Console.WriteLine("═══════════════════════════════════════════════════════");

using var connection = new SqliteConnection($"Data Source={dbPath}");
connection.Open();

// APLICAR MIGRATION: AddConfiguracaoClinica
Console.WriteLine("\n🔧 APLICANDO MIGRATION...");

using (var transaction = connection.BeginTransaction())
{
    try
    {
        // 1. Criar tabela ConfiguracaoClinica
        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS ConfiguracaoClinica (
                    Id INTEGER NOT NULL PRIMARY KEY,
                    NomeClinica TEXT NOT NULL CHECK(length(NomeClinica) <= 200),
                    Morada TEXT CHECK(length(Morada) <= 500),
                    Telefone TEXT CHECK(length(Telefone) <= 50),
                    Email TEXT CHECK(length(Email) <= 100),
                    NIPC TEXT CHECK(length(NIPC) <= 20),
                    LogoPath TEXT CHECK(length(LogoPath) <= 500),
                    DataAtualizacao TEXT NOT NULL
                );";
            cmd.ExecuteNonQuery();
            Console.WriteLine("  ✅ Tabela ConfiguracaoClinica criada");
        }

        // 2. Inserir seed
        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT OR IGNORE INTO ConfiguracaoClinica
                (Id, NomeClinica, Morada, Telefone, Email, NIPC, LogoPath, DataAtualizacao)
                VALUES (1, 'Minha Clínica', NULL, NULL, NULL, NULL, NULL, datetime('now'));";
            var rows = cmd.ExecuteNonQuery();
            if (rows > 0)
                Console.WriteLine("  ✅ Seed inserido (Id=1)");
            else
                Console.WriteLine("  ℹ️ Seed já existia");
        }

        // 3. Registar migration
        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = @"
                INSERT OR IGNORE INTO __EFMigrationsHistory (MigrationId, ProductVersion)
                VALUES ('20251008131514_AddConfiguracaoClinica', '8.0.0');";
            cmd.ExecuteNonQuery();
            Console.WriteLine("  ✅ Migration registada");
        }

        transaction.Commit();
        Console.WriteLine("\n✅ MIGRATION APLICADA COM SUCESSO!");
    }
    catch (Exception ex)
    {
        transaction.Rollback();
        Console.WriteLine($"\n❌ ERRO: {ex.Message}");
        return;
    }
}

Console.WriteLine($"✅ Base de dados: {Path.GetFullPath(dbPath)}");
Console.WriteLine("═══════════════════════════════════════════════════════");

using var connection = new SqliteConnection($"Data Source={dbPath}");
connection.Open();

// 1. TOTAL DE PACIENTES
using (var cmd = connection.CreateCommand())
{
    cmd.CommandText = "SELECT COUNT(*) FROM Pacientes;";
    var totalPacientes = (long)cmd.ExecuteScalar()!;
    Console.WriteLine($"\n📊 TOTAL DE PACIENTES: {totalPacientes}");

    if (totalPacientes == 3)
    {
        Console.WriteLine("🚨 ALERTA: Apenas 3 pacientes = BD com seed (dados fictícios)!");
    }
    else if (totalPacientes > 3)
    {
        Console.WriteLine($"✅ OK: {totalPacientes} pacientes reais encontrados!");
    }
}

// 2. LISTAR PACIENTES
Console.WriteLine("\n👥 LISTA DE PACIENTES:");
Console.WriteLine("───────────────────────────────────────────────────────");
using (var cmd = connection.CreateCommand())
{
    cmd.CommandText = "SELECT Id, NomeCompleto, DataNascimento FROM Pacientes ORDER BY Id LIMIT 15;";
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
    {
        Console.WriteLine($"  #{reader.GetInt32(0):D3} - {reader.GetString(1)} (nascido em {reader.GetString(2)})");
    }
}

// 3. TOTAL DE IMAGENS
using (var cmd = connection.CreateCommand())
{
    cmd.CommandText = "SELECT COUNT(*) FROM IrisImagens;";
    var totalImagens = (long)cmd.ExecuteScalar()!;
    Console.WriteLine($"\n📸 TOTAL DE IMAGENS ÍRIS: {totalImagens}");
}

// 4. OUTRAS TABELAS
Console.WriteLine("\n📋 OUTRAS TABELAS:");
string[] tabelas = { "Sessoes", "Contactos", "IrisMarcas" };
foreach (var tabela in tabelas)
{
    try
    {
        using var cmd = connection.CreateCommand();
        cmd.CommandText = $"SELECT COUNT(*) FROM {tabela};";
        var count = (long)cmd.ExecuteScalar()!;
        Console.WriteLine($"  {tabela}: {count} registos");
    }
    catch
    {
        Console.WriteLine($"  {tabela}: (tabela não existe)");
    }
}

// 5. VERIFICAR TABELA ConfiguracaoClinica
Console.WriteLine("\n⚙️ CONFIGURAÇÕES:");
try
{
    using var cmd = connection.CreateCommand();
    cmd.CommandText = "SELECT COUNT(*) FROM ConfiguracaoClinica;";
    var count = (long)cmd.ExecuteScalar()!;
    Console.WriteLine($"  ConfiguracaoClinica: {count} registos");

    if (count == 0)
    {
        Console.WriteLine("  ⚠️ Tabela existe mas está vazia (migração OK, seed pendente)");
    }
}
catch
{
    Console.WriteLine("  ⚠️ Tabela ConfiguracaoClinica NÃO EXISTE (migração pendente)");
}

Console.WriteLine("\n═══════════════════════════════════════════════════════");
