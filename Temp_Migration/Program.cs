using Microsoft.Data.Sqlite;

var dbPath = @"C:\Users\nfjpc\OneDrive\Documentos\BioDeskPro2\biodesk.db";
if (!File.Exists(dbPath)) { Console.WriteLine($"❌ BD não encontrada: {dbPath}"); return; }
Console.WriteLine($"✅ BD: {dbPath}\n");

using var conn = new SqliteConnection($"Data Source={dbPath}");
conn.Open();
using var transaction = conn.BeginTransaction();
try
{
    using (var cmd = conn.CreateCommand())
    {
        cmd.CommandText = @"CREATE TABLE IF NOT EXISTS ConfiguracaoClinica (
            Id INTEGER PRIMARY KEY, NomeClinica TEXT NOT NULL, Morada TEXT,
            Telefone TEXT, Email TEXT, NIPC TEXT, LogoPath TEXT, DataAtualizacao TEXT NOT NULL);";
        cmd.ExecuteNonQuery();
        Console.WriteLine("✅ Tabela criada");
    }
    using (var cmd = conn.CreateCommand())
    {
        cmd.CommandText = @"INSERT OR IGNORE INTO ConfiguracaoClinica
            (Id, NomeClinica, DataAtualizacao) VALUES (1, 'Minha Clínica', datetime('now'));";
        cmd.ExecuteNonQuery();
        Console.WriteLine("✅ Seed inserido");
    }
    using (var cmd = conn.CreateCommand())
    {
        cmd.CommandText = @"INSERT OR IGNORE INTO __EFMigrationsHistory
            (MigrationId, ProductVersion) VALUES ('20251008131514_AddConfiguracaoClinica', '8.0.0');";
        cmd.ExecuteNonQuery();
        Console.WriteLine("✅ Migration registada");
    }
    transaction.Commit();
    Console.WriteLine("\n✅ SUCESSO!\n");
}
catch (Exception ex) { transaction.Rollback(); Console.WriteLine($"\n❌ ERRO: {ex.Message}"); }
