using Microsoft.Data.Sqlite;

var dbPath = Path.Combine(Directory.GetCurrentDirectory(), "src", "BioDesk.App", "biodesk.db");
var connectionString = $"Data Source={dbPath}";

Console.WriteLine($"🔍 Verificando BD: {dbPath}");
Console.WriteLine();

using var connection = new SqliteConnection(connectionString);
connection.Open();

var command = connection.CreateCommand();
command.CommandText = @"
    SELECT
        Id,
        NomeCompleto,
        NumeroProcesso,
        datetime(DataCriacao) as DataCriacao
    FROM Pacientes
    ORDER BY DataCriacao DESC;
";

using var reader = command.ExecuteReader();

Console.WriteLine("📊 PACIENTES NA BASE DE DADOS:");
Console.WriteLine("════════════════════════════════════════════════════════════");

int count = 0;
while (reader.Read())
{
    count++;
    Console.WriteLine($"{count}. ID={reader.GetInt32(0)} | Nome={reader.GetString(1)} | Processo={reader.GetString(2)} | Data={reader.GetString(3)}");
}

Console.WriteLine("════════════════════════════════════════════════════════════");
Console.WriteLine($"✅ Total: {count} pacientes");
