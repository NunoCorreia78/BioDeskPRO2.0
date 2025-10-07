#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.Data.Sqlite, 8.0.0"
#r "nuget: SQLitePCLRaw.bundle_e_sqlite3, 2.1.6"

using System;
using System.IO;
using Microsoft.Data.Sqlite;
using SQLitePCL;

var dbPath = Path.Combine(Directory.GetCurrentDirectory(), "biodesk.db");
if (!File.Exists(dbPath))
{
    Console.WriteLine($"❌ Base de dados não encontrada em {dbPath}");
    return;
}

var connectionString = $"Data Source={dbPath}";
Batteries_V2.Init();

var fixes = new (int Id, string RelativePath)[]
{
    (3, Path.Combine("Pacientes", "Maria_Fernanda_Costa", "IrisImagens", "Iris_Esquerdo_20251003_110701.jpg")),
    (4, Path.Combine("Pacientes", "Maria_Fernanda_Costa", "IrisImagens", "Iris_Direito_20251003_110740.jpg"))
};

var connection = new SqliteConnection(connectionString);
connection.Open();

try
{
    foreach (var fix in fixes)
    {
        var absolutePath = Path.Combine(Directory.GetCurrentDirectory(), fix.RelativePath);

        if (!File.Exists(absolutePath))
        {
            Console.WriteLine($"⚠️  Ficheiro esperado não existe: {absolutePath}");
            continue;
        }

        using (var updateCmd = connection.CreateCommand())
        {
            updateCmd.CommandText = "UPDATE IrisImagens SET CaminhoImagem = @path WHERE Id = @id";
            updateCmd.Parameters.AddWithValue("@path", absolutePath);
            updateCmd.Parameters.AddWithValue("@id", fix.Id);

            var rows = updateCmd.ExecuteNonQuery();
            Console.WriteLine(rows == 1
                ? $"✅ Atualizado registo #{fix.Id} → {absolutePath}"
                : $"⚠️  Nenhum registo atualizado para Id={fix.Id}");
        }
    }

    Console.WriteLine("────────────────────────────");

    using (var verifyCmd = connection.CreateCommand())
    {
        verifyCmd.CommandText = "SELECT Id, CaminhoImagem FROM IrisImagens WHERE Id IN (3,4)";

        using (var reader = verifyCmd.ExecuteReader())
        {
            while (reader.Read())
            {
                var id = reader.GetInt32(0);
                var path = reader.GetString(1);
                var exists = File.Exists(path) ? "✅" : "❌";
                Console.WriteLine($"ID {id}: {path} -> {exists}");
            }
        }
    }
}
finally
{
    connection.Close();
    connection.Dispose();
}
