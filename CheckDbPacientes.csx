#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.Data.Sqlite, 8.0.0"

using Microsoft.Data.Sqlite;
using System;

var dbPath = Path.Combine(Directory.GetCurrentDirectory(), "biodesk.db");

if (!File.Exists(dbPath))
{
    Console.WriteLine($"❌ BD não encontrada: {dbPath}");
    return;
}

Console.WriteLine($"📂 Verificando BD: {dbPath}");
Console.WriteLine($"📊 Tamanho: {new FileInfo(dbPath).Length / 1024} KB\n");

using var connection = new SqliteConnection($"Data Source={dbPath}");
connection.Open();

// Verificar total de pacientes
using (var cmd = connection.CreateCommand())
{
    cmd.CommandText = "SELECT COUNT(*) FROM Pacientes";
    var total = Convert.ToInt32(cmd.ExecuteScalar());
    Console.WriteLine($"👥 Total de Pacientes: {total}");
}

// Verificar se IDs 1,2,3 existem
using (var cmd = connection.CreateCommand())
{
    cmd.CommandText = "SELECT Id, NumeroProcesso, NomeCompleto FROM Pacientes WHERE Id IN (1,2,3) ORDER BY Id";
    using var reader = cmd.ExecuteReader();

    if (reader.HasRows)
    {
        Console.WriteLine("\n⚠️ Pacientes SEED encontrados (IDs 1,2,3):");
        while (reader.Read())
        {
            Console.WriteLine($"  • ID {reader.GetInt32(0)}: {reader.GetString(1)} - {reader.GetString(2)}");
        }
    }
    else
    {
        Console.WriteLine("\n✅ IDs 1,2,3 estão LIVRES (nenhum paciente seed)");
    }
}

// Listar primeiros 5 pacientes reais
using (var cmd = connection.CreateCommand())
{
    cmd.CommandText = "SELECT Id, NumeroProcesso, NomeCompleto FROM Pacientes ORDER BY Id LIMIT 5";
    using var reader = cmd.ExecuteReader();

    if (reader.HasRows)
    {
        Console.WriteLine("\n📋 Primeiros 5 Pacientes:");
        while (reader.Read())
        {
            Console.WriteLine($"  • ID {reader.GetInt32(0)}: {reader.GetString(1)} - {reader.GetString(2)}");
        }
    }
}

// Verificar total de Sessoes
using (var cmd = connection.CreateCommand())
{
    cmd.CommandText = "SELECT COUNT(*) FROM Sessoes";
    try
    {
        var total = Convert.ToInt32(cmd.ExecuteScalar());
        Console.WriteLine($"\n📅 Total de Sessões: {total}");
    }
    catch
    {
        Console.WriteLine("\n❌ Tabela Sessoes não existe ou está vazia");
    }
}

Console.WriteLine("\n✅ Análise completa!");
