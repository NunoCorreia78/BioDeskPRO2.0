#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.Data.Sqlite, 8.0.0"
#r "nuget: SQLitePCLRaw.bundle_e_sqlite3, 2.1.6"

using System;
using System.IO;
using Microsoft.Data.Sqlite;
using SQLitePCL;

var dbPath = Path.Combine(Directory.GetCurrentDirectory(), "biodesk.db");
var connectionString = $"Data Source={dbPath}";

if (!File.Exists(dbPath))
{
    Console.WriteLine("❌ Base de dados NÃO encontrada!");
    return;
}

Console.WriteLine($"✅ Base de dados encontrada: {dbPath}");
Console.WriteLine("════════════════════════════════════════════════════════════");

Batteries_V2.Init();

var connection = new SqliteConnection(connectionString);
connection.Open();

try
{
    // 1. CONTAR TOTAL DE IMAGENS
    using (var cmd = connection.CreateCommand())
    {
        cmd.CommandText = "SELECT COUNT(*) FROM IrisImagens;";
        var total = (long)cmd.ExecuteScalar()!;
        Console.WriteLine($"\n📊 TOTAL DE IMAGENS NA BASE DE DADOS: {total}");

        if (total == 0)
        {
            Console.WriteLine("\n🚨 PROBLEMA ENCONTRADO: Tabela IrisImagens está VAZIA!");
            Console.WriteLine("   Não existem imagens para exibir.");
            Console.WriteLine("\n💡 SOLUÇÃO:");
            Console.WriteLine("   1. Vai à Ficha do Paciente → Tab Íris");
            Console.WriteLine("   2. Clica no botão '📁 Adicionar' ou '📷 Capturar'");
            Console.WriteLine("   3. Seleciona/captura uma imagem");
            Console.WriteLine("════════════════════════════════════════════════════════════");
            return;
        }
    }

    // 2. LISTAR TODAS AS IMAGENS
    Console.WriteLine("\n📷 IMAGENS REGISTADAS:");
    Console.WriteLine("────────────────────────────────────────────────────────────");

    using (var cmd = connection.CreateCommand())
    {
        cmd.CommandText = @"
            SELECT Id, PacienteId, Olho, DataCaptura, CaminhoImagem
            FROM IrisImagens
            ORDER BY DataCaptura DESC;";

        using var reader = cmd.ExecuteReader();

        while (reader.Read())
        {
            var id = reader.GetInt32(0);
            var pacienteId = reader.GetInt32(1);
            var olho = reader.GetString(2);
            var data = reader.GetString(3);
            var caminho = reader.GetString(4);
            var existe = File.Exists(caminho) ? "✅" : "❌ FALTA";

            Console.WriteLine($"  ID: {id} | Paciente: {pacienteId} | Olho: {olho}");
            Console.WriteLine($"  Data: {data}");
            Console.WriteLine($"  Ficheiro: {existe} {caminho}");
            Console.WriteLine();
        }
    }

    // 3. CONTAR IMAGENS POR PACIENTE
    Console.WriteLine("👤 IMAGENS POR PACIENTE:");
    Console.WriteLine("────────────────────────────────────────────────────────────");

    using (var cmd = connection.CreateCommand())
    {
        cmd.CommandText = @"
            SELECT p.Id, p.NomeCompleto, COUNT(i.Id) as TotalImagens
            FROM Pacientes p
            LEFT JOIN IrisImagens i ON p.Id = i.PacienteId
            GROUP BY p.Id, p.NomeCompleto;";

        using var reader = cmd.ExecuteReader();

        while (reader.Read())
        {
            var id = reader.GetInt32(0);
            var nome = reader.GetString(1);
            var total = reader.GetInt64(2);

            Console.WriteLine($"  Paciente #{id} - {nome}: {total} imagens");
        }
    }

    Console.WriteLine("════════════════════════════════════════════════════════════");
}
finally
{
    connection.Close();
    connection.Dispose();
}
