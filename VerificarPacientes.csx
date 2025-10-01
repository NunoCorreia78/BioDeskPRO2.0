#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.EntityFrameworkCore.Sqlite, 8.0.8"
#r "nuget: Microsoft.EntityFrameworkCore, 8.0.8"

using Microsoft.Data.Sqlite;
using System;
using System.IO;

var dbPath = Path.Combine(Directory.GetCurrentDirectory(), "src", "BioDesk.App", "biodesk.db");
var connectionString = $"Data Source={dbPath}";

Console.WriteLine($"🔍 Verificando BD: {dbPath}");
Console.WriteLine();

using var connection = new SqliteConnection(connectionString);
connection.Open();

// Query pacientes
var command = connection.CreateCommand();
command.CommandText = @"
    SELECT
        Id,
        NomeCompleto,
        NumeroProcesso,
        datetime(DataCriacao) as DataCriacao,
        datetime(DataUltimaAtualizacao) as DataUltimaAtualizacao
    FROM Pacientes
    ORDER BY DataCriacao DESC
    LIMIT 10;
";

using var reader = command.ExecuteReader();

Console.WriteLine("📊 PACIENTES NA BASE DE DADOS:");
Console.WriteLine("═══════════════════════════════════════════════════════════════");
Console.WriteLine($"{"ID",-5} {"Nome Completo",-35} {"Nº Processo",-15} {"Data Criação",-20}");
Console.WriteLine("───────────────────────────────────────────────────────────────");

int count = 0;
while (reader.Read())
{
    count++;
    var id = reader.GetInt32(0);
    var nome = reader.GetString(1);
    var processo = reader.IsDBNull(2) ? "N/A" : reader.GetString(2);
    var dataCriacao = reader.IsDBNull(3) ? "N/A" : reader.GetString(3);

    Console.WriteLine($"{id,-5} {nome,-35} {processo,-15} {dataCriacao,-20}");
}

Console.WriteLine("═══════════════════════════════════════════════════════════════");
Console.WriteLine($"✅ Total de pacientes: {count}");
