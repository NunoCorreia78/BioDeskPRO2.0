#!/usr/bin/env dotnet-script
#r "nuget: Microsoft.EntityFrameworkCore.Sqlite, 8.0.8"
#r "nuget: Microsoft.EntityFrameworkCore, 8.0.8"

using Microsoft.EntityFrameworkCore;
using System.IO;

// Configurar base de dados
var dbPath = Path.Combine(Directory.GetCurrentDirectory(), "biodesk.db");
Console.WriteLine($"📂 Base de dados: {dbPath}");
Console.WriteLine($"📊 Arquivo existe: {File.Exists(dbPath)}");
Console.WriteLine();

if (!File.Exists(dbPath))
{
    Console.WriteLine("❌ Ficheiro biodesk.db não encontrado!");
    return;
}

var options = new DbContextOptionsBuilder<AppDbContext>()
    .UseSqlite($"Data Source={dbPath}")
    .Options;

using var db = new AppDbContext(options);

// Contar pacientes
var totalPacientes = db.Database.SqlQueryRaw<int>("SELECT COUNT(*) as Value FROM Pacientes").FirstOrDefault();
Console.WriteLine($"✅ Total de pacientes na BD: {totalPacientes}");
Console.WriteLine();

// Listar pacientes
var pacientes = db.Database.SqlQueryRaw<PacienteInfo>(
    "SELECT Id, NumeroProcesso, NomeCompleto, DataNascimento, DataUltimaAtualizacao FROM Pacientes ORDER BY Id"
).ToList();

Console.WriteLine("📋 Lista de Pacientes:");
Console.WriteLine("-----------------------------------");
foreach (var p in pacientes)
{
    Console.WriteLine($"ID: {p.Id} | Nº Processo: {p.NumeroProcesso} | Nome: {p.NomeCompleto}");
    Console.WriteLine($"   Nascimento: {p.DataNascimento:dd/MM/yyyy} | Atualizado: {p.DataUltimaAtualizacao:dd/MM/yyyy HH:mm}");
    Console.WriteLine();
}

// Classes auxiliares
class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}

class PacienteInfo
{
    public int Id { get; set; }
    public int NumeroProcesso { get; set; }
    public string NomeCompleto { get; set; } = string.Empty;
    public DateTime DataNascimento { get; set; }
    public DateTime DataUltimaAtualizacao { get; set; }
}
