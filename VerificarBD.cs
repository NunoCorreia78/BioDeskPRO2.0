using System;
using System.IO;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data;

var dbPath = Path.Combine(Directory.GetCurrentDirectory(), "biodesk.db");
Console.WriteLine($"📂 Base de dados: {dbPath}");
Console.WriteLine($"📊 Arquivo existe: {File.Exists(dbPath)}\n");

if (!File.Exists(dbPath))
{
    Console.WriteLine("❌ Ficheiro biodesk.db não encontrado!");
    return;
}

var options = new DbContextOptionsBuilder<BioDeskDbContext>()
    .UseSqlite($"Data Source={dbPath}")
    .Options;

using var db = new BioDeskDbContext(options);

var totalPacientes = db.Pacientes.Count();
Console.WriteLine($"✅ Total de pacientes na BD: {totalPacientes}\n");

var pacientes = db.Pacientes
    .OrderBy(p => p.Id)
    .Select(p => new 
    { 
        p.Id, 
        p.NumeroProcesso, 
        p.NomeCompleto, 
        p.DataNascimento, 
        p.DataUltimaAtualizacao 
    })
    .ToList();

Console.WriteLine("📋 Lista de Pacientes:");
Console.WriteLine("-----------------------------------");
foreach (var p in pacientes)
{
    Console.WriteLine($"ID: {p.Id} | Nº Processo: {p.NumeroProcesso} | Nome: {p.NomeCompleto}");
    Console.WriteLine($"   Nascimento: {p.DataNascimento:dd/MM/yyyy} | Atualizado: {p.DataUltimaAtualizacao:dd/MM/yyyy HH:mm}\n");
}
