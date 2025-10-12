using System;
using System.Linq;
using Microsoft.EntityFrameworkCore;
using BioDesk.Data.Context;
using BioDesk.Services.Configuration;

// Script de teste rápido - LastActiveTab
Console.WriteLine("\n=== TESTE: Persistencia Estado Abas ===\n");

var pathService = new PathService();
var dbPath = pathService.DatabasePath;

Console.WriteLine($"BD Path: {dbPath}");
Console.WriteLine($"BD Exists: {System.IO.File.Exists(dbPath)}\n");

var options = new DbContextOptionsBuilder<BioDeskDbContext>()
    .UseSqlite($"Data Source={dbPath}")
    .Options;

using var context = new BioDeskDbContext(options);

Console.WriteLine("Top 5 Pacientes com LastActiveTab:\n");

var pacientes = context.Pacientes
    .OrderBy(p => p.Id)
    .Take(5)
    .Select(p => new { p.Id, p.NomeCompleto, p.LastActiveTab })
    .ToList();

foreach (var p in pacientes)
{
    var abaName = p.LastActiveTab switch
    {
        1 => "Dados",
        2 => "Saude",
        3 => "Consentimentos",
        4 => "Consultas",
        5 => "Irisdiagnostico",
        6 => "Comunicacao",
        7 => "Documentos",
        8 => "Terapias",
        _ => "Invalida"
    };
    
    Console.WriteLine($"[{p.Id}] {p.NomeCompleto,-30} -> Aba {p.LastActiveTab} ({abaName})");
}

Console.WriteLine($"\nTotal: {pacientes.Count} pacientes");
Console.WriteLine("\n=== TESTE CONCLUIDO ===\n");

Console.WriteLine("INSTRUCOES TESTE MANUAL:");
Console.WriteLine("1. Abrir ficha de paciente");
Console.WriteLine("2. Navegar para Aba 5 (Irisdiagnostico)");
Console.WriteLine("3. Fechar ficha");
Console.WriteLine("4. Reabrir mesmo paciente");
Console.WriteLine("5. DEVE abrir diretamente na Aba 5!");
